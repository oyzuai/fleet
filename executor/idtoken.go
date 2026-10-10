package executor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// The build asks the runner for OIDC ID tokens over loopback, the way a
// GitHub Actions step asks the Actions runtime: GET $OYZU_ID_TOKEN_URL with
// ?audience= and "Authorization: Bearer $OYZU_ID_TOKEN_REQUEST_TOKEN"
// answers {"value": "<jwt>", "expires_at": "..."}. The request token is
// random per job and only good for this; the job token that pays for the ID
// token stays in the runner.
const (
	// EnvIDTokenURL and EnvIDTokenRequestToken are what the build reads.
	EnvIDTokenURL          = "OYZU_ID_TOKEN_URL"
	EnvIDTokenRequestToken = "OYZU_ID_TOKEN_REQUEST_TOKEN"
	idTokenPath            = "/id-token"
	idTokenTimeout         = 20 * time.Second
)

// idBroker serves ID tokens to the build on a loopback port.
type idBroker struct {
	client   *runnerclient.Client
	jobToken string
	secret   string
	// issued is told every token handed out, so the log masks it.
	issued func(string)
	srv    *http.Server
	url    string
}

// startIDBroker listens on an ephemeral loopback port until stop is called.
func startIDBroker(client *runnerclient.Client, jobToken string, issued func(string)) (*idBroker, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &idBroker{client: client, jobToken: jobToken, secret: hex.EncodeToString(raw[:]), issued: issued}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+idTokenPath, b.serve)
	b.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	b.url = "http://" + ln.Addr().String() + idTokenPath
	go func() { _ = b.srv.Serve(ln) }()
	return b, nil
}

// env is what the build is given to reach the broker.
func (b *idBroker) env() []string {
	return []string{EnvIDTokenURL + "=" + b.url, EnvIDTokenRequestToken + "=" + b.secret}
}

func (b *idBroker) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = b.srv.Shutdown(ctx)
}

type idTokenAnswer struct {
	Value   string    `json:"value"`
	Expires time.Time `json:"expires_at"`
}

func (b *idBroker) serve(w http.ResponseWriter, r *http.Request) {
	scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(tok), []byte(b.secret)) != 1 {
		brokerError(w, http.StatusUnauthorized, "Send Authorization: Bearer $"+EnvIDTokenRequestToken+".")
		return
	}
	aud := r.URL.Query().Get("audience")
	if aud == "" {
		brokerError(w, http.StatusBadRequest, "Name the relying party with ?audience=.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), idTokenTimeout)
	defer cancel()
	t, err := b.client.IDToken(ctx, b.jobToken, aud)
	var se *runnerclient.StatusError
	switch {
	case err == nil:
	case errors.As(err, &se) && se.Status == http.StatusNotFound:
		brokerError(w, http.StatusNotFound, "This Oyzu deployment does not issue job ID tokens.")
		return
	case errors.As(err, &se) && (se.Status == http.StatusUnprocessableEntity || se.Status == http.StatusTooManyRequests || se.Status == http.StatusConflict):
		brokerError(w, se.Status, se.Detail)
		return
	default:
		brokerError(w, http.StatusServiceUnavailable, "Oyzu did not issue an ID token; try again.")
		return
	}
	b.issued(t.Token)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(idTokenAnswer{Value: t.Token, Expires: t.Expires})
}

func brokerError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
