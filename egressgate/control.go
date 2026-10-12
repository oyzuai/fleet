package egressgate

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxControlBody = 1 << 20

// TokenHeader carries the control token. It is a header of its own, besides
// Authorization, because a request through the Kubernetes API server's
// service proxy has its Authorization replaced by the caller's cluster
// credentials.
const TokenHeader = "X-Oyzu-Control-Token"

// ControlHandler is the manager's API to the gateway:
//
//	PUT    /v1/jobs/{job}          register a job: a Registration body
//	DELETE /v1/jobs/{job}          unregister it
//	GET    /v1/jobs/{job}/denials  its denials, from ?after=N
//	GET    /v1/health
//
// Every call needs the control token, in TokenHeader or as a bearer token. The listener should be loopback only;
// where it cannot be (a container's published port), the token and the
// refusal of any caller that is a job make up for it.
func (g *Gateway) ControlHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"mode": g.cfg.Mode})
	})
	mux.HandleFunc("PUT /v1/jobs/{job}", func(w http.ResponseWriter, r *http.Request) {
		var reg Registration
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlBody)).Decode(&reg); err != nil {
			http.Error(w, "bad registration: "+err.Error(), http.StatusBadRequest)
			return
		}
		reg.Job = r.PathValue("job")
		if err := g.Register(reg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1/jobs/{job}", func(w http.ResponseWriter, r *http.Request) {
		g.Unregister(r.PathValue("job"))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/jobs/{job}/denials", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		out, next, ok := g.Denials(r.PathValue("job"), after)
		if !ok {
			http.Error(w, "no such job", http.StatusNotFound)
			return
		}
		writeJSON(w, DenialsReply{Denials: out, Next: next, Mode: g.cfg.Mode})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if src, ok := addrOf(addrString(r.RemoteAddr)); ok && g.find(src) != nil {
			http.Error(w, "jobs cannot use the control API", http.StatusForbidden)
			return
		}
		got := r.Header.Get(TokenHeader)
		if got == "" {
			scheme, bearer, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			if strings.EqualFold(scheme, "Bearer") {
				got = bearer
			}
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Client is the manager's side of the control API.
type Client struct {
	// Base is the control URL, such as http://127.0.0.1:49153.
	Base  string
	Token string
	HTTP  *http.Client
}

// NewClient returns a Client with a short per-call timeout.
func NewClient(base, token string) *Client {
	return &Client{Base: strings.TrimSuffix(base, "/"), Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var r io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set(TokenHeader, c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &StatusError{Status: resp.StatusCode, Message: strings.TrimSpace(string(b))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxControlBody)).Decode(out)
}

// StatusError is an error response from the gateway.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("egress gateway: %d %s", e.Status, e.Message)
}

// Health succeeds when the gateway answers.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/health", nil, nil)
}

// Register adds or replaces a job.
func (c *Client) Register(ctx context.Context, r Registration) error {
	return c.do(ctx, http.MethodPut, "/v1/jobs/"+url.PathEscape(r.Job), r, nil)
}

// Unregister removes a job; one that is already gone succeeds.
func (c *Client) Unregister(ctx context.Context, job string) error {
	return c.do(ctx, http.MethodDelete, "/v1/jobs/"+url.PathEscape(job), nil, nil)
}

// Denials reads a job's denials from index after on.
func (c *Client) Denials(ctx context.Context, job string, after int) (DenialsReply, error) {
	var out DenialsReply
	err := c.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(job)+"/denials?after="+strconv.Itoa(after), nil, &out)
	return out, err
}

// NotFound reports whether err is the gateway saying the job is unknown.
func NotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// JobClient is a job's side: it asks the gateway's proxy port about the job
// the request comes from. It connects directly, never through a proxy.
type JobClient struct {
	// Base is the gateway's proxy URL, such as http://172.20.0.2:3128.
	Base string
	HTTP *http.Client
}

// NewJobClient returns a JobClient for the gateway at base.
func NewJobClient(base string) *JobClient {
	return &JobClient{Base: strings.TrimSuffix(base, "/"), HTTP: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}}
}

// Ready reports whether the gateway knows this job yet.
func (c *JobClient) Ready(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+PathReady, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusNoContent, nil
}

// Denials reads this job's denials from index after on.
func (c *JobClient) Denials(ctx context.Context, after int) (DenialsReply, error) {
	var out DenialsReply
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+PathDenials+"?after="+strconv.Itoa(after), nil)
	if err != nil {
		return out, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, &StatusError{Status: resp.StatusCode}
	}
	return out, json.NewDecoder(io.LimitReader(resp.Body, maxControlBody)).Decode(&out)
}
