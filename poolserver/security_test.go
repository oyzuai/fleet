package poolserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func signRSA(t *testing.T, key *rsa.PrivateKey, kid string, claims any) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}))
	input := h + "." + base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	digest := sha256.Sum256([]byte(input))
	sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func jwk(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}
func TestGitHubOIDCCallerAndDenials(t *testing.T) {
	f := newFixture(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var fetches atomic.Int64
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		respond(w, 200, map[string]any{"keys": []any{jwk(key, "key-1")}})
	}))
	defer jwks.Close()
	f.s.oidc.jwksURL = jwks.URL
	now := f.now.Load()
	claims := map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": f.cfg.PublicURL, "exp": now + 300, "nbf": now - 1, "sub": "repo:oyzuai/fleet:ref:refs/heads/main", "repository": "oyzuai/fleet", "sha": testSHA, "ref": "refs/heads/main", "run_id": "123", "run_attempt": "1"}
	token := signRSA(t, key, "key-1", claims)
	header := map[string]string{"Authorization": "Bearer " + token}
	status, b, _ := f.request(t, "POST", runsPath, "", createBody(), header)
	if status != 201 {
		t.Fatalf("OIDC create %d %s", status, b)
	}
	var run Run
	_ = json.Unmarshal(b, &run)
	status, _, _ = f.request(t, "GET", run.Links.Self, "", nil, header)
	if status != 200 {
		t.Fatal("own OIDC run inaccessible")
	}
	if fetches.Load() != 1 {
		t.Fatal("keys not cached")
	}
	for _, change := range []map[string]any{{"iss": "https://attacker.invalid"}, {"aud": "other"}, {"exp": now}, {"nbf": now + 10}, {"repository": "oyzuai/other"}, {"ref": "refs/heads/forbidden"}, {"run_id": ""}} {
		bad := map[string]any{}
		for k, v := range claims {
			bad[k] = v
		}
		for k, v := range change {
			bad[k] = v
		}
		tok := signRSA(t, key, "key-1", bad)
		status, _, _ = f.request(t, "POST", runsPath, "", createBody(), map[string]string{"Authorization": "Bearer " + tok})
		if status != 401 {
			t.Fatalf("OIDC claim denial %#v returned %d", change, status)
		}
	}
	changed := createBody()
	changed.Commit = strings.Repeat("f", 40)
	status, _, _ = f.request(t, "POST", runsPath, "", changed, header)
	if status != 403 {
		t.Fatal("OIDC commit mismatch allowed")
	}
	changed = createBody()
	changed.Ref = "refs/pull/1/merge"
	status, _, _ = f.request(t, "POST", runsPath, "", changed, header)
	if status != 403 {
		t.Fatal("OIDC ref mismatch allowed")
	}
	claims["run_id"] = "124"
	other := signRSA(t, key, "key-1", claims)
	status, _, _ = f.request(t, "GET", run.Links.Self, "", nil, map[string]string{"Authorization": "Bearer " + other})
	if status != 404 {
		t.Fatal("another Actions run read the result")
	}
	// Unknown kid forces a bounded refresh; an invalid signature never passes.
	bad := signRSA(t, key, "unknown", claims)
	status, _, _ = f.request(t, "GET", runsPath, "", nil, map[string]string{"Authorization": "Bearer " + bad})
	if status != 401 || fetches.Load() != 2 {
		t.Fatalf("unknown kid refresh %d %d", status, fetches.Load())
	}
	wrong, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	bad = signRSA(t, wrong, "key-1", claims)
	status, _, _ = f.request(t, "GET", runsPath, "", nil, map[string]string{"Authorization": "Bearer " + bad})
	if status != 401 {
		t.Fatal("bad signature accepted")
	}
	parts := strings.Split(token, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"key-1"}`))
	status, _, _ = f.request(t, "GET", runsPath, "", nil, map[string]string{"Authorization": "Bearer " + strings.Join(parts, ".")})
	if status != 401 {
		t.Fatal("algorithm confusion accepted")
	}
}
func TestGitHubAppScopeAndCommitLookup(t *testing.T) {
	f := newFixture(t)
	f.cfg.GitHubApp.AppID = 12345
	if err := f.cfg.defaults(); err != nil {
		t.Fatal(err)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var installations, tokens atomic.Int64
	var excess atomic.Bool
	var absent atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/installation":
			installations.Add(1)
			p := strings.Split(bearer(r), ".")
			if len(p) != 3 {
				t.Error("missing app JWT")
				w.WriteHeader(401)
				return
			}
			var c struct {
				Issuer int64 `json:"iss"`
				Expiry int64 `json:"exp"`
				Issued int64 `json:"iat"`
			}
			if decodeJWT(p[1], &c) != nil || c.Issuer != 12345 || c.Expiry-c.Issued > 600 {
				t.Error("invalid App JWT claims")
			}
			sig, _ := base64.RawURLEncoding.DecodeString(p[2])
			digest := sha256.Sum256([]byte(p[0] + "." + p[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
				t.Error("invalid App JWT signature")
			}
			respond(w, 200, map[string]int{"id": 42})
		case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
			tokens.Add(1)
			var in struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			if decodeJSON(r.Body, &in) != nil || len(in.Repositories) != 1 || in.Repositories[0] != "fleet" || len(in.Permissions) != 1 || in.Permissions["contents"] != "read" {
				t.Error("App credential not single-repository contents read")
			}
			permissions := map[string]string{"contents": "read", "metadata": "read"}
			if excess.Load() {
				permissions["checks"] = "write"
			}
			respond(w, 201, map[string]any{"token": "generated-installation-token", "expires_at": time.Unix(f.now.Load(), 0).Add(time.Hour), "permissions": permissions, "repositories": []any{map[string]string{"full_name": "oyzuai/fleet"}}})
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/commits/"+testSHA:
			if bearer(r) != "generated-installation-token" {
				t.Error("commit request did not use installation token")
			}
			if absent.Load() {
				w.WriteHeader(404)
				return
			}
			respond(w, 200, map[string]string{"sha": testSHA})
		default:
			t.Errorf("unexpected GitHub request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer api.Close()
	app, e := newGitHubApp(f.cfg, Options{AppKey: key, HTTPClient: api.Client(), Now: func() time.Time { return time.Unix(f.now.Load(), 0) }})
	if e != nil {
		t.Fatal(e)
	}
	app.base = api.URL
	for i := 0; i < 2; i++ {
		s, e := app.Source(context.Background(), "oyzuai/fleet")
		if e != nil || s.Repository != "oyzuai/fleet" {
			t.Fatalf("source %#v %v", s, e)
		}
	}
	if installations.Load() != 1 || tokens.Load() != 2 {
		t.Fatalf("installation cache/token mint counts %d %d", installations.Load(), tokens.Load())
	}
	exists, e := app.CommitExists(context.Background(), "oyzuai/fleet", testSHA)
	if e != nil || !exists {
		t.Fatalf("commit %v %v", exists, e)
	}
	absent.Store(true)
	exists, e = app.CommitExists(context.Background(), "oyzuai/fleet", testSHA)
	if e != nil || exists {
		t.Fatalf("missing commit %v %v", exists, e)
	}
	excess.Store(true)
	if _, e = app.Source(context.Background(), "oyzuai/fleet"); e == nil {
		t.Fatal("overprivileged credential accepted")
	}
}
func TestMalformedChunksAndRequestLimits(t *testing.T) {
	f := newFixture(t)
	f.create(t)
	id := f.login(t)
	st := f.start(t, id.access)
	ctx := context.Background()
	valid, _ := chunkFor(t, 1, 1, 1, "hello")
	cases := []runnerclient.LogChunk{valid, valid, valid, valid, valid}
	cases[0].Data = []byte("not gzip")
	cases[1].Hash = strings.Repeat("a", 64)
	cases[2].Entries = 1001
	cases[3].Attempt = 2
	cases[4].Data = bytes.Repeat([]byte{'a'}, maxChunkBytes+1)
	for i, bad := range cases {
		if _, e := f.c.UploadLogs(ctx, st.JobToken, bad); e == nil {
			t.Fatalf("malformed chunk %d accepted", i)
		}
	}
	var bomb bytes.Buffer
	z := gzip.NewWriter(&bomb)
	_, _ = io.Copy(z, io.LimitReader(zeroReader{}, maxChunkBytes+1))
	_ = z.Close()
	bad := valid
	bad.Data = bomb.Bytes()
	if _, e := f.c.UploadLogs(ctx, st.JobToken, bad); e == nil {
		t.Fatal("decompression bomb accepted")
	}
	raw := append(mustJSON(runnerclient.LogEntry{Sequence: 1, Stream: "stdout", Time: time.Now(), Text: strings.Repeat("a", 65537)}), '\n')
	var buf bytes.Buffer
	z = gzip.NewWriter(&buf)
	_, _ = z.Write(raw)
	_ = z.Close()
	bad = valid
	bad.Data = buf.Bytes()
	bad.Hash = hash(raw)
	if _, e := f.c.UploadLogs(ctx, st.JobToken, bad); e == nil {
		t.Fatal("overlong log line accepted")
	}
	req, _ := http.NewRequest("POST", f.ts.URL+runsPath, strings.NewReader(`{"repository":`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Tailscale-User-Login", "micah@example.com")
	resp, e := f.ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("malformed JSON accepted")
	}
	status, _, _ := f.request(t, "GET", "/healthz", "", nil, nil)
	if status != 204 {
		t.Fatal("health check failed")
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
