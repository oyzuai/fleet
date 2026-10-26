package poolserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestPoolJobTokenCreatorClaimsAndJWKS(t *testing.T) {
	for _, kind := range []string{"actions", "actions-pr", "actions-minimal", "tailnet", "snapshot"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			body := createBody()
			owner := "micah@example.com"
			var headers map[string]string
			if kind == "actions-pr" {
				body.Ref = "refs/pull/7/merge"
			}
			facts := map[string]string{"repository": body.Repository.Name, "ref": body.Ref}
			if strings.HasPrefix(kind, "actions") {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					respond(w, 200, map[string]any{"keys": []any{jwk(key, "actions-key")}})
				}))
				defer jwks.Close()
				f.s.oidc.jwksURL = jwks.URL
				if kind != "actions-minimal" {
					facts["repository_id"] = "123"
					facts["repository_owner_id"] = "456"
					facts["ref_type"] = "branch"
					facts["event_name"] = "push"
					facts["job_workflow_ref"] = "oyzuai/fleet/.github/workflows/ci.yml@" + body.Ref
					if kind == "actions-pr" {
						facts["event_name"] = "pull_request"
					}
				}
				claims := map[string]any{"iss": "https://token.actions.githubusercontent.com", "aud": f.cfg.PublicURL, "exp": f.now.Load() + 60, "sha": testSHA, "sub": "creator", "run_id": "creator-run", "run_attempt": "1"}
				for k, v := range facts {
					claims[k] = v
				}
				headers = map[string]string{"Authorization": "Bearer " + signRSA(t, key, "actions-key", claims)}
				owner = ""
			}
			if kind == "snapshot" {
				data := []byte("snapshot archive")
				digest := "sha256:" + hash(data)
				if status := uploadSource(t, f, digest, data); status != 201 {
					t.Fatalf("upload: %d", status)
				}
				body.Commit = ""
				body.Source = &SnapshotSource{Kind: "snapshot", Digest: digest, BaseCommit: testSHA}
			}
			status, raw, _ := f.request(t, "POST", runsPath, owner, body, headers)
			if status != 201 {
				t.Fatalf("create: %d %s", status, raw)
			}
			var run Run
			if err := json.Unmarshal(raw, &run); err != nil {
				t.Fatal(err)
			}
			// Reopen before token issuance: creator authority and signing identity
			// must survive restart, independently of the creator's expired JWT.
			oldPublic := f.s.issuer.key.Public()
			reopened, err := New(f.cfg, Options{Source: testSource{exists: true}, Now: f.s.now})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(oldPublic, reopened.issuer.key.Public()) {
				t.Fatal("issuer changed after restart")
			}
			f.s = reopened
			f.ts.Config.Handler = reopened
			f.now.Add(61) // The Actions creator token no longer authenticates a caller.
			id := f.login(t)
			st := f.start(t, id.access)
			token, err := f.c.IDToken(context.Background(), st.JobToken, "https://cache.example.test")
			if err != nil {
				t.Fatal(err)
			}
			status, jwksRaw, _ := f.request(t, "GET", "/.well-known/jwks.json", "", nil, nil)
			if status != 200 {
				t.Fatalf("JWKS: %d", status)
			}
			var set struct {
				Keys []struct{ Kty, Crv, Alg, Use, Kid, X string }
			}
			if err := json.Unmarshal(jwksRaw, &set); err != nil {
				t.Fatal(err)
			}
			if len(set.Keys) != 1 {
				t.Fatalf("JWKS keys: %s", jwksRaw)
			}
			key := set.Keys[0]
			if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Alg != "EdDSA" || key.Use != "sig" || key.Kid == "" {
				t.Fatalf("JWKS: %s", jwksRaw)
			}
			public, err := base64.RawURLEncoding.DecodeString(key.X)
			if err != nil || len(public) != ed25519.PublicKeySize {
				t.Fatal("invalid JWKS public key")
			}
			parts := strings.Split(token.Token, ".")
			if len(parts) != 3 {
				t.Fatal("not JWT")
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			if !ed25519.Verify(ed25519.PublicKey(public), []byte(parts[0]+"."+parts[1]), sig) {
				t.Fatal("JWKS signature failed")
			}
			var header map[string]string
			if decodeJWT(parts[0], &header) != nil || header["alg"] != "EdDSA" || header["kid"] != key.Kid {
				t.Fatal("bad JWT header")
			}
			var got map[string]any
			if err := decodeJWT(parts[1], &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range facts {
				if got[k] != v {
					t.Fatalf("claim %s=%v, want %q", k, got[k], v)
				}
			}
			for _, k := range []string{"repository_id", "repository_owner_id", "ref_type", "event_name", "job_workflow_ref"} {
				if _, expected := facts[k]; !expected {
					if _, ok := got[k]; ok {
						t.Fatalf("invented %s", k)
					}
				}
			}
			wantKind := "commit"
			if kind == "snapshot" {
				wantKind = "snapshot"
			}
			if got["source_kind"] != wantKind || got["sha"] != testSHA || got["run_id"] != run.ID || got["iss"] != f.cfg.PublicURL || got["aud"] != "https://cache.example.test" || got["sub"] != "repo:"+body.Repository.Name+":ref:"+body.Ref || got["exp"] != float64(f.now.Load()+600) || !token.Expires.Equal(time.Unix(f.now.Load()+600, 0)) {
				t.Fatalf("claims: %#v", got)
			}
			if bytes.Contains(jwksRaw, f.s.issuer.key.Seed()) {
				t.Fatal("private seed in JWKS")
			}
			if got["iat"] != float64(f.now.Load()) || got["nbf"] != float64(f.now.Load()) {
				t.Fatalf("token timing: %#v", got)
			}
			for _, audience := range []string{"", strings.Repeat("a", 2049), "cache\nclaim"} {
				var statusErr *runnerclient.StatusError
				if _, err := f.c.IDToken(context.Background(), st.JobToken, audience); !errors.As(err, &statusErr) || statusErr.Status != 422 {
					t.Fatalf("invalid audience accepted: %v", err)
				}
			}
			if _, err := f.c.IDToken(context.Background(), id.access, "cache"); !errors.Is(err, runnerclient.ErrUnauthenticated) {
				t.Fatalf("manager token accepted: %v", err)
			}
			if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "succeeded"}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.c.IDToken(context.Background(), st.JobToken, "cache"); !errors.Is(err, runnerclient.ErrUnauthenticated) {
				t.Fatalf("finished job accepted: %v", err)
			}
		})
	}
}

func TestIssuerKeyPrivateAndInvalidKeyRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pool deployment uses Linux private-file modes")
	}
	dir := t.TempDir()
	if _, err := loadJobIssuer(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "issuer.key")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("issuer key is not0600")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJobIssuer(dir); err == nil {
		t.Fatal("publicly readable key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`"invalid seed"`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJobIssuer(dir); err == nil {
		t.Fatal("corrupt key accepted or regenerated")
	}
}
