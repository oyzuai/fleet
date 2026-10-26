package poolserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func attachRepositoryFactsAPI(t *testing.T, f *fixture, status int) *atomic.Int64 {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/installation":
			respond(w, 200, map[string]int{"id": 42})
		case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
			var in struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			if decodeJSON(r.Body, &in) != nil || len(in.Repositories) != 1 || in.Repositories[0] != "fleet" || len(in.Permissions) != 1 || in.Permissions["contents"] != "read" {
				t.Error("repository facts did not use a single-repository read credential")
			}
			respond(w, 201, map[string]any{
				"token": "repository-read-token", "expires_at": time.Unix(f.now.Load(), 0).Add(time.Hour),
				"permissions": map[string]string{"contents": "read"}, "repositories": []any{map[string]string{"full_name": "oyzuai/fleet"}},
			})
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet":
			calls.Add(1)
			if bearer(r) != "repository-read-token" {
				t.Error("repository lookup did not use the installation token")
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			respond(w, 200, map[string]any{"id": 1234, "owner": map[string]int{"id": 5678}})
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/commits/"+testSHA:
			respond(w, 200, map[string]string{"sha": testSHA})
		default:
			t.Errorf("unexpected GitHub request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(api.Close)
	app, err := newGitHubApp(f.cfg, Options{AppKey: key, HTTPClient: api.Client(), Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	app.base = api.URL
	f.s.source = app
	return &calls
}

func TestTerminalJobTokenRepositoryFacts(t *testing.T) {
	for _, kind := range []string{"commit", "snapshot"} {
		for _, lookupStatus := range []int{http.StatusOK, http.StatusServiceUnavailable} {
			t.Run(fmt.Sprintf("%s/lookup-%d", kind, lookupStatus), func(t *testing.T) {
				f := newFixture(t)
				calls := attachRepositoryFactsAPI(t, f, lookupStatus)
				body := createBody()
				if kind == "snapshot" {
					data, _ := sourceTestManifest(t, f, "terminal source")
					digest := "sha256:" + hash(data)
					if status := uploadSource(t, f, digest, data); status != 201 {
						t.Fatalf("upload: %d", status)
					}
					body.Commit = ""
					body.Source = &SnapshotSource{Kind: "snapshot", Digest: digest, BaseCommit: testSHA}
				}
				headers := map[string]string{"Idempotency-Key": "terminal-run"}
				status, raw, _ := f.request(t, "POST", runsPath, "micah@example.com", body, headers)
				if status != 201 {
					t.Fatalf("repository lookup prevented run creation: %d %s", status, raw)
				}
				var run Run
				if err := json.Unmarshal(raw, &run); err != nil {
					t.Fatal(err)
				}
				if status, _, _ = f.request(t, "POST", runsPath, "micah@example.com", body, headers); status != 200 {
					t.Fatalf("idempotent run creation: %d", status)
				}
				if calls.Load() != 1 {
					t.Fatalf("repository looked up %d times at creation", calls.Load())
				}
				// Reopen with a source provider that cannot look up IDs. Tokens
				// must use persisted source facts, not another GitHub request.
				reopened, err := New(f.cfg, Options{Source: testSource{exists: true}, Now: f.s.now})
				if err != nil {
					t.Fatal(err)
				}
				f.s, f.ts.Config.Handler = reopened, reopened
				rr := reopened.state.Runs[run.ID]
				if rr.Creator != nil || (rr.RepositoryFacts != nil) != (lookupStatus == http.StatusOK) {
					t.Fatal("repository source facts changed creator authority or did not persist")
				}
				st := f.start(t, f.login(t).access)
				for i := 0; i < 2; i++ {
					token, err := f.c.IDToken(context.Background(), st.JobToken, "https://cache.example.test")
					if err != nil {
						t.Fatalf("repository lookup prevented token issuance: %v", err)
					}
					parts := strings.Split(token.Token, ".")
					var claims map[string]any
					if len(parts) != 3 || decodeJWT(parts[1], &claims) != nil {
						t.Fatal("invalid job token")
					}
					for key, value := range map[string]string{"repository_id": "1234", "repository_owner_id": "5678"} {
						if lookupStatus == http.StatusOK {
							if claims[key] != value {
								t.Fatalf("%s=%v, want %s", key, claims[key], value)
							}
						} else if _, present := claims[key]; present {
							t.Fatalf("failed lookup invented %s", key)
						}
					}
					for _, key := range []string{"event_name", "ref_type", "job_workflow_ref"} {
						if _, present := claims[key]; present {
							t.Fatalf("terminal token acquired push claim %s", key)
						}
					}
					if claims["repository"] != body.Repository.Name || claims["ref"] != body.Ref || claims["source_kind"] != kind {
						t.Fatalf("run source claims changed: %#v", claims)
					}
				}
				if calls.Load() != 1 {
					t.Fatal("token issuance repeated repository lookup")
				}
			})
		}
	}
}
