package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/poolserver"
	"github.com/oyzuai/fleet/runnerclient"
)

type poolTestSource struct{}

func (poolTestSource) CommitExists(context.Context, string, string) (bool, error) { return true, nil }
func (poolTestSource) Source(_ context.Context, repo string) (runnerclient.Source, error) {
	return runnerclient.Source{Token: "test-source-only", Repository: repo, Expires: time.Now().Add(time.Hour)}, nil
}
func TestExecutorReportsRealPoolTerminalOutcomes(t *testing.T) {
	for _, mode := range []string{"cancel-without-completion", "missing-task", "verbose-success"} {
		t.Run(mode, func(t *testing.T) {
			var cfg poolserver.Config
			cfg.Account = "test"
			cfg.PublicURL = "https://pool.test"
			cfg.StateDir = t.TempDir()
			cfg.Repositories = []string{"oyzuai/fleet"}
			cfg.Callers.TailnetUsers = []string{"test@example.com"}
			cfg.GitHubApp.AppID = 5467712
			h := sha256.Sum256([]byte("enroll"))
			cfg.EnrollmentTokenSHA256 = hex.EncodeToString(h[:])
			pool, err := poolserver.New(cfg, poolserver.Options{Source: poolTestSource{}})
			if err != nil {
				t.Fatal(err)
			}
			const path = "/api/v1alpha1/accounts/test/runs"
			var run poolserver.Run
			var cancelled atomic.Bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "cancel-without-completion" && r.URL.Path == "/runner/v1/job/finish" && cancelled.CompareAndSwap(false, true) {
					req := httptest.NewRequest("POST", run.Links.Self+"/cancel", nil)
					req.RemoteAddr = "127.0.0.1:1234"
					req.Header.Set("Tailscale-User-Login", "test@example.com")
					rec := httptest.NewRecorder()
					pool.ServeHTTP(rec, req)
					if rec.Code != 202 {
						t.Errorf("cancel: %d %s", rec.Code, rec.Body.String())
					}
				}
				pool.ServeHTTP(w, r)
			})
			server := httptest.NewServer(handler)
			defer server.Close()
			op := poolserver.Operation{Kind: "build"}
			if mode == "missing-task" {
				op = poolserver.Operation{Kind: "run", Task: "not-defined"}
			}
			body, _ := json.Marshal(poolserver.RunCreate{Repository: poolserver.Repository{Provider: "github", Name: "oyzuai/fleet"}, Commit: "0123456789abcdef0123456789abcdef01234567", Ref: "refs/heads/main", Operation: op})
			req, _ := http.NewRequest("POST", server.URL+path, bytes.NewReader(body))
			req.Header.Set("Tailscale-User-Login", "test@example.com")
			req.Header.Set("Content-Type", "application/json")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			err = json.NewDecoder(resp.Body).Decode(&run)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 201 {
				t.Fatalf("create %d %v", resp.StatusCode, err)
			}
			client := runnerclient.New(server.URL, server.Client())
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			enrolled, err := client.Enroll(context.Background(), "enroll", "test", pub)
			if err != nil {
				t.Fatal(err)
			}
			claims := assertion.New(enrolled.ManagerID, "oyzu-runs", "once", time.Now(), time.Minute)
			signed, _ := assertion.Sign(priv, enrolled.KeyID, assertion.TypeLogin, claims)
			access, err := client.Login(context.Background(), signed)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := client.Claim(context.Background(), access.Token)
			if err != nil || claim == nil {
				t.Fatalf("claim %v", err)
			}
			tools, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			token := filepath.Join(dir, "startup")
			if err = os.WriteFile(token, []byte(claim.StartupToken), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FAKE_TOOLS", "1")
			t.Setenv("FAKE_GIT_LOG", filepath.Join(dir, "git-log"))
			if mode == "verbose-success" {
				t.Setenv("FAKE_OYZU_VERBOSE_TAIL", "1")
			}
			if err = Run(context.Background(), Config{Client: client, StartupTokenFile: token, WorkDir: filepath.Join(dir, "work"), Git: tools, Oyzu: tools, LogDrainTimeout: time.Second}); err != nil {
				t.Fatal(err)
			}
			req, _ = http.NewRequest("GET", server.URL+run.Links.Self, nil)
			req.Header.Set("Tailscale-User-Login", "test@example.com")
			resp, err = server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err = json.Unmarshal(b, &run); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "cancel-without-completion":
				if run.State != "failed" || run.CancelRequestedAt == nil || run.Reason == nil || run.Reason.Code != "RUNNER_ERROR" || !strings.Contains(run.Reason.Message, "not confirmed") {
					t.Fatalf("lost cancellation failure: %s", b)
				}
			case "missing-task":
				if run.State != "failed" || run.Reason == nil || run.Reason.Code != "TASK_NOT_DEFINED" {
					t.Fatalf("lost missing-task disposition: %s", b)
				}
			case "verbose-success":
				if run.State != "succeeded" {
					t.Fatalf("verbose success rejected: %s", b)
				}
			}
		})
	}
}
