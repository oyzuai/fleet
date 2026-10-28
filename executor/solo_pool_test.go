package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/poolserver"
	"github.com/oyzuai/fleet/runnerclient"
)

type soloTransport func(*http.Request) (*http.Response, error)

func (f soloTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The fake GitHub serves both anonymous API responses and a real Git smart-HTTP
// checkout. Neither source-provider nor checkout is replaced with a test stub.
func TestNoAppPublicPoolCheckout(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	command := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	source := filepath.Join(root, "source")
	if err = os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	command(source, "init", "--quiet")
	if err = os.WriteFile(filepath.Join(source, "input.txt"), []byte("public source"), 0600); err != nil {
		t.Fatal(err)
	}
	command(source, "add", ".")
	command(source, "commit", "--quiet", "-m", "public")
	sha := command(source, "rev-parse", "HEAD")
	repos := filepath.Join(root, "repos")
	if err = os.MkdirAll(filepath.Join(repos, "owner"), 0700); err != nil {
		t.Fatal(err)
	}
	command(root, "clone", "--quiet", "--bare", source, filepath.Join(repos, "owner", "public.git"))
	backend := &cgi.Handler{Path: filepath.Join(command(root, "--exec-path"), "git-http-backend"), Env: []string{"GIT_PROJECT_ROOT=" + repos, "GIT_HTTP_EXPORT_ALL=1"}}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("anonymous GitHub received authorization")
		}
		switch r.URL.Path {
		case "/repos/owner/public":
			json.NewEncoder(w).Encode(map[string]any{"id": 1, "owner": map[string]int{"id": 2}, "private": false})
		case "/repos/owner/public/commits/" + sha:
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})
		default:
			backend.ServeHTTP(w, r)
		}
	}))
	defer github.Close()
	transport := github.Client().Transport
	api := &http.Client{Transport: soloTransport(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		u := *r.URL
		clone.URL = &u
		clone.URL.Scheme = "https"
		clone.URL.Host = strings.TrimPrefix(github.URL, "https://")
		return transport.RoundTrip(clone)
	})}
	var cfg poolserver.Config
	cfg.Account = "test"
	cfg.PublicURL = "https://pool.test"
	cfg.StateDir = filepath.Join(root, "state")
	cfg.Repositories = []string{"owner/public"}
	cfg.EnrollmentTokenSHA256 = snapshotDigest([]byte("enroll"))[7:]
	cfg.Callers.Tokens = []poolserver.TokenCaller{{Name: "alice", SHA256: snapshotDigest([]byte("caller-secret"))[7:]}}
	pool, err := poolserver.New(cfg, poolserver.Options{HTTPClient: api})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(pool)
	defer server.Close()
	body, _ := json.Marshal(poolserver.RunCreate{Repository: poolserver.Repository{Provider: "github", Name: "owner/public"}, Commit: sha, Operation: poolserver.Operation{Kind: "build"}})
	req, _ := http.NewRequest("POST", server.URL+"/api/v1alpha1/accounts/test/runs", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer caller-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("create %d %s", resp.StatusCode, b)
	}
	ctx := context.Background()
	client := runnerclient.New(server.URL, server.Client())
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	enrolled, err := client.Enroll(ctx, "enroll", "test", pub)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertion.New(enrolled.ManagerID, "oyzu-runs", "public-checkout", time.Now(), time.Minute)
	signed, err := assertion.Sign(priv, enrolled.KeyID, assertion.TypeLogin, claims)
	if err != nil {
		t.Fatal(err)
	}
	access, err := client.Login(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Report(ctx, access.Token, runnerclient.Report{Facts: map[string]string{manager.FactIsolation: "container", manager.FactEgress: manager.EgressEnforced, manager.FactUntrusted: manager.UntrustedAccepted}}); err != nil {
		t.Fatal(err)
	}
	claim, err := client.Claim(ctx, access.Token)
	if err != nil || claim == nil {
		t.Fatal("claim", err)
	}
	started, err := client.Start(ctx, claim.StartupToken, runnerclient.StartupAssignment{})
	if err != nil {
		t.Fatal(err)
	}
	src, err := client.Source(ctx, started.JobToken)
	if err != nil || src.Token != "" {
		t.Fatal("source", src, err)
	}
	// Trust only the local fake's generated certificate for the actual Git client.
	cert := filepath.Join(root, "ca.pem")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: github.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", cert)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	work := filepath.Join(root, "checkout")
	if err = os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err = checkout(ctx, Config{Git: git, GitURL: github.URL, WorkDir: work}, src.Token, started.Job); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(work, "input.txt"))
	if err != nil || string(contents) != "public source" {
		t.Fatal("checkout content", err)
	}
	config, err := os.ReadFile(filepath.Join(work, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Authorization", "oyzp_", "caller-secret", started.JobToken, "x-access-token"} {
		if bytes.Contains(config, []byte(secret)) {
			t.Fatal("credential persisted in git config")
		}
	}
}
