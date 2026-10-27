package poolserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTokenCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"account":"test","callers":{"tailnet_users":[]},"extra":{"keep":true}}`), 0400); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	var out bytes.Buffer
	if err := TokenCommand("create", path, "alice", &out); err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(out.String())
	if !strings.HasPrefix(token, "oyzp_") || len(token) != 48 || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("unexpected token output %q", out.String())
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte(token)) || !bytes.Contains(data, []byte(hash([]byte(token)))) || !bytes.Contains(data, []byte(`"extra"`)) {
		t.Fatal("config lost data or stored plaintext")
	}
	after, _ := os.Stat(path)
	if before.Mode() != after.Mode() {
		t.Fatal("mode changed")
	}
	// Same ownership is required even for a read-only original.
	if before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid || before.Sys().(*syscall.Stat_t).Gid != after.Sys().(*syscall.Stat_t).Gid {
		t.Fatal("ownership changed")
	}
	out.Reset()
	if err := TokenCommand("list", path, "", &out); err != nil || out.String() != "alice\n" {
		t.Fatalf("list %q %v", out.String(), err)
	}
	out.Reset()
	if err := TokenCommand("create", path, "alice", &out); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := TokenCommand("revoke", path, "alice", &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("revoke printed credential")
	}
	if err := TokenCommand("list", path, "", &out); err != nil || out.Len() != 0 {
		t.Fatal("revocation failed")
	}
}

func TestTokenCallerIsolation(t *testing.T) {
	f := newFixture(t)
	f.s.cfg.Callers.Tokens = []TokenCaller{{Name: "alice", SHA256: hash([]byte("alice-secret"))}, {Name: "bob", SHA256: hash([]byte("bob-secret"))}}
	path := "/api/v1alpha1/accounts/oyzu/runs"
	body := RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Commit: testSHA, Operation: Operation{Kind: "build"}}
	auth := func(s string) map[string]string { return map[string]string{"Authorization": "Bearer " + s} }
	status, data, _ := f.request(t, "POST", path, "", body, auth("alice-secret"))
	if status != 201 {
		t.Fatalf("create %d %s", status, data)
	}
	var run Run
	_ = json.Unmarshal(data, &run)
	if run.Trigger.Actor != "token:alice" {
		t.Fatal(run.Trigger)
	}
	for _, suffix := range []string{"", "/cancel"} {
		method := "GET"
		if suffix != "" {
			method = "POST"
		}
		status, _, _ = f.request(t, method, path+"/"+run.ID+suffix, "", nil, auth("bob-secret"))
		if status != 404 {
			t.Fatalf("other caller access %d", status)
		}
	}
	status, data, _ = f.request(t, "GET", path, "", nil, auth("bob-secret"))
	if status != 200 || bytes.Contains(data, []byte(run.ID)) {
		t.Fatalf("list leaked run: %s", data)
	}
	f.s.cfg.Callers.Tokens = nil
	status, _, _ = f.request(t, "GET", path, "micah@example.com", nil, auth("alice-secret"))
	if status != 401 {
		t.Fatal("revoked bearer accepted", status)
	}
	f.s.cfg.Callers.TailnetUsers = nil
	status, _, _ = f.request(t, "GET", path, "micah@example.com", nil, nil)
	if status != 401 {
		t.Fatal("header accepted without configured users")
	}
}

func TestAnonymousRepository(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("anonymous API sent credential")
		}
		calls++
		switch r.URL.Path {
		case "/repos/oyzuai/fleet":
			w.Write([]byte(`{"id":1,"owner":{"id":2},"private":false}`))
		case "/repos/oyzuai/private":
			w.Write([]byte(`{"id":3,"private":true}`))
		case "/repos/oyzuai/missing":
			w.WriteHeader(404)
		default:
			w.Write([]byte(`{"sha":"` + testSHA + `"}`))
		}
	}))
	defer server.Close()
	now := time.Now()
	a := newAnonymousGitHub(Options{HTTPClient: server.Client(), Now: func() time.Time { return now }})
	a.api.base = server.URL
	ctx := context.Background()
	if ok, err := a.CommitExists(ctx, "oyzuai/fleet", testSHA); !ok || err != nil {
		t.Fatal(ok, err)
	}
	source, err := a.Source(ctx, "oyzuai/fleet")
	if err != nil || source.Token != "" || source.Repository != "oyzuai/fleet" {
		t.Fatal(source, err)
	}
	if calls != 2 {
		t.Fatal("repository lookup not cached", calls)
	}
	now = now.Add(11 * time.Minute)
	if _, err = a.repositoryFacts(ctx, "oyzuai/fleet"); err != nil || calls != 3 {
		t.Fatal("cache did not expire", err, calls)
	}
	for _, repo := range []string{"oyzuai/private", "oyzuai/missing"} {
		if _, err = a.CommitExists(ctx, repo, testSHA); err != errPrivateRepository {
			t.Fatal(repo, err)
		}
	}
}

func TestSoloStartupValidation(t *testing.T) {
	f := newFixture(t)
	for _, id := range []int64{0, 12345, 5467712} {
		c := f.cfg
		c.GitHubApp.AppID = id
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		// No-App files omit the optional block.
		if id == 0 {
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(b, &raw)
			delete(raw, "github_app")
			b, _ = json.Marshal(raw)
		}
		path := filepath.Join(t.TempDir(), "server.json")
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadConfig(path); err != nil {
			t.Fatalf("app id %d: %v", id, err)
		}
	}
	c := f.cfg
	c.Callers.TailnetUsers = nil
	c.Callers.GitHub = nil
	if err := c.defaults(); err == nil || !strings.Contains(err.Error(), "pool-server token create") {
		t.Fatal("missing startup guidance", err)
	}
	for _, tokens := range [][]TokenCaller{
		{{Name: "Bad", SHA256: hash([]byte("x"))}},
		{{Name: "alice", SHA256: "bad"}},
		{{Name: "alice", SHA256: hash([]byte("x"))}, {Name: "alice", SHA256: hash([]byte("y"))}},
	} {
		c := f.cfg
		c.Callers.Tokens = tokens
		if err := c.defaults(); err == nil {
			t.Fatal("invalid tokens accepted")
		}
	}
}

func TestNoAppChecksStartupAndPrivateRun(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	f := newFixture(t)
	c := f.cfg
	c.StateDir = t.TempDir()
	c.GitHubApp.AppID = 0
	c.Callers.TailnetUsers = nil
	c.Callers.GitHub = nil
	c.Callers.Tokens = []TokenCaller{{Name: "alice", SHA256: hash([]byte("secret"))}}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential on anonymous request")
		}
		w.WriteHeader(404)
	}))
	defer api.Close()
	s, err := New(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.source.(*anonymousGitHub).api.base = api.URL
	req := httptest.NewRequest("POST", runsPath, strings.NewReader(`{"repository":{"provider":"github","name":"oyzuai/fleet"},"commit":"`+testSHA+`","operation":{"kind":"build"}}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), errPrivateRepository.Error()) {
		t.Fatalf("private run %d %s", rec.Code, rec.Body.String())
	}
	s.enqueueChecksLocked("unused")
	s.retryChecks()
	if s.checks != nil || len(s.dirtyChecks) != 0 || strings.Count(logs.String(), "per-stage checks disabled") != 1 {
		t.Fatal("checks not disabled once", logs.String())
	}
}
