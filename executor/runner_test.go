package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// The test binary doubles as fake git and oyzu: with FAKE_TOOLS set it acts
// as git for git's subcommands and as oyzu otherwise, instead of running tests.
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_TOOLS") == "" {
		os.Exit(m.Run())
	}
	if len(os.Args) < 2 {
		fakeRenovate()
	}
	switch os.Args[1] {
	case "init", "remote", "config", "fetch", "checkout", "diff", "status", "add", "commit", "rev-parse", "push", "-c":
		fakeGit()
	default:
		fakeOyzu()
	}
}

// fakeGit records its arguments and the auth header it was given, and on
// checkout writes the commit's oyzu.toml.
func fakeGit() {
	args := os.Args[1:]
	rec, _ := json.Marshal(map[string]any{"args": args, "header": os.Getenv("GIT_CONFIG_VALUE_0")})
	f, _ := os.OpenFile(os.Getenv("FAKE_GIT_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(f, string(rec))
	f.Close()
	verb := gitVerb(args)
	if os.Getenv("FAKE_GIT_FAIL") == verb {
		fmt.Fprintln(os.Stderr, "fatal: could not read from remote")
		os.Exit(128)
	}
	switch verb {
	case "checkout":
		_ = os.WriteFile("oyzu.toml", []byte("[tasks.policy-check]\nargv = [\"true\"]\n"), 0o600)
	case "status":
		// No environment holds a NUL, so the tests write it as \0.
		fmt.Print(strings.ReplaceAll(os.Getenv("FAKE_GIT_STATUS"), `\0`, "\x00"))
	case "rev-parse":
		fmt.Println("fedcba9876543210fedcba9876543210fedcba98")
	}
	os.Exit(0)
}

func fakeOyzu() {
	if os.Getenv("FAKE_TRUST_REPORT") != "" {
		reportTrust()
	}
	if p, ok := os.LookupEnv("FAKE_OYZU_PLAN"); ok {
		fmt.Fprintln(os.Stderr, "Planning platform")
		fmt.Print(p)
		os.Exit(0)
	}
	for i := 1; i <= 100; i++ {
		fmt.Printf("line %d of %s\n", i, strings.Join(os.Args[1:], " "))
	}
	if os.Getenv("FAKE_OYZU_LEAK") != "" {
		// Credentials written whole, split across writes and encoded.
		os.Stdout.WriteString("job token oyzu_")
		time.Sleep(50 * time.Millisecond)
		os.Stdout.WriteString("job_ok here\n")
		fmt.Fprintf(os.Stderr, "source %s and %s\n", "ghs_secret", base64.StdEncoding.EncodeToString([]byte("x:ghs_secret")))
		os.Stdout.WriteString("startup oyzu_start_ok\n")
	}
	if os.Getenv("FAKE_OYZU_ID_TOKEN") != "" {
		fetchIDToken()
	}
	if os.Getenv("FAKE_OYZU_SECRETS") != "" {
		// Print the secret, then report what the build could see.
		fmt.Printf("npm token %s\n", os.Getenv("NPM_TOKEN"))
		path := os.Getenv("GCP_KEY")
		b, err := os.ReadFile(path)
		info, _ := os.Stat(path)
		fmt.Printf("key file %v %s mode %v\n", err, b, info.Mode().Perm())
		fmt.Printf("key path %s\n", filepath.Dir(path))
	}
	if os.Getenv("FAKE_OYZU_EGRESS") != "" {
		reportEgress()
	}
	if m, ok := os.LookupEnv("FAKE_OYZU_MANIFEST"); ok {
		_ = os.MkdirAll("dist", 0o700)
		_ = os.WriteFile(filepath.Join("dist", "manifest.json"), []byte(m), 0o600)
	}
	if d := os.Getenv("FAKE_OYZU_SLEEP"); d != "" {
		t, _ := time.ParseDuration(d)
		time.Sleep(t)
	}
	if os.Getenv("FAKE_OYZU_FAIL") != "" {
		os.Exit(3)
	}
	os.Exit(0)
}

// fetchIDToken asks the runner for an ID token the way a build tool would,
// prints it (the log must mask it) and reports what it could see.
func fetchIDToken() {
	for _, kv := range os.Environ() {
		if strings.Contains(kv, "oyzu_job_ok") {
			fmt.Println("job token visible to the build")
		}
	}
	req, _ := http.NewRequest(http.MethodGet, os.Getenv(EnvIDTokenURL)+"?audience=sts.amazonaws.com", nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv(EnvIDTokenRequestToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("id token request failed:", err)
		return
	}
	defer resp.Body.Close()
	var out struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("id token status %d value %s\n", resp.StatusCode, out.Value)

	bad, _ := http.NewRequest(http.MethodGet, os.Getenv(EnvIDTokenURL)+"?audience=vault", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	if resp, err := http.DefaultClient.Do(bad); err == nil {
		fmt.Printf("wrong request token status %d\n", resp.StatusCode)
		resp.Body.Close()
	}
}

// reportEgress prints what a build sees of the egress proxy: the proxy URL
// (whose password the log must mask), whether the CA file is there, and
// whether the credential leaked into its environment.
func reportEgress() {
	fmt.Println("proxy", os.Getenv("HTTPS_PROXY"))
	if b, err := os.ReadFile(os.Getenv(EnvEgressCAFile)); err == nil && strings.Contains(string(b), "BEGIN CERTIFICATE") {
		fmt.Println("job CA present")
	}
	for _, kv := range os.Environ() {
		if strings.Contains(kv, "ghs_egress") {
			fmt.Println("egress credential visible to the build")
		}
	}
}

// fakeRuns is the runner API as a runner sees it.
type fakeRuns struct {
	job        runnerclient.Job
	heartbeats atomic.Int32
	refuseBeat bool
	mu         sync.Mutex
	finished   *runnerclient.Outcome
	startups   []string
	audiences  []string
	// secretsStatus, when set, is job/secrets' answer.
	secretsStatus int
	secretPulls   int
	// egress is the job/egress answer; empty answers 404, as a runs
	// without egress does.
	egress string

	// writeTokens counts tokens that can write handed out.
	writeTokens int
}

func (f *fakeRuns) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	path := strings.TrimPrefix(r.URL.Path, "/runner/v1/")
	if path == "job/start" {
		f.mu.Lock()
		f.startups = append(f.startups, auth)
		f.mu.Unlock()
		if auth != "oyzu_start_ok" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"job_token": "oyzu_job_ok", "heartbeat_seconds": 1, "job": f.job})
		return
	}
	if auth != "oyzu_job_ok" {
		w.WriteHeader(401)
		return
	}
	switch path {
	case "job/heartbeat":
		f.heartbeats.Add(1)
		if f.refuseBeat {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	case "job/source":
		_, _ = w.Write([]byte(`{"token":"ghs_secret","repository":"oyzuai/platform"}`))
	case "job/secrets":
		f.mu.Lock()
		f.secretPulls++
		f.mu.Unlock()
		if f.secretsStatus != 0 {
			w.WriteHeader(f.secretsStatus)
			return
		}
		_, _ = w.Write([]byte(`{"secrets":[{"variable":"NPM_TOKEN","file":false,"value":"bnBtX3NlY3JldF92YWx1ZQ=="},` +
			`{"variable":"GCP_KEY","file":true,"value":"eyJwcml2YXRlX2tleSI6InNla3JpdCJ9"}]}`))
	case "job/id-token":
		var in struct {
			Audience string `json:"audience"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.audiences = append(f.audiences, in.Audience)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"token":"eyJhbGciOiJSUzI1NiJ9.fake-id-token.c2ln","expires_at":"2030-01-01T00:00:00Z"}`))
	case "job/egress":
		if f.egress == "" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(f.egress))

	case "job/write-token":
		f.mu.Lock()
		f.writeTokens++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"token":"ghs_write","repository":"oyzuai/platform","access":"push"}`))
	case "job/finish":
		var o runnerclient.Outcome
		_ = json.NewDecoder(r.Body).Decode(&o)
		f.mu.Lock()
		f.finished = &o
		f.mu.Unlock()
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

const sha = "0123456789abcdef0123456789abcdef01234567"

func setup(t *testing.T, job runnerclient.Job) (*fakeRuns, Config, string) {
	t.Helper()
	runs := &fakeRuns{job: job}
	srv := httptest.NewServer(runs)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "startup-token")
	if err := os.WriteFile(tokenFile, []byte("oyzu_start_ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitLog := filepath.Join(dir, "git.log")
	self, _ := os.Executable()
	cfg := Config{
		Client:           runnerclient.New(srv.URL, srv.Client()),
		StartupTokenFile: tokenFile,
		WorkDir:          filepath.Join(dir, "work"),
		GitURL:           "https://github.example",
		Git:              self,
		Oyzu:             self,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	t.Setenv("FAKE_GIT_LOG", gitLog)
	t.Setenv("FAKE_TOOLS", "1")
	return runs, cfg, gitLog
}

func buildJob(op string, command ...string) runnerclient.Job {
	return runnerclient.Job{ID: 9, Attempt: 1, Repository: "oyzuai/platform", HeadSHA: sha, Operation: op, Task: "policy-check", Command: command}
}

func TestRunSucceeds(t *testing.T) {
	runs, cfg, gitLog := setup(t, buildJob("build", "oyzu", "build", "backend"))
	t.Setenv("FAKE_OYZU_SLEEP", "1500ms")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.StartupTokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup token file still there: %v", err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" || *o.ExitCode != 0 || !strings.Contains(o.Summary, "line 100 of build backend") ||
		strings.Contains(o.Summary, "line 40 of") {
		t.Fatalf("outcome = %+v", o)
	}
	if runs.heartbeats.Load() == 0 {
		t.Fatal("no heartbeat during a 1.5s build")
	}
	log, _ := os.ReadFile(gitLog)
	if strings.Contains(string(log), "ghs_secret") {
		t.Fatalf("the source token is in git's arguments or a log line: %s", log)
	}
	if !strings.Contains(string(log), `"header":"Authorization: Basic `) || !strings.Contains(string(log), sha) {
		t.Fatalf("git calls = %s", log)
	}
}

func TestRunPlans(t *testing.T) {
	job := buildJob("build", "oyzu", "build", "--affected", "89abcdef0123456789abcdef0123456789abcdef", "--plan", "--json")
	job.Kind, job.AffectedBase = "plan", "89abcdef0123456789abcdef0123456789abcdef"
	runs, cfg, gitLog := setup(t, job)
	t.Setenv("FAKE_OYZU_PLAN", "{\n  \"schemaVersion\": 1,\n  \"kind\": \"build-preview\"\n}\n")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" || string(o.Plan) != `{"schemaVersion":1,"kind":"build-preview"}` {
		t.Fatalf("outcome = %+v, plan %s", o, o.Plan)
	}
	if strings.Contains(o.Summary, "schemaVersion") || !strings.Contains(o.Summary, "Planning platform") {
		t.Errorf("summary = %q, want the stderr tail and not the record", o.Summary)
	}
	log, _ := os.ReadFile(gitLog)
	for _, want := range []string{`"--filter=blob:none"`, `"remote.origin.promisor"`, `["diff","--numstat","89abcdef`} {
		if !strings.Contains(string(log), want) {
			t.Errorf("git calls lack %s: %s", want, log)
		}
	}
	if strings.Contains(string(log), `"--depth"`) {
		t.Errorf("a plan fetched shallowly: %s", log)
	}
}

func TestRunFailsAPlanWithNoRecord(t *testing.T) {
	job := buildJob("build", "oyzu", "build", "--plan", "--json")
	job.Kind = "plan"
	runs, cfg, _ := setup(t, job)
	t.Setenv("FAKE_OYZU_PLAN", "not a record")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || o.Plan != nil || !strings.Contains(o.Summary, "no readable plan") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunReportsFailure(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_OYZU_FAIL", "1")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || *o.ExitCode != 3 {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunSkipsAMissingTask(t *testing.T) {
	job := buildJob("run", "oyzu", "run", "nope")
	job.Task = "nope"
	runs, cfg, _ := setup(t, job)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "skipped" {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunReportsCheckoutFailure(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_GIT_FAIL", "fetch")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "could not read from remote") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunStopsWhenRunsTakesTheJobBack(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	runs.refuseBeat = true
	t.Setenv("FAKE_OYZU_SLEEP", "20s")
	start := time.Now()
	err := Run(context.Background(), cfg)
	if !errors.Is(err, errLost) {
		t.Fatalf("Run = %v, want errLost", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("the build was not stopped")
	}
	if runs.finished != nil {
		t.Fatalf("reported %+v for a job that is no longer ours", runs.finished)
	}
}

func TestRunRejectsBadJobs(t *testing.T) {
	for name, job := range map[string]runnerclient.Job{
		"bad sha":  {ID: 1, Repository: "oyzuai/platform", HeadSHA: "main", Command: []string{"oyzu", "build"}},
		"bad repo": {ID: 1, Repository: "../x", HeadSHA: sha, Command: []string{"oyzu", "build"}},
		"dot name": {ID: 1, Repository: "oyzuai/..", HeadSHA: sha, Command: []string{"oyzu", "build"}},
		"not oyzu": {ID: 1, Repository: "oyzuai/platform", HeadSHA: sha, Command: []string{"sh", "-c", "x"}},
	} {
		runs, cfg, _ := setup(t, job)
		if err := Run(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if o := runs.finished; o == nil || o.State != "failed" {
			t.Errorf("%s: outcome = %+v", name, o)
		}
	}
}

func TestStartupTokenIsReadOnce(t *testing.T) {
	_, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	if err := os.WriteFile(cfg.StartupTokenFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("ran with an empty startup token")
	}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("ran without a startup token file")
	}
}

func TestStartupTokenFromAVariableIsUnset(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build", "backend"))
	cfg.StartupTokenFile, cfg.StartupTokenEnv = "", "OYZU_TEST_STARTUP_TOKEN"
	t.Setenv("OYZU_TEST_STARTUP_TOKEN", "oyzu_start_ok\n")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("OYZU_TEST_STARTUP_TOKEN"); ok {
		t.Fatal("the startup token variable is still set")
	}
	if o := runs.finished; o == nil || o.State != "succeeded" {
		t.Fatalf("outcome = %+v", o)
	}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("ran twice from one variable")
	}
}

func TestTail(t *testing.T) {
	var tl tail
	for i := range 100 {
		fmt.Fprintf(&tl, "l%d\n", i)
	}
	fmt.Fprint(&tl, "partial")
	got := strings.Split(tl.String(), "\n")
	if len(got) != summaryLines+1 || got[0] != "l40" || got[len(got)-1] != "partial" {
		t.Fatalf("tail = %v", got)
	}
}

// LOG-01: build output reaches neither the runner's own stdout and stderr
// (the pool host's log) nor, unmasked, the check run's summary.
func TestRunKeepsBuildOutputOutOfRunnerLogs(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build", "backend"))
	t.Setenv("FAKE_OYZU_LEAK", "1")
	var own bytes.Buffer
	restore := captureStdio(t, &own)
	err := Run(context.Background(), cfg)
	restore()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(own.String(), "line 1 of") || strings.Contains(own.String(), "job token") {
		t.Fatalf("build output reached the runner's stdio: %q", own.String())
	}
	o := runs.finished
	if o == nil || !strings.Contains(o.Summary, "*** here") || !strings.Contains(o.Summary, "startup ***") {
		t.Fatalf("outcome = %+v", o)
	}
	for _, s := range []string{"oyzu_job_ok", "ghs_secret", "oyzu_start_ok", "Z2hzX3NlY3JldA"} {
		if strings.Contains(o.Summary, s) {
			t.Fatalf("%s is in the summary: %s", s, o.Summary)
		}
	}
}

// captureStdio sends this process's stdout and stderr to buf until restore.
func captureStdio(t *testing.T, buf *bytes.Buffer) (restore func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan struct{})
	go func() { _, _ = io.Copy(buf, r); close(done) }()
	return func() {
		os.Stdout, os.Stderr = stdout, stderr
		w.Close()
		<-done
	}
}

func TestBuildGetsIDTokensWithoutTheJobToken(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_OYZU_ID_TOKEN", "1")
	t.Setenv(EnvIDTokenURL, "http://attacker.example/")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" {
		t.Fatalf("outcome = %+v", o)
	}
	if !strings.Contains(o.Summary, "id token status 200 value ***") {
		t.Errorf("the build did not get a masked ID token:\n%s", o.Summary)
	}
	if strings.Contains(o.Summary, "fake-id-token") {
		t.Errorf("the ID token is in the summary:\n%s", o.Summary)
	}
	if !strings.Contains(o.Summary, "wrong request token status 401") {
		t.Errorf("a wrong request token was not refused:\n%s", o.Summary)
	}
	if strings.Contains(o.Summary, "job token visible") || strings.Contains(o.Summary, "failed") {
		t.Errorf("summary:\n%s", o.Summary)
	}
	if len(runs.audiences) != 1 || runs.audiences[0] != "sts.amazonaws.com" {
		t.Errorf("audiences asked for = %q", runs.audiences)
	}
}

func TestBuildSecretsReachTheBuildMasked(t *testing.T) {
	job := buildJob("build", "oyzu", "build")
	job.Secrets = []string{"GCP_KEY", "NPM_TOKEN"}
	runs, cfg, _ := setup(t, job)
	cfg.SecretsDir = t.TempDir()
	t.Setenv("FAKE_OYZU_SECRETS", "1")
	t.Setenv("NPM_TOKEN", "inherited-from-the-host")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" {
		t.Fatalf("outcome = %+v", o)
	}
	for _, leak := range []string{"npm_secret_value", "sekrit", "inherited-from-the-host"} {
		if strings.Contains(o.Summary, leak) {
			t.Errorf("%q is in the summary:\n%s", leak, o.Summary)
		}
	}
	// Windows reports a read-only file as 0444 whatever its owner-only mode.
	mode := "-r--------"
	if runtime.GOOS == "windows" {
		mode = "-r--r--r--"
	}
	if !strings.Contains(o.Summary, "npm token ***") || !strings.Contains(o.Summary, "key file <nil> *** mode "+mode) {
		t.Errorf("summary:\n%s", o.Summary)
	}
	entries, _ := os.ReadDir(cfg.SecretsDir)
	if len(entries) != 0 {
		t.Errorf("secret files left behind: %v", entries)
	}
}

func TestNoSecretsPulledUnlessTheJobNamesThem(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runs.secretPulls != 0 {
		t.Errorf("pulled secrets %d times for a job with none", runs.secretPulls)
	}
}

func TestRefusedSecretsFailTheJob(t *testing.T) {
	job := buildJob("build", "oyzu", "build")
	job.Secrets = []string{"NPM_TOKEN"}
	runs, cfg, _ := setup(t, job)
	runs.secretsStatus = http.StatusForbidden
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "build secrets") {
		t.Fatalf("outcome = %+v", o)
	}

	// Released variables the job did not name are refused too.
	job.Secrets = []string{"NPM_TOKEN"}
	runs, cfg, _ = setup(t, job)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || strings.Contains(o.Summary, "npm_secret_value") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunnerStartsTheEgressProxyForGrants(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	runs.egress = `{"grants":[{"host":"github.com","authorization":"Bearer ghs_egress","expires_at":"2030-01-01T00:00:00Z"}],"repositories":["oyzuai/oyzu"]}`
	t.Setenv("FAKE_OYZU_EGRESS", "1")
	t.Setenv("HTTPS_PROXY", "http://corp.example:3128")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" {
		t.Fatalf("outcome = %+v", o)
	}
	if !strings.Contains(o.Summary, "proxy http://oyzu:***@127.0.0.1:") || !strings.Contains(o.Summary, "job CA present") ||
		strings.Contains(o.Summary, "visible to the build") || strings.Contains(o.Summary, "corp.example") {
		t.Fatalf("summary:\n%s", o.Summary)
	}
}

func TestRunnerWithoutGrantsLeavesTheProxyAlone(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_OYZU_EGRESS", "1")
	t.Setenv("HTTPS_PROXY", "http://corp.example:3128")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "succeeded" || !strings.Contains(o.Summary, "proxy http://corp.example:3128") ||
		strings.Contains(o.Summary, "job CA present") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestRunnerFailsWhenEgressGrantsFail(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	runs.egress = `not json`
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "egress grants") {
		t.Fatalf("outcome = %+v", o)
	}
}
