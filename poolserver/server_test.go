package poolserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

type testSource struct {
	exists bool
	err    error
}

func (f testSource) CommitExists(context.Context, string, string) (bool, error) {
	return f.exists, f.err
}
func (f testSource) Source(_ context.Context, repo string) (runnerclient.Source, error) {
	return runnerclient.Source{Token: "test-source-only", Repository: repo, Expires: time.Now().Add(time.Hour)}, f.err
}

type fixture struct {
	s   *Server
	ts  *httptest.Server
	c   *runnerclient.Client
	cfg Config
	now atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.now.Store(time.Now().UTC().Truncate(time.Second).Unix())
	f.cfg.Account = "oyzu"
	f.cfg.PublicURL = "https://pool.example.test"
	f.cfg.StateDir = t.TempDir()
	f.cfg.Repositories = []string{"oyzuai/fleet"}
	f.cfg.EnrollmentTokenSHA256 = hash([]byte("enrollment"))
	f.cfg.Callers.TailnetUsers = []string{"micah@example.com", "other@example.com"}
	f.cfg.Callers.GitHub = []GitHubCaller{{Repository: "oyzuai/fleet", Refs: []string{"refs/heads/main", "refs/pull/*"}}}
	f.cfg.GitHubApp.AppID = 5467712
	var err error
	f.s, err = New(f.cfg, Options{Source: testSource{exists: true}, Now: func() time.Time { return time.Unix(f.now.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	f.ts = httptest.NewServer(f.s)
	t.Cleanup(f.ts.Close)
	f.c = runnerclient.New(f.ts.URL, f.ts.Client())
	return f
}
func (f *fixture) request(t *testing.T, method, path, owner string, body any, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "" {
		req.Header.Set("Tailscale-User-Login", owner)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b, resp.Header
}
func createBody() RunCreate {
	return RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Commit: testSHA, Ref: "refs/heads/main", Operation: Operation{Kind: "build", Targets: []string{"cli"}}}
}

const runsPath = "/api/v1alpha1/accounts/oyzu/runs"

func (f *fixture) create(t *testing.T) Run {
	t.Helper()
	status, b, _ := f.request(t, "POST", runsPath, "micah@example.com", createBody(), nil)
	if status != 201 {
		t.Fatalf("create status %d: %s", status, b)
	}
	var run Run
	if err := json.Unmarshal(b, &run); err != nil {
		t.Fatal(err)
	}
	return run
}

type loginIdentity struct {
	enrolled runnerclient.Enrolled
	key      ed25519.PrivateKey
	access   string
}

func (f *fixture) login(t *testing.T) loginIdentity {
	t.Helper()
	id := f.loginWithoutReport(t)
	if err := f.c.Report(context.Background(), id.access, runnerclient.Report{Facts: qualifiedFacts()}); err != nil {
		t.Fatal(err)
	}
	return id
}

func qualifiedFacts() map[string]string {
	return map[string]string{manager.FactOS: "linux", manager.FactIsolation: "container", manager.FactEgress: manager.EgressEnforced, manager.FactUntrusted: manager.UntrustedAccepted}
}

func (f *fixture) loginWithoutReport(t *testing.T) loginIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.c.Enroll(context.Background(), "enrollment", "test-manager", pub)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertion.New(e.ManagerID, "oyzu-runs", randomToken(), time.Unix(f.now.Load(), 0), time.Minute)
	signed, err := assertion.Sign(priv, e.KeyID, assertion.TypeLogin, claims)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.c.Login(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	return loginIdentity{e, priv, access.Token}
}
func (f *fixture) start(t *testing.T, access string) runnerclient.Started {
	t.Helper()
	c, e := f.c.Claim(context.Background(), access)
	if e != nil || c == nil {
		t.Fatalf("claim: %v", e)
	}
	st, e := f.c.Start(context.Background(), c.StartupToken, runnerclient.StartupAssignment{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.Start(context.Background(), c.StartupToken, runnerclient.StartupAssignment{}); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatalf("startup replay accepted: %v", e)
	}
	return st
}
func TestRunLifecycleRealRunnerClient(t *testing.T) {
	f := newFixture(t)
	run := f.create(t)
	id := f.login(t)
	ctx := context.Background()
	demand, err := f.c.Demand(ctx, id.access)
	if err != nil || demand.Ready != 1 {
		t.Fatalf("demand: %#v %v", demand, err)
	}
	if err = f.c.Report(ctx, id.access, runnerclient.Report{Facts: qualifiedFacts(), Slots: runnerclient.Slots{Max: 2}}); err != nil {
		t.Fatal(err)
	}
	session, err := f.c.ReadinessSession(ctx, id.access, "boot")
	if err != nil || session.Enabled || session.ID != "" {
		t.Fatalf("readiness: %#v %v", session, err)
	}
	st := f.start(t, id.access)
	if strings.Join(st.Job.Command, " ") != "oyzu build --isolated --full cli" || st.Job.Kind != "build" || st.Job.HeadSHA != testSHA || len(st.Job.Secrets) != 0 {
		t.Fatalf("unsafe job: %#v", st.Job)
	}
	source, err := f.c.Source(ctx, st.JobToken)
	if err != nil || source.Repository != "oyzuai/fleet" {
		t.Fatalf("source: %#v %v", source, err)
	}
	expires, cancel, err := f.c.HeartbeatStatus(ctx, st.JobToken)
	if err != nil || cancel || expires.IsZero() {
		t.Fatalf("heartbeat %v %v %v", expires, cancel, err)
	}
	zero := 0
	output := runnerclient.Output{Path: "dist/report.xml", Kind: "report", Digest: "sha256:" + strings.Repeat("a", 64), MediaType: "application/xml", Size: 10, Target: "cli", Name: "report", Version: "1.0", OCIDigest: "sha256:" + strings.Repeat("b", 64)}
	if err = f.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "succeeded", ExitCode: &zero, Outputs: []runnerclient.Output{output}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.c.Source(ctx, st.JobToken); !errors.Is(err, runnerclient.ErrUnauthenticated) {
		t.Fatalf("post-finish source accepted: %v", err)
	}
	status, b, _ := f.request(t, "GET", run.Links.Result, "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte(`"state":"succeeded"`)) || !bytes.Contains(b, []byte(output.Digest)) {
		t.Fatalf("result %d %s", status, b)
	}
	for _, extra := range []string{`"target":`, `"name":`, `"version":`, `"oci_digest":`} {
		if bytes.Contains(b, []byte(extra)) {
			t.Fatalf("runner-only output field leaked: %s", b)
		}
	}
	status, b, _ = f.request(t, "GET", run.Links.Self+"/outputs/"+output.Digest, "micah@example.com", nil, nil)
	if status != 404 || !bytes.Contains(b, []byte("OUTPUT_NOT_FOUND")) {
		t.Fatalf("output %d %s", status, b)
	}
	for _, route := range []string{"job/secrets", "job/write-token", "job/kind/start", "readiness/work"} {
		status, _, _ := f.request(t, "POST", "/runner/v1/"+route, "", nil, map[string]string{"Authorization": "Bearer " + st.JobToken})
		if status != 404 {
			t.Fatalf("slice-only route %s: %d", route, status)
		}
	}
}
func TestAccessValidationAndIdempotency(t *testing.T) {
	f := newFixture(t)
	body := createBody()
	headers := map[string]string{"Idempotency-Key": "once"}
	status, b, _ := f.request(t, "POST", runsPath, "micah@example.com", body, headers)
	if status != 201 {
		t.Fatalf("create %d %s", status, b)
	}
	var run Run
	_ = json.Unmarshal(b, &run)
	status, b, _ = f.request(t, "POST", runsPath, "micah@example.com", body, headers)
	if status != 200 || !bytes.Contains(b, []byte(run.ID)) {
		t.Fatalf("retry %d %s", status, b)
	}
	changed := body
	changed.Operation = Operation{Kind: "run", Task: "policy-check"}
	status, b, _ = f.request(t, "POST", runsPath, "micah@example.com", changed, headers)
	if status != 409 || !bytes.Contains(b, []byte("IDEMPOTENCY_KEY_REUSED")) {
		t.Fatalf("key conflict %d %s", status, b)
	}
	for _, path := range []string{run.Links.Self, run.Links.Logs, run.Links.Result, run.Links.Self + "/outputs/x"} {
		status, _, _ := f.request(t, "GET", path, "other@example.com", nil, nil)
		if status != 404 {
			t.Fatalf("foreign run %s: %d", path, status)
		}
	}
	status, _, _ = f.request(t, "POST", run.Links.Self+"/cancel", "other@example.com", nil, nil)
	if status != 404 {
		t.Fatal("foreign cancel accepted")
	}
	status, b, _ = f.request(t, "GET", runsPath, "other@example.com", nil, nil)
	if status != 200 || bytes.Contains(b, []byte(run.ID)) {
		t.Fatal("foreign list exposed run")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", runsPath, bytes.NewReader(mustJSON(body)))
	req.RemoteAddr = "198.51.100.1:4567"
	req.Header.Set("Tailscale-User-Login", "micah@example.com")
	req.Header.Set("Content-Type", "application/json")
	f.s.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("non-loopback identity trusted")
	}
	status, _, _ = f.request(t, "GET", runsPath, "micah@example.com", nil, map[string]string{"Authorization": "Bearer invalid"})
	if status != 401 {
		t.Fatal("invalid explicit bearer bypassed")
	}
	bads := []any{map[string]any{"repository": body.Repository, "commit": testSHA, "operation": map[string]any{"kind": "build", "isolated": false}}, map[string]any{"repository": body.Repository, "commit": "main", "operation": body.Operation}, map[string]any{"repository": body.Repository, "commit": testSHA, "operation": map[string]any{"kind": "build", "targets": []string{"--off"}}}, map[string]any{"repository": body.Repository, "commit": testSHA, "operation": map[string]any{"kind": "run", "task": "--off"}}, map[string]any{"repository": body.Repository, "commit": testSHA, "operation": map[string]any{"kind": "build", "targets": []string{}, "affected_base": testSHA}}}
	for _, bad := range bads {
		status, b, _ = f.request(t, "POST", runsPath, "micah@example.com", bad, nil)
		if status != 400 && status != 422 {
			t.Fatalf("unsafe create accepted %d %s", status, b)
		}
	}
	unknown := body
	unknown.Repository.Name = "oyzuai/other"
	status, b, _ = f.request(t, "POST", runsPath, "micah@example.com", unknown, nil)
	if status != 403 || !bytes.Contains(b, []byte("PERMISSION_DENIED")) {
		t.Fatalf("unlisted repo %d %s", status, b)
	}
	f.s.source = testSource{exists: false}
	status, b, _ = f.request(t, "POST", runsPath, "micah@example.com", body, nil)
	if status != 422 || !bytes.Contains(b, []byte("COMMIT_NOT_FOUND")) {
		t.Fatalf("missing commit %d %s", status, b)
	}
	for _, query := range []string{"?page_size=0", "?cursor=!!!", "?commit=main", "?state=unknown", "?repository=other"} {
		status, _, _ = f.request(t, "GET", runsPath+query, "micah@example.com", nil, nil)
		if status != 400 {
			t.Fatalf("bad page %s: %d", query, status)
		}
	}
}

func TestCreateSchemaAndServerSelectedCommands(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []any{
		map[string]any{"repository": createBody().Repository, "commit": testSHA, "operation": map[string]any{"kind": "build", "command": []string{"sh"}}},
		map[string]any{"repository": createBody().Repository, "commit": testSHA, "operation": map[string]any{"kind": "build", "targets": nil}},
		map[string]any{"repository": createBody().Repository, "commit": testSHA},
	} {
		status, b, _ := f.request(t, "POST", runsPath, "micah@example.com", bad, nil)
		if status != 422 || !bytes.Contains(b, []byte("VALIDATION_FAILED")) {
			t.Fatalf("schema validation %d %s", status, b)
		}
	}
	id := f.login(t)
	for _, op := range []Operation{{Kind: "build", AffectedBase: testSHA}, {Kind: "run", Task: "cli:test"}} {
		body := createBody()
		body.Operation = op
		status, b, _ := f.request(t, "POST", runsPath, "micah@example.com", body, nil)
		if status != 201 {
			t.Fatalf("create operation %d %s", status, b)
		}
		st := f.start(t, id.access)
		want := "oyzu build --isolated --full --affected " + testSHA
		if op.Kind == "run" {
			want = "oyzu run --isolated cli:test"
		}
		if strings.Join(st.Job.Command, " ") != want {
			t.Fatalf("command %v", st.Job.Command)
		}
		if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "succeeded"}); err != nil {
			t.Fatal(err)
		}
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestCancelReleaseAndLeasePersistence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.login(t)
	queued := f.create(t)
	status, _, _ := f.request(t, "POST", queued.Links.Self+"/cancel", "micah@example.com", nil, nil)
	if status != 202 {
		t.Fatal("queued cancel")
	}
	c, e := f.c.Claim(ctx, id.access)
	if e != nil || c != nil {
		t.Fatalf("cancelled job claim: %#v %v", c, e)
	}
	run := f.create(t)
	c, e = f.c.Claim(ctx, id.access)
	if e != nil || c == nil {
		t.Fatal(e)
	}
	released, e := f.c.Release(ctx, id.access, runnerclient.Release{JobID: c.JobID, Attempt: c.Attempt})
	if e != nil || !released {
		t.Fatalf("release %v %v", released, e)
	}
	c2, e := f.c.Claim(ctx, id.access)
	if e != nil || c2.Attempt != 1 {
		t.Fatalf("release consumed attempt %#v %v", c2, e)
	}
	if _, e = f.c.Start(ctx, c.StartupToken, runnerclient.StartupAssignment{}); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("released startup retained authority")
	}
	st, e := f.c.Start(ctx, c2.StartupToken, runnerclient.StartupAssignment{})
	if e != nil {
		t.Fatal(e)
	}
	status, _, _ = f.request(t, "POST", run.Links.Self+"/cancel", "micah@example.com", nil, nil)
	if status != 202 {
		t.Fatal("running cancel")
	}
	_, cancel, e := f.c.HeartbeatStatus(ctx, st.JobToken)
	if e != nil || !cancel {
		t.Fatalf("cancel directive %v %v", cancel, e)
	}
	if e = f.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "succeeded"}); e == nil {
		t.Fatal("cancel race lost")
	}
	if e = f.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "cancelled"}); e != nil {
		t.Fatal(e)
	}
	timeout := f.create(t)
	st = f.start(t, id.access)
	f.now.Add(121)
	reopened, e := New(f.cfg, Options{Source: testSource{exists: true}, Now: func() time.Time { return time.Unix(f.now.Load(), 0) }})
	if e != nil {
		t.Fatal(e)
	}
	f.ts.Config.Handler = reopened
	f.s = reopened
	status, b, _ := f.request(t, "GET", timeout.Links.Self, "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte(`"state":"timed_out"`)) || !bytes.Contains(b, []byte("LEASE_EXPIRED")) {
		t.Fatalf("expired persisted run %d %s", status, b)
	}
	if _, e = f.c.Source(ctx, st.JobToken); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("expired source accepted")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e = f.c.Enroll(ctx, "enrollment", "again", pub); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("enrollment reused after restart")
	}
}
func TestAssertionReplayRotationAndRestart(t *testing.T) {
	f := newFixture(t)
	id := f.login(t)
	ctx := context.Background()
	claims := assertion.New(id.enrolled.ManagerID, "oyzu-runs", "single-jti", time.Unix(f.now.Load(), 0), time.Minute)
	a, _ := assertion.Sign(id.key, id.enrolled.KeyID, assertion.TypeLogin, claims)
	if _, e := f.c.Login(ctx, a); e != nil {
		t.Fatal(e)
	}
	if _, e := f.c.Login(ctx, a); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("assertion replay")
	}
	nextPub, nextPriv, _ := ed25519.GenerateKey(rand.Reader)
	claims.ID = "rotate"
	claims.NewKey = assertion.EncodeKey(nextPub)
	a, _ = assertion.Sign(id.key, id.enrolled.KeyID, assertion.TypeRotation, claims)
	kid, e := f.c.RegisterKey(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	claims.ID = "third"
	a, _ = assertion.Sign(id.key, id.enrolled.KeyID, assertion.TypeRotation, claims)
	if _, e = f.c.RegisterKey(ctx, a); !errors.Is(e, runnerclient.ErrKeyLimit) {
		t.Fatalf("key limit: %v", e)
	}
	claims.ID = "new-key-login"
	claims.NewKey = ""
	a, _ = assertion.Sign(nextPriv, kid, assertion.TypeLogin, claims)
	if _, e = f.c.Login(ctx, a); e != nil {
		t.Fatal(e)
	}
	claims.ID = "retired"
	a, _ = assertion.Sign(id.key, id.enrolled.KeyID, assertion.TypeLogin, claims)
	if _, e = f.c.Login(ctx, a); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("old key not retired")
	}
	if _, e = f.c.Demand(ctx, id.access); e != nil {
		t.Fatal("access token retired with signing key")
	}
	// Credentials on disk contain only hashes, not the bearer returned to callers.
	files, _ := filepath.Glob(filepath.Join(f.cfg.StateDir, "*.json"))
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(b, []byte(id.access)) {
			t.Fatal("plaintext bearer persisted")
		}
	}
}
func chunkFor(t *testing.T, attempt int, seq, first int64, text string) (runnerclient.LogChunk, []byte) {
	t.Helper()
	entry := runnerclient.LogEntry{Sequence: first, Stream: "stdout", Time: time.Now().UTC(), Text: text}
	raw := append(mustJSON(entry), '\n')
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write(raw)
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return runnerclient.LogChunk{Attempt: attempt, Seq: seq, First: first, Last: first, Entries: 1, Data: compressed.Bytes(), Hash: hash(raw)}, raw
}
func TestLogsGaplessBoundedDrainAndLongPoll(t *testing.T) {
	f := newFixture(t)
	run := f.create(t)
	id := f.login(t)
	st := f.start(t, id.access)
	ctx := context.Background()
	chunk, raw := chunkFor(t, 1, 1, 1, "hello\n")
	ack, e := f.c.UploadLogs(ctx, st.JobToken, chunk)
	if e != nil || ack.NextSeq != 2 {
		t.Fatalf("upload %#v %v", ack, e)
	}
	if _, e = f.c.UploadLogs(ctx, st.JobToken, chunk); e != nil {
		t.Fatal("idempotent chunk", e)
	}
	bad := chunk
	bad.Seq = 3
	if _, e = f.c.UploadLogs(ctx, st.JobToken, bad); e == nil {
		t.Fatal("gap accepted")
	}
	bad = chunk
	bad.Hash = strings.Repeat("a", 64)
	if _, e = f.c.UploadLogs(ctx, st.JobToken, bad); e == nil {
		t.Fatal("hash mismatch accepted")
	}
	status, b, h := f.request(t, "GET", run.Links.Self, "micah@example.com", nil, nil)
	if status != 200 {
		t.Fatal(string(b))
	}
	status, _, _ = f.request(t, "GET", run.Links.Self, "micah@example.com", nil, map[string]string{"If-None-Match": h.Get("ETag")})
	if status != 304 {
		t.Fatal("ETag unchanged")
	}
	status, b, _ = f.request(t, "GET", run.Links.Logs, "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte("hello")) || !bytes.Contains(b, []byte(`"complete":false`)) {
		t.Fatalf("logs %d %s", status, b)
	}
	// A long poll wakes when a representation changes rather than waiting its timeout.
	poll := make(chan int, 1)
	go func() {
		status, _, _ := f.request(t, "GET", run.Links.Self+"?wait=3", "micah@example.com", nil, map[string]string{"If-None-Match": h.Get("ETag")})
		poll <- status
	}()
	if e = f.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "succeeded"}); e != nil {
		t.Fatal(e)
	}
	select {
	case status := <-poll:
		if status != 200 {
			t.Fatalf("long poll %d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not wake")
	}
	fin := runnerclient.LogFinish{Attempt: 1, FinalSeq: 1, TotalEntries: 1, Hash: hash(raw)}
	if _, e = f.c.FinishLogs(ctx, st.JobToken, fin); e != nil {
		t.Fatal("postfinish log drain", e)
	}
	if _, e = f.c.FinishLogs(ctx, st.JobToken, fin); e != nil {
		t.Fatal("repeat finish", e)
	}
	status, b, _ = f.request(t, "GET", run.Links.Logs+"?cursor="+encodeCursor(1), "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte(`"complete":true`)) {
		t.Fatalf("drain %d %s", status, b)
	}
	f.now.Add(901)
	if _, e = f.c.UploadLogs(ctx, st.JobToken, chunk); !errors.Is(e, runnerclient.ErrUnauthenticated) {
		t.Fatal("drain bearer outlived window")
	}
}
func TestConcurrentCreateClaimAndRecovery(t *testing.T) {
	f := newFixture(t)
	id := f.login(t)
	var wg sync.WaitGroup
	statuses := make(chan int, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _, _ := f.request(t, "POST", runsPath, "micah@example.com", createBody(), map[string]string{"Idempotency-Key": "concurrent"})
			statuses <- status
		}()
	}
	wg.Wait()
	close(statuses)
	created := 0
	for status := range statuses {
		if status == 201 {
			created++
		} else if status != 200 {
			t.Fatalf("concurrent create %d", status)
		}
	}
	if created != 1 {
		t.Fatalf("created %d runs", created)
	}
	claims := make(chan *runnerclient.Claim, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claim, e := f.c.Claim(context.Background(), id.access)
			if e != nil {
				t.Error(e)
			}
			claims <- claim
		}()
	}
	wg.Wait()
	close(claims)
	n := 0
	for claim := range claims {
		if claim != nil {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("claimed %d times", n)
	}
	// Simulate death after the WAL commit but before all individual files were replaced.
	f.s.mu.Lock()
	d := f.s.state.clone()
	for _, r := range d.Runs {
		r.Run.State = "cancelled"
		now := f.s.now()
		r.Run.FinishedAt = &now
		d.Jobs[r.JobID].State = "cancelled"
	}
	if e := atomicJSON(filepath.Join(f.cfg.StateDir, "transaction.json"), d); e != nil {
		t.Fatal(e)
	}
	f.s.mu.Unlock()
	recovered, e := loadState(f.cfg.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	if len(recovered.Runs) != 1 {
		t.Fatal("lost run")
	}
	for _, r := range recovered.Runs {
		if r.Run.State != "cancelled" {
			t.Fatal("WAL not replayed")
		}
	}
	if _, e = os.Stat(filepath.Join(f.cfg.StateDir, "transaction.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("WAL not cleared")
	}
}

// This driver calls the real runnerclient just as an executor would. No command
// or host fallback runs in this protocol integration test.
type protocolDriver struct {
	c    *runnerclient.Client
	mu   sync.Mutex
	busy bool
	done chan error
}

func (d *protocolDriver) Facts(context.Context) (manager.Facts, error) {
	return qualifiedFacts(), nil
}
func (d *protocolDriver) Capacity(context.Context) (manager.Capacity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.busy {
		return manager.Capacity{Max: 1, Running: 1}, nil
	}
	return manager.Capacity{Max: 1, Ready: []manager.SlotID{"test"}}, nil
}
func (d *protocolDriver) Provision(context.Context, int) error { return nil }
func (d *protocolDriver) Start(ctx context.Context, slot manager.SlotID, c runnerclient.Claim) (manager.Handle, error) {
	d.mu.Lock()
	d.busy = true
	d.mu.Unlock()
	st, e := d.c.Start(ctx, c.StartupToken, runnerclient.StartupAssignment{})
	if e == nil {
		_, e = d.c.Source(ctx, st.JobToken)
	}
	if e == nil {
		e = d.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "succeeded"})
	}
	d.done <- e
	return manager.Handle{Slot: slot, Job: c.JobID, Attempt: c.Attempt, Ref: strconv.FormatInt(c.JobID, 10)}, e
}
func (d *protocolDriver) Wait(context.Context, manager.Handle) (manager.Exit, error) {
	return manager.Exit{Reason: manager.ExitExited}, nil
}
func (d *protocolDriver) Teardown(context.Context, manager.Handle) error {
	d.mu.Lock()
	d.busy = false
	d.mu.Unlock()
	return nil
}
func (d *protocolDriver) Reap(context.Context, []manager.JobID) error { return nil }
func TestRealManagerAgainstPoolServer(t *testing.T) {
	f := newFixture(t)
	run := f.create(t)
	store := manager.Store{Dir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, e := manager.Enroll(ctx, f.c, store, f.ts.URL, "oyzu-runs", "enrollment", "manager", time.Now()); e != nil {
		t.Fatal(e)
	}
	driver := &protocolDriver{c: f.c, done: make(chan error, 1)}
	m, e := manager.Open(manager.Config{Client: f.c, Store: store, Driver: driver, PollInterval: 5 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	select {
	case e := <-driver.done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real manager did not claim")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("manager did not stop")
	}
	status, b, _ := f.request(t, "GET", run.Links.Result, "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte(`"state":"succeeded"`)) {
		t.Fatalf("real manager result %d %s", status, b)
	}
}
