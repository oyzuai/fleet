package poolserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

type fakeStageCheck struct {
	ID         int64  `json:"id"`
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
	Output     checkOutput
	Batches    []int
}

type fakeChecksAPI struct {
	mu                 sync.Mutex
	checks             map[int64]*fakeStageCheck
	calls              int
	creates            int
	patches            int
	missing            bool
	fail               bool
	lostCreate         bool
	failPatch          int
	excess             bool
	wrongRepo          bool
	expired            bool
	tokenMints         int
	unauthorized       int
	unauthorizedMethod string
	blocked            <-chan struct{}
	entered            chan struct{}
}

func attachChecksAPI(t *testing.T, f *fixture) *fakeChecksAPI {
	t.Helper()
	fake := &fakeChecksAPI{checks: map[int64]*fakeStageCheck{}}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		blocked, entered := fake.blocked, fake.entered
		fake.mu.Unlock()
		if blocked != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-blocked:
			case <-r.Context().Done():
				return
			}
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.calls++
		if strings.Contains(r.URL.Path, "check-runs") && r.Method == fake.unauthorizedMethod && fake.unauthorized > 0 {
			fake.unauthorized--
			w.WriteHeader(401)
			return
		}
		if fake.fail {
			w.WriteHeader(503)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/installation":
			if fake.missing {
				w.WriteHeader(404)
				return
			}
			respond(w, 200, map[string]int{"id": 42})
		case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
			fake.tokenMints++
			var in struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			if decodeJSON(r.Body, &in) != nil || len(in.Repositories) != 1 || in.Repositories[0] != "fleet" || len(in.Permissions) != 1 || in.Permissions["checks"] != "write" {
				t.Error("check credential is not restricted to one repository and checks:write")
			}
			permissions := map[string]string{"checks": "write", "metadata": "read"}
			if fake.excess {
				permissions["contents"] = "read"
			}
			repo := "oyzuai/fleet"
			if fake.wrongRepo {
				repo = "oyzuai/other"
			}
			expires := time.Unix(f.now.Load(), 0).Add(time.Hour)
			if fake.expired {
				expires = time.Unix(f.now.Load(), 0)
			}
			respond(w, 201, map[string]any{"token": "private-check-token", "expires_at": expires, "permissions": permissions, "repositories": []any{map[string]string{"full_name": repo}}})
		case r.Method == "GET" && r.URL.Path == "/repos/oyzuai/fleet/commits/"+testSHA+"/check-runs":
			if bearer(r) != "private-check-token" || r.URL.Query().Get("filter") != "all" {
				t.Error("check lookup lacks restricted token or all-attempt filter")
			}
			checks := []*fakeStageCheck{}
			for _, c := range fake.checks {
				if c.Name == r.URL.Query().Get("check_name") {
					checks = append(checks, c)
				}
			}
			respond(w, 200, map[string]any{"check_runs": checks})
		case r.Method == "POST" && r.URL.Path == "/repos/oyzuai/fleet/check-runs":
			var in struct {
				Name       string `json:"name"`
				HeadSHA    string `json:"head_sha"`
				ExternalID string `json:"external_id"`
				Status     string `json:"status"`
			}
			if decodeJSON(r.Body, &in) != nil || bearer(r) != "private-check-token" || in.HeadSHA != testSHA || in.Status != "in_progress" || in.ExternalID == "" {
				t.Error("invalid check creation (or unexpected details_url)")
				w.WriteHeader(400)
				return
			}
			fake.creates++
			id := int64(fake.creates)
			fake.checks[id] = &fakeStageCheck{ID: id, ExternalID: in.ExternalID, Name: in.Name, HeadSHA: in.HeadSHA, Status: in.Status}
			if fake.lostCreate {
				fake.lostCreate = false
				// GitHub committed the create, but its response was incomplete.
				w.WriteHeader(201)
				_, _ = w.Write([]byte("{"))
				return
			}
			respond(w, 201, map[string]int64{"id": id})
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/repos/oyzuai/fleet/check-runs/"):
			fake.patches++
			if fake.failPatch == fake.patches {
				w.WriteHeader(503)
				return
			}
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/oyzuai/fleet/check-runs/"), 10, 64)
			c := fake.checks[id]
			var in struct {
				Status     string      `json:"status"`
				Conclusion string      `json:"conclusion,omitempty"`
				Output     checkOutput `json:"output"`
			}
			if c == nil || decodeJSON(r.Body, &in) != nil || bearer(r) != "private-check-token" || len(in.Output.Annotations) > 50 {
				t.Error("invalid check update")
				w.WriteHeader(400)
				return
			}
			c.Status, c.Conclusion = in.Status, in.Conclusion
			c.Output.Title, c.Output.Summary = in.Output.Title, in.Output.Summary
			if len(in.Output.Annotations) > 0 {
				c.Batches = append(c.Batches, len(in.Output.Annotations))
				c.Output.Annotations = append(c.Output.Annotations, in.Output.Annotations...)
			}
			respond(w, 200, map[string]int64{"id": id})
		default:
			t.Errorf("unexpected GitHub request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(api.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app, err := newGitHubApp(f.cfg, Options{AppKey: key, HTTPClient: api.Client(), Now: func() time.Time { return time.Unix(f.now.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	app.base = api.URL
	f.s.checks = app
	return fake
}

func (api *fakeChecksAPI) snapshot() (map[string]fakeStageCheck, int, int, int) {
	api.mu.Lock()
	defer api.mu.Unlock()
	out := map[string]fakeStageCheck{}
	for _, c := range api.checks {
		copy := *c
		copy.Batches = append([]int(nil), c.Batches...)
		copy.Output.Annotations = append([]checkAnnotation(nil), c.Output.Annotations...)
		out[c.Name] = copy
	}
	return out, api.calls, api.creates, api.patches
}

func stageChunk(t *testing.T, seq, first int64, entries ...runnerclient.LogEntry) runnerclient.LogChunk {
	t.Helper()
	var raw, compressed bytes.Buffer
	for i, entry := range entries {
		entry.Sequence = first + int64(i)
		entry.Time = time.Now().UTC()
		entry.Stream = "system"
		if err := json.NewEncoder(&raw).Encode(entry); err != nil {
			t.Fatal(err)
		}
	}
	z := gzip.NewWriter(&compressed)
	if _, err := z.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return runnerclient.LogChunk{Attempt: 1, Seq: seq, First: first, Last: first + int64(len(entries)) - 1, Entries: int64(len(entries)), Data: compressed.Bytes(), Hash: hash(raw.Bytes())}
}

func uploadStageChunk(t *testing.T, f *fixture, token string, chunk runnerclient.LogChunk) {
	t.Helper()
	if _, err := f.c.UploadLogs(context.Background(), token, chunk); err != nil {
		t.Fatal(err)
	}
	f.s.flushChecks(context.Background())
}

func TestStageChecksStartFinishAndChunkRetry(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	start := stageChunk(t, 1, 1,
		runnerclient.LogEntry{Scope: "cli:test"},
		runnerclient.LogEntry{Scope: "cli:build"},
		runnerclient.LogEntry{Scope: "cli"},
		runnerclient.LogEntry{Scope: "cli:test:nested"})
	uploadStageChunk(t, f, st.JobToken, start)
	checks, _, creates, _ := api.snapshot()
	if creates != 2 || checks["oyzu / cli / test"].Status != "in_progress" || checks["oyzu / cli / build"].Status != "in_progress" {
		t.Fatalf("stage starts: %#v", checks)
	}
	end := stageChunk(t, 2, 5,
		runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "failed"}},
		runnerclient.LogEntry{Scope: "cli:build", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}})
	uploadStageChunk(t, f, st.JobToken, end)
	checks, _, _, patches := api.snapshot()
	if checks["oyzu / cli / test"].Conclusion != "failure" || checks["oyzu / cli / build"].Conclusion != "success" || checks["oyzu / cli / test"].Status != "completed" {
		t.Fatalf("stage results: %#v", checks)
	}
	uploadStageChunk(t, f, st.JobToken, end)
	_, _, retriedCreates, retriedPatches := api.snapshot()
	if retriedCreates != creates || retriedPatches != patches {
		t.Fatalf("identical chunk changed published checks: creates %d patches %d", retriedCreates, retriedPatches)
	}
	source, err := f.c.Source(context.Background(), st.JobToken)
	if err != nil || source.Token != "test-source-only" {
		t.Fatalf("check token reached source route: %#v %v", source, err)
	}
}

func TestStageCheckConclusions(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	want := map[string]string{"success": "success", "failed": "failure", "skipped": "skipped", "cancelled": "cancelled", "other": "neutral", "": "neutral"}
	var entries []runnerclient.LogEntry
	for status := range want {
		entries = append(entries, runnerclient.LogEntry{Scope: "cli:stage-" + status, Event: &runnerclient.LogEvent{Kind: "finished", Status: status}})
	}
	uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, entries...))
	checks, _, creates, _ := api.snapshot()
	if creates != len(want) {
		t.Fatalf("created %d checks", creates)
	}
	for status, conclusion := range want {
		c := checks["oyzu / cli / stage-"+status]
		if c.Status != "completed" || c.Conclusion != conclusion {
			t.Errorf("status %q: %#v", status, c)
		}
	}
}

func TestStageCheckAnnotationsBatchAndPathlessSummary(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "failed"}}))
	failures := []runnerclient.TestFailure{{Scope: "cli:test", Name: "without location", Message: "pathless failure"}, {Scope: "other:test", Name: "other scope", Message: "must not leak"}}
	for i := 0; i < 121; i++ {
		failures = append(failures, runnerclient.TestFailure{Scope: "cli:test", Name: fmt.Sprintf("test-%d", i), Classname: "suite", Path: "src/example_test.go", Line: i + 1, Message: "expected true"})
	}
	if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "failed", TestFailures: failures}); err != nil {
		t.Fatal(err)
	}
	f.s.flushChecks(context.Background())
	checks, _, _, _ := api.snapshot()
	c := checks["oyzu / cli / test"]
	if fmt.Sprint(c.Batches) != "[50 50 21]" || len(c.Output.Annotations) != 121 || !strings.Contains(c.Output.Summary, "pathless failure") || strings.Contains(c.Output.Summary, "must not leak") {
		t.Fatalf("annotations/summary: %#v", c)
	}
	for i, a := range c.Output.Annotations {
		if a.Path != "src/example_test.go" || a.StartLine != i+1 || a.EndLine != i+1 || a.AnnotationLevel != "failure" || a.Title != fmt.Sprintf("suite: test-%d", i) || a.Message != "expected true" {
			t.Errorf("annotation %d: %#v", i, a)
		}
	}
}

func TestStageChecksFinishOpenScopesAndLateLogs(t *testing.T) {
	for _, state := range []string{"succeeded", "failed", "cancelled", "timed_out"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			api := attachChecksAPI(t, f)
			f.create(t)
			st := f.start(t, f.login(t).access)
			uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"}))
			if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: state}); err != nil {
				t.Fatal(err)
			}
			f.s.flushChecks(context.Background())
			checks, _, _, _ := api.snapshot()
			c := checks["oyzu / cli / test"]
			want := "failure"
			if state == "cancelled" {
				want = "cancelled"
			}
			if c.Status != "completed" || c.Conclusion != want || (want == "failure" && c.Output.Summary != "stage did not report a result") {
				t.Fatalf("open stage not closed: %#v", c)
			}
			uploadStageChunk(t, f, st.JobToken, stageChunk(t, 2, 2, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}}))
			checks, _, creates, _ := api.snapshot()
			if creates != 1 || checks["oyzu / cli / test"].Conclusion != "success" {
				t.Fatalf("drained result did not update original check: %#v", checks)
			}
		})
	}
}

func TestStageChecksSurviveRestartAndAmbiguousCreate(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	run := f.create(t)
	st := f.start(t, f.login(t).access)
	api.mu.Lock()
	api.lostCreate = true
	api.mu.Unlock()
	chunk := stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}})
	uploadStageChunk(t, f, st.JobToken, chunk)
	f.s.mu.Lock()
	if f.s.state.Runs[run.ID].Checks["cli:test"].ID != 0 {
		t.Error("incomplete create response unexpectedly persisted an ID")
	}
	f.s.mu.Unlock()
	reopened, err := New(f.cfg, Options{Source: testSource{exists: true}, Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	reopened.checks = f.s.checks
	reopened.retryChecks()
	reopened.flushChecks(context.Background())
	checks, _, creates, _ := api.snapshot()
	if creates != 1 || checks["oyzu / cli / test"].Conclusion != "success" {
		t.Fatalf("restart duplicated or lost check: %#v", checks)
	}
	if reopened.state.Runs[run.ID].Checks["cli:test"].ID != 1 {
		t.Fatal("recovered check ID was not persisted")
	}
	// Open the actual persisted state again; no lookup/create/update is needed.
	again, err := New(f.cfg, Options{Source: testSource{exists: true}, Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	again.checks = f.s.checks
	_, calls, _, _ := api.snapshot()
	again.retryChecks()
	again.flushChecks(context.Background())
	_, after, _, _ := api.snapshot()
	if calls != after {
		t.Fatalf("published state was redelivered after restart: %d -> %d", calls, after)
	}
}

func TestStageChecksRetryChunkUsesPersistedID(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	run := f.create(t)
	st := f.start(t, f.login(t).access)
	api.mu.Lock()
	api.failPatch = 1
	api.mu.Unlock()
	chunk := stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "failed"}})
	uploadStageChunk(t, f, st.JobToken, chunk)
	f.s.mu.Lock()
	c := *f.s.state.Runs[run.ID].Checks["cli:test"]
	f.s.mu.Unlock()
	if c.ID != 1 || c.Published == c.Revision {
		t.Fatalf("failed update did not retain pending check ID: %#v", c)
	}
	uploadStageChunk(t, f, st.JobToken, chunk)
	checks, _, creates, _ := api.snapshot()
	if creates != 1 || checks["oyzu / cli / test"].Conclusion != "failure" {
		t.Fatalf("chunk retry duplicated or lost check: %#v", checks)
	}
}

func TestStageChecksLeaseExpiryClosesOpenScope(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"}))
	f.now.Add(121)
	f.s.mu.Lock()
	err := f.s.expire()
	f.s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.s.retryChecks()
	f.s.flushChecks(context.Background())
	checks, _, _, _ := api.snapshot()
	c := checks["oyzu / cli / test"]
	if c.Conclusion != "failure" || c.Output.Summary != "stage did not report a result" {
		t.Fatalf("expired executor left check open: %#v", c)
	}
}

func TestStageCheckPartialAnnotationRetry(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	run := f.create(t)
	st := f.start(t, f.login(t).access)
	uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"}))
	api.mu.Lock()
	api.failPatch = api.patches + 2 // Accept 50, then fail the next batch.
	api.mu.Unlock()
	failures := make([]runnerclient.TestFailure, 101)
	for i := range failures {
		failures[i] = runnerclient.TestFailure{Scope: "cli:test", Name: "test", Path: "test.js", Message: "failure"}
	}
	if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "failed", TestFailures: failures}); err != nil {
		t.Fatal(err)
	}
	f.s.flushChecks(context.Background())
	reopened, err := New(f.cfg, Options{Source: testSource{exists: true}, Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	reopened.checks = f.s.checks
	reopened.retryChecks()
	reopened.flushChecks(context.Background())
	checks, _, creates, _ := api.snapshot()
	c := checks["oyzu / cli / test"]
	if creates != 1 || fmt.Sprint(c.Batches) != "[50 50 1]" || len(c.Output.Annotations) != 101 || c.Output.Annotations[0].StartLine != 1 {
		t.Fatalf("partial retry duplicated or dropped batches: %#v", c)
	}
	persisted := reopened.state.Runs[run.ID].Checks["cli:test"]
	if persisted.AnnotationsSent != 101 || persisted.Published != persisted.Revision {
		t.Fatalf("annotation progress not persisted: %#v", persisted)
	}
}

func TestStageChecksSkipSnapshotsAndUnavailableInstallation(t *testing.T) {
	for _, snapshot := range []bool{true, false} {
		t.Run(fmt.Sprintf("snapshot=%t", snapshot), func(t *testing.T) {
			f := newFixture(t)
			api := attachChecksAPI(t, f)
			if snapshot {
				data := []byte("snapshot fixture")
				digest := "sha256:" + hash(data)
				if status := uploadSource(t, f, digest, data); status != 201 {
					t.Fatalf("upload snapshot: %d", status)
				}
				body := createBody()
				body.Commit = ""
				body.Source = &SnapshotSource{Kind: "snapshot", Digest: digest, BaseCommit: testSHA}
				if status, b, _ := f.request(t, "POST", runsPath, "micah@example.com", body, nil); status != 201 {
					t.Fatalf("create snapshot: %d %s", status, b)
				}
			} else {
				f.create(t)
				api.mu.Lock()
				api.missing = true
				api.mu.Unlock()
			}
			st := f.start(t, f.login(t).access)
			uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"}))
			if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "succeeded"}); err != nil {
				t.Fatal(err)
			}
			f.s.flushChecks(context.Background())
			_, calls, creates, _ := api.snapshot()
			if creates != 0 || (snapshot && calls != 0) {
				t.Fatalf("checks posted for excluded source: calls %d creates %d", calls, creates)
			}
		})
	}
}

func TestGitHubCheckErrorsDoNotFailRunnerRequests(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	run := f.create(t)
	st := f.start(t, f.login(t).access)
	api.mu.Lock()
	api.fail = true
	api.mu.Unlock()
	chunk := stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}})
	uploadStageChunk(t, f, st.JobToken, chunk)
	uploadStageChunk(t, f, st.JobToken, chunk)
	if err := f.c.Finish(context.Background(), st.JobToken, runnerclient.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	f.s.flushChecks(context.Background())
	status, b, _ := f.request(t, "GET", run.Links.Self, "micah@example.com", nil, nil)
	if status != 200 || !bytes.Contains(b, []byte(`"state":"succeeded"`)) || bytes.Contains(b, []byte("private-check-token")) {
		t.Fatalf("GitHub error changed run or leaked credential: %d %s", status, b)
	}
	api.mu.Lock()
	api.fail = false
	api.mu.Unlock()
	f.s.retryChecks()
	f.s.flushChecks(context.Background())
	checks, _, creates, _ := api.snapshot()
	if creates != 1 || checks["oyzu / cli / test"].Conclusion != "success" {
		t.Fatalf("GitHub recovery lost result: %#v", checks)
	}
}

func TestCheckTokenRejectsExcessScopeAndExpiredCredentials(t *testing.T) {
	for _, kind := range []string{"excess", "wrong repository", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			api := attachChecksAPI(t, f)
			api.mu.Lock()
			api.excess = kind == "excess"
			api.wrongRepo = kind == "wrong repository"
			api.expired = kind == "expired"
			api.mu.Unlock()
			if token, err := f.s.checks.checkToken(context.Background(), "oyzuai/fleet"); err == nil || token != "" {
				t.Fatal("unsafe check credential accepted")
			}
		})
	}
}

func TestStageCheckFailureBoundsAndSummaryLimit(t *testing.T) {
	valid := runnerclient.TestFailure{Scope: "cli:test", Name: "test", Message: strings.Repeat("x", 1024)}
	if !validTestFailures([]runnerclient.TestFailure{valid}) {
		t.Fatal("maximum message rejected")
	}
	oversized := valid
	oversized.Message += "x"
	unsafe := valid
	unsafe.Path = "../outside.js"
	negativeLine := valid
	negativeLine.Line = -1
	for _, failures := range [][]runnerclient.TestFailure{{oversized}, {unsafe}, {negativeLine}, make([]runnerclient.TestFailure, 201)} {
		if validTestFailures(failures) {
			t.Fatal("invalid test failures accepted")
		}
	}
	rr := &runRecord{TestFailures: make([]runnerclient.TestFailure, 200)}
	for i := range rr.TestFailures {
		rr.TestFailures[i] = valid
	}
	out, annotations := checkText(rr, "cli:test", &stageCheck{Conclusion: "failure"})
	if len(out.Summary) > 60<<10 || !strings.HasSuffix(out.Summary, "[truncated]") || len(annotations) != 0 {
		t.Fatal("pathless summary was not bounded")
	}
}

func startCheckReaper(t *testing.T, s *Server) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Reap(ctx); err != context.Canceled {
			t.Errorf("Reap returned %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("check publisher did not stop with Reap")
		}
	})
	return cancel, done
}

func TestStageChecksBlockedGitHubDoesNotDelayRunnerRequests(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseGitHub := func() { releaseOnce.Do(func() { close(release) }) }
	entered := make(chan struct{}, 1)
	api.mu.Lock()
	api.blocked, api.entered = release, entered
	api.mu.Unlock()
	startCheckReaper(t, f.s)
	// Release before waiting for reaper cleanup, including on assertion failure.
	t.Cleanup(releaseGitHub)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	chunk := stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"})
	if _, err := f.c.UploadLogs(ctx, st.JobToken, chunk); err != nil {
		t.Fatalf("initial log upload waited for GitHub: %v", err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("publisher did not reach GitHub")
	}
	if _, err := f.c.UploadLogs(ctx, st.JobToken, chunk); err != nil {
		t.Fatalf("duplicate log upload waited for GitHub: %v", err)
	}
	end := stageChunk(t, 2, 2, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}})
	if _, err := f.c.UploadLogs(ctx, st.JobToken, end); err != nil {
		t.Fatalf("new log upload waited for GitHub: %v", err)
	}
	if err := f.c.Finish(ctx, st.JobToken, runnerclient.Outcome{State: "succeeded"}); err != nil {
		t.Fatalf("job finish waited for GitHub: %v", err)
	}
	// The safety-net scan also only enqueues, even while the publisher is stuck.
	f.now.Add(30)
	f.s.retryChecks()
	releaseGitHub()
	f.s.flushChecks(context.Background())
	checks, _, creates, _ := api.snapshot()
	if creates != 1 || checks["oyzu / cli / test"].Conclusion != "success" {
		t.Fatalf("queued checks did not publish after GitHub resumed: %#v", checks)
	}
}

func TestStageChecksReapCancellationStopsBlockedPublisher(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	entered := make(chan struct{}, 1)
	api.mu.Lock()
	api.blocked, api.entered = make(chan struct{}), entered
	api.mu.Unlock()
	cancel, done := startCheckReaper(t, f.s)
	if _, err := f.c.UploadLogs(context.Background(), st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test"})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not reach GitHub")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Reap did not cancel and join the blocked publisher")
	}
}

func TestStageChecksQueueCoalescesAndReusesToken(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	f.create(t)
	st := f.start(t, f.login(t).access)
	for i := int64(1); i <= 4; i++ {
		chunk := stageChunk(t, i, i, runnerclient.LogEntry{Scope: "cli:test"})
		if _, err := f.c.UploadLogs(context.Background(), st.JobToken, chunk); err != nil {
			t.Fatal(err)
		}
	}
	f.s.mu.Lock()
	dirty := len(f.s.dirtyChecks)
	f.s.mu.Unlock()
	_, calls, _, _ := api.snapshot()
	if dirty != 1 || calls != 0 {
		t.Fatalf("queued chunks: dirty runs %d, GitHub calls %d", dirty, calls)
	}
	f.s.flushChecks(context.Background())
	_, _, creates, patches := api.snapshot()
	if creates != 1 || patches != 1 {
		t.Fatalf("coalesced chunks: creates %d patches %d", creates, patches)
	}
	for i := int64(5); i <= 7; i++ {
		uploadStageChunk(t, f, st.JobToken, stageChunk(t, i, i, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}}))
	}
	api.mu.Lock()
	mints := api.tokenMints
	api.mu.Unlock()
	if mints != 1 {
		t.Fatalf("several log chunks minted %d check credentials", mints)
	}
}

func TestStageCheckTokenRefreshesBeforeExpiry(t *testing.T) {
	f := newFixture(t)
	api := attachChecksAPI(t, f)
	for _, advance := range []int64{0, 55*60 - 1, 1, 60 * 60} {
		f.now.Add(advance)
		if _, err := f.s.checks.checkToken(context.Background(), "oyzuai/fleet"); err != nil {
			t.Fatal(err)
		}
	}
	api.mu.Lock()
	mints := api.tokenMints
	api.mu.Unlock()
	if mints != 3 {
		t.Fatalf("expected initial, pre-expiry and expired refresh; got %d", mints)
	}
}

func TestStageCheckUnauthorizedRefreshIsBounded(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PATCH"} {
		for _, rejections := range []int{1, 3} {
			t.Run(fmt.Sprintf("%s/%d", method, rejections), func(t *testing.T) {
				f := newFixture(t)
				api := attachChecksAPI(t, f)
				f.create(t)
				st := f.start(t, f.login(t).access)
				api.mu.Lock()
				api.unauthorizedMethod, api.unauthorized = method, rejections
				api.mu.Unlock()
				uploadStageChunk(t, f, st.JobToken, stageChunk(t, 1, 1, runnerclient.LogEntry{Scope: "cli:test", Event: &runnerclient.LogEvent{Kind: "finished", Status: "success"}}))
				checks, _, _, _ := api.snapshot()
				api.mu.Lock()
				mints, remaining := api.tokenMints, api.unauthorized
				api.mu.Unlock()
				if mints != 2 || remaining != max(0, rejections-2) {
					t.Fatalf("401 retry unbounded: mints %d remaining rejections %d", mints, remaining)
				}
				if rejections == 1 && checks["oyzu / cli / test"].Conclusion != "success" {
					t.Fatalf("refresh did not recover check delivery: %#v", checks)
				}
				if rejections > 1 && checks["oyzu / cli / test"].Conclusion != "" {
					t.Fatalf("repeated 401 unexpectedly completed: %#v", checks)
				}
			})
		}
	}
}

func TestRecordCheckDeliveryIgnoresRemovedRunOrScope(t *testing.T) {
	f := newFixture(t)
	run := f.create(t)
	for _, id := range []string{run.ID, "removed-run"} {
		if err := f.s.recordCheckDelivery(id, "removed:scope", &stageCheck{ID: 42}); err != nil {
			t.Fatal(err)
		}
	}
}
