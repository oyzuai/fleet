package kindrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

// TestMain lets the test binary act as a kind, behaving as OYZU_FAKE_KIND
// says.
func TestMain(m *testing.M) {
	if mode := os.Getenv("OYZU_FAKE_KIND"); mode != "" {
		fakeKind(mode)
		return
	}
	os.Exit(m.Run())
}

// fakeKind reads a request and behaves as mode says: ok answers at once,
// hang waits to be stopped, secrets reports what OYZU_SECRETS_DIR holds,
// garbage writes no valid result.
func fakeKind(mode string) {
	raw, _ := io.ReadAll(os.Stdin)
	req, err := kindprotocol.DecodeRequest(raw)
	if err != nil {
		os.Exit(3)
	}
	ev := func(body kindprotocol.EventBody, seq int64) {
		line, _ := json.Marshal(kindprotocol.Event{SchemaVersion: kindprotocol.SchemaVersion, Type: kindprotocol.TypeEvent,
			ExecutionID: req.ExecutionID, Operation: req.Operation, Sequence: seq, Time: time.Now().UTC(), Event: body})
		os.Stderr.Write(append(line, '\n'))
	}
	result := func(res kindprotocol.Result) {
		res.SchemaVersion, res.Type, res.Operation, res.ExecutionID = kindprotocol.SchemaVersion, kindprotocol.TypeResult, req.Operation, req.ExecutionID
		out, _ := json.Marshal(res)
		os.Stdout.Write(out)
	}
	pct := 50
	ev(kindprotocol.EventBody{Type: "progress", Percent: &pct, Message: "halfway"}, 0)
	os.Stderr.WriteString("a plain line\n")
	if req.Operation == kindprotocol.OpAbort {
		os.WriteFile(filepath.Join(os.Getenv("OYZU_KIND_STATE_DIR"), "aborted"), nil, 0o600)
		result(kindprotocol.Result{Outcome: kindprotocol.Succeeded})
		return
	}
	switch mode {
	case "hang":
		time.Sleep(time.Minute)
	case "garbage":
		os.Stdout.WriteString("not json")
		os.Exit(1)
	case "secrets":
		b, _ := os.ReadFile(filepath.Join(os.Getenv("OYZU_SECRETS_DIR"), "deploy_key"))
		ev(kindprotocol.EventBody{Type: "log", Level: "info", Message: "key=" + string(b)}, 1)
	case "connectors":
		reportConnectors(ev)
	case "ledger":
		// Counts its runs in its ledger, as the script kind records the
		// execution IDs it applied.
		path := filepath.Join(os.Getenv("OYZU_KIND_LEDGER_DIR"), "count")
		b, _ := os.ReadFile(path)
		os.WriteFile(path, append(b, 'x'), 0o600)
	}
	result(kindprotocol.Result{Outcome: kindprotocol.Succeeded, Observed: &kindprotocol.ObservedState{
		AsOf: time.Now().UTC(), Components: []kindprotocol.ObservedComponent{}}})
}

// fakeRuns is the runner API's kind job half.
type fakeRuns struct {
	cancel atomic.Bool
	mu     sync.Mutex
	events []runnerclient.KindEvent
	finish map[string]json.RawMessage
	// connectors is what job/kind/connectors answers.
	connectors runnerclient.KindConnectors
	// ledger is the ledger runs keeps; saves counts job/kind/ledger posts.
	ledger []byte
	saves  int
}

func (f *fakeRuns) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/runner/v1/") {
	case "job/kind/heartbeat":
		json.NewEncoder(w).Encode(runnerclient.KindBeat{Expires: time.Now().Add(time.Minute), Cancel: f.cancel.Load()})
	case "job/kind/events":
		var in struct{ Events []runnerclient.KindEvent }
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.events = append(f.events, in.Events...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "job/kind/secrets":
		json.NewEncoder(w).Encode(map[string]any{"secrets": []runnerclient.KindSecret{{Name: "deploy_key", Value: []byte("s3cret")}}})
	case "job/kind/connectors":
		json.NewEncoder(w).Encode(f.connectors)
	case "job/kind/ledger/fetch":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.ledger == nil {
			http.NotFound(w, r)
			return
		}
		w.Write(f.ledger)
	case "job/kind/ledger":
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.ledger, f.saves = b, f.saves+1
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "job/kind/finish":
		f.mu.Lock()
		json.NewDecoder(r.Body).Decode(&f.finish)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T, mode string, op kindprotocol.Operation, timeout, abort int, secrets []string) (*fakeRuns, Config, runnerclient.Job, string) {
	t.Helper()
	kinds := t.TempDir()
	if err := os.Symlink(os.Args[0], filepath.Join(kinds, "kind-fake")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OYZU_FAKE_KIND", mode)
	f := &fakeRuns{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	kind := kindprotocol.KindRef{Name: "fake", Version: "1.0.0"}
	request := kindprotocol.Request{SchemaVersion: kindprotocol.SchemaVersion, Type: kindprotocol.TypeRequest,
		Operation: op, ExecutionID: "e1", Kind: kind,
		TargetSettings: json.RawMessage(`{}`), Components: []kindprotocol.ComponentVersion{{Component: "web", Version: "1",
			Artifacts: []kindprotocol.Artifact{{Name: "b", Digest: "sha256:" + strings.Repeat("a", 64)}}}}}
	if op == kindprotocol.OpApply {
		request.ApprovedPlan = &kindprotocol.Plan{SchemaVersion: kindprotocol.SchemaVersion, Type: kindprotocol.TypePlan,
			Kind: kind, Summary: "Run it.", Changes: []kindprotocol.Change{}, RiskFlags: []kindprotocol.RiskFlag{}}
		if err := request.ApprovedPlan.Seal(); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := json.Marshal(request)
	job := runnerclient.Job{ID: 7, Attempt: 1, Kind: runnerclient.KindOperationJob, KindOperation: &runnerclient.KindOperation{
		RecordID: "r1", Operation: string(op), Request: req, TimeoutSeconds: timeout, AbortTimeoutSeconds: abort, Secrets: secrets}}
	job.KindOperation.Kind.Name, job.KindOperation.Kind.Version = "fake", "1.0.0"
	state := t.TempDir()
	cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), Token: "oyzu_kjob_x",
		HeartbeatEvery: 50 * time.Millisecond, KindsDir: kinds, StateDir: state, SecretsDir: t.TempDir(),
		StopGrace: 200 * time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return f, cfg, job, filepath.Join(state, "fake")
}

func TestResultAndEventsReachRuns(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var res kindprotocol.Result
	if err := json.Unmarshal(f.finish["result"], &res); err != nil || res.Outcome != kindprotocol.Succeeded {
		t.Fatalf("finish %s", f.finish)
	}
	// A batch may arrive twice (runs keeps the first); numbers have no gaps.
	var progress, plain bool
	seen := map[int]bool{}
	for _, e := range f.events {
		seen[e.N] = true
		progress = progress || e.Type == "progress" && *e.Percent == 50
		plain = plain || e.Type == "log" && e.Message == "a plain line"
	}
	for n := range len(seen) {
		if !seen[n] {
			t.Fatalf("event %d is missing from %+v", n, f.events)
		}
	}
	if !progress || !plain {
		t.Fatalf("events %+v", f.events)
	}
}

func TestSecretsAreFilesNotRequest(t *testing.T) {
	f, cfg, job, _ := setup(t, "secrets", kindprotocol.OpObserve, 30, 0, []string{"deploy_key"})
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range f.events {
		found = found || e.Message == "key=s3cret"
	}
	if !found {
		t.Fatalf("the kind did not read its secret file: %+v", f.events)
	}
	if left, _ := filepath.Glob(filepath.Join(cfg.SecretsDir, "*")); len(left) != 0 {
		t.Fatalf("secrets left behind: %v", left)
	}
}

func TestTimeoutStopsTheKind(t *testing.T) {
	f, cfg, job, _ := setup(t, "hang", kindprotocol.OpApply, 1, 0, nil)
	start := time.Now()
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the timeout did not stop the kind")
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Code != "timed-out" || !none.Started {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestCancelRunsAbort(t *testing.T) {
	f, cfg, job, state := setup(t, "hang", kindprotocol.OpApply, 60, 30, nil)
	f.cancel.Store(true)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "aborted")); err != nil {
		t.Fatal("the kind's abort operation did not run")
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Code != "cancelled" {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestCancelWithoutAbortStopsTheKind(t *testing.T) {
	f, cfg, job, state := setup(t, "hang", kindprotocol.OpApply, 60, 0, nil)
	f.cancel.Store(true)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "aborted")); err == nil {
		t.Fatal("abort ran for a kind without one")
	}
	if !strings.Contains(string(f.finish["no_result"]), `"cancelled"`) {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestNoValidResult(t *testing.T) {
	f, cfg, job, _ := setup(t, "garbage", kindprotocol.OpApply, 30, 0, nil)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Code != "crashed" {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestUnpinnedImageNeverStarts(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpApply, 30, 0, nil)
	job.KindOperation.Image = "ghcr.io/acme/kind:latest"
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Code != "kind-not-started" || none.Started {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestLedgerFollowsTheTargetAcrossHosts(t *testing.T) {
	f, cfg, job, _ := setup(t, "ledger", kindprotocol.OpObserve, 30, 0, nil)
	job.KindOperation.Ledger = true
	// Two hosts: each run has its own state directory, and only runs
	// carries the ledger from one to the other.
	for host := range 2 {
		cfg.StateDir = t.TempDir()
		if err := Run(context.Background(), cfg, job); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(f.finish["result"]), `"succeeded"`) {
			t.Fatalf("host %d: finish %s", host, f.finish)
		}
	}
	dir := t.TempDir()
	if err := untarFlat(f.ledger, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "count")); string(b) != "xx" || f.saves != 2 {
		t.Fatalf("ledger %q after %d saves; want both runs counted", b, f.saves)
	}
	if left, _ := filepath.Glob(filepath.Join(cfg.SecretsDir, "*")); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
}

func TestUnchangedLedgerIsNotSent(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	job.KindOperation.Ledger = true
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if f.saves != 0 {
		t.Fatalf("an unchanged ledger was sent %d times", f.saves)
	}
}

func TestImageKindGetsLedgerAndNetwork(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpApply, 30, 0, nil)
	job.KindOperation.Ledger = true
	job.KindOperation.Image = "registry.local/kinds/fake@sha256:" + strings.Repeat("b", 64)
	args := filepath.Join(t.TempDir(), "args")
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\necho \"$@\" >> "+args+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Docker, cfg.DockerNetwork = docker, "host"
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(args)
	run := strings.SplitN(string(b), "\n", 2)[0]
	for _, want := range []string{"--network host", fmt.Sprintf("--user %d:%d", os.Getuid(), os.Getgid()), "OYZU_KIND_LEDGER_DIR=" + ContainerLedgerDir, ":" + ContainerLedgerDir + " ",
		" " + job.KindOperation.Image} {
		if !strings.Contains(run, want) {
			t.Fatalf("docker %s lacks %q", run, want)
		}
	}
	if !strings.Contains(string(f.finish["no_result"]), "no-result") {
		t.Fatalf("finish %s", f.finish)
	}
}
