package kindrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

func useServer(t *testing.T, cfg *Config, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg.Client = runnerclient.New(srv.URL, srv.Client())
}

func TestMaskingInvalidJSONReportsDroppedEvent(t *testing.T) {
	f, cfg, _, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	u := newUploader(cfg.Client, cfg.Token, cfg.Log)
	// A numeric credential can match an unquoted JSON number.
	u.mask.Add("123456")
	percent := 123456
	e := runnerclient.KindEvent{Type: "progress", Percent: &percent}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	u.add(e)
	if len(u.pending) != 0 || u.dropped != 1 || u.droppedBytes != len(raw) {
		t.Fatalf("pending=%d dropped=%d bytes=%d", len(u.pending), u.dropped, u.droppedBytes)
	}
	u.flush(context.Background())
	want := fmt.Sprintf("dropped 1 events/%d bytes", len(raw))
	if len(f.events) != 1 || !strings.Contains(f.events[0].Message, want) || strings.Contains(f.events[0].Message, "123456") {
		t.Fatalf("loss marker: %+v", f.events)
	}
	if u.dropped != 0 || u.droppedBytes != 0 {
		t.Fatal("reported loss was not cleared")
	}
}

func TestImageWithoutOwnerHasOnlyJobLabels(t *testing.T) {
	_, cfg, job, _ := setup(t, "docker", kindprotocol.OpObserve, 30, 0, nil)
	cfg.Docker = installFake(t, t.TempDir(), "docker")
	args := filepath.Join(t.TempDir(), "args")
	t.Setenv("OYZU_DOCKER_ARGS", args)
	job.KindOperation.Image = "registry/kind@sha256:" + strings.Repeat("b", 64)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--label oyzu.kind.job=7", "--label oyzu.kind.attempt=1"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "oyzu.kind.runner=") || strings.Contains(string(raw), "oyzu.kind.manager=") {
		t.Fatalf("owner labels without owner: %s", raw)
	}
}

func TestImagePullUsesOperationBudget(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		want    time.Duration
	}{{20, 20 * time.Second}, {300, 5 * time.Minute}, {900, 10 * time.Minute}} {
		r := &run{op: &runnerclient.KindOperation{TimeoutSeconds: tc.seconds, AbortTimeoutSeconds: 45}}
		if got := r.imagePullTimeout(""); got != tc.want {
			t.Errorf("%d seconds: got %s, want %s", tc.seconds, got, tc.want)
		}
		if got := r.imagePullTimeout("abort"); got != 45*time.Second {
			t.Errorf("abort got %s", got)
		}
	}
}

func TestImagePullStopsOnCancelShutdownAndLeaseLoss(t *testing.T) {
	for _, cause := range []error{nil, context.Canceled, ErrLost} {
		t.Run(fmt.Sprint(cause), func(t *testing.T) {
			f, cfg, job, _ := setup(t, "docker", kindprotocol.OpObserve, 600, 0, nil)
			cfg.Docker = installFake(t, t.TempDir(), "docker")
			job.KindOperation.Image = "registry/kind@sha256:" + strings.Repeat("b", 64)
			args := filepath.Join(t.TempDir(), "args")
			t.Setenv("OYZU_DOCKER_ARGS", args)
			t.Setenv("OYZU_DOCKER_MISSING", "1")
			t.Setenv("OYZU_DOCKER_DELAY_COMMAND", "pull")
			t.Setenv("OYZU_DOCKER_DELAY", "1m")
			ctx, cancel := context.WithCancelCause(context.Background())
			done := make(chan struct{})
			var runErr error
			go func() {
				runErr = Run(ctx, cfg, job)
				close(done)
			}()
			defer func() {
				cancel(nil)
				<-done
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				raw, _ := os.ReadFile(args)
				if strings.Contains(string(raw), "pull ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("pull never started")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if cause == nil {
				f.cancel.Store(true)
			} else {
				cancel(cause)
			}
			select {
			case <-done:
				if cause == ErrLost && !errors.Is(runErr, ErrLost) || cause != ErrLost && runErr != nil {
					t.Fatalf("Run: %v", runErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("pull ignored cancellation")
			}
		})
	}
}

func TestContainerRemovalCanExceedDrainTimeout(t *testing.T) {
	_, cfg, job, _ := setup(t, "docker", kindprotocol.OpObserve, 30, 0, nil)
	cfg.Docker = installFake(t, t.TempDir(), "docker")
	job.KindOperation.Image = "registry/kind@sha256:" + strings.Repeat("b", 64)
	completed := filepath.Join(t.TempDir(), "removed")
	t.Setenv("OYZU_DOCKER_DELAY_COMMAND", "rm")
	t.Setenv("OYZU_DOCKER_DELAY", "3s")
	t.Setenv("OYZU_DOCKER_COMPLETED", completed)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(completed); err != nil {
		t.Fatal("container removal was cut short:", err)
	}
}

func TestStalledEventsStillFinishesWithRetry(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	var finishes atomic.Int32
	useServer(t, &cfg, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/events"):
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		case strings.HasSuffix(r.URL.Path, "/finish"):
			if finishes.Add(1) == 1 {
				http.Error(w, "retry", 503)
				return
			}
		}
		f.ServeHTTP(w, r)
	})
	start := time.Now()
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 8*time.Second || len(f.finish["result"]) == 0 || finishes.Load() != 2 {
		t.Fatalf("finish=%s attempts=%d elapsed=%s", f.finish, finishes.Load(), time.Since(start))
	}
}

func TestOversizedStderrDrainsAndKeepsLaterEvents(t *testing.T) {
	f, cfg, job, _ := setup(t, "long-line", kindprotocol.OpObserve, 3, 0, nil)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var later, dropped bool
	for _, e := range f.events {
		later = later || e.Message == "after long line"
		dropped = dropped || strings.Contains(e.Message, "oversized stderr")
	}
	if !later || !dropped || len(f.finish["result"]) == 0 {
		t.Fatalf("finish=%s later=%v dropped=%v", f.finish, later, dropped)
	}
}

func TestObservedEventRetainsState(t *testing.T) {
	f, cfg, job, _ := setup(t, "observed", kindprotocol.OpObserve, 30, 0, nil)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.events {
		if e.Type == "observed" {
			if e.Observed == nil || len(e.Observed.Components) != 1 || e.Observed.Components[0].Version != "v2" {
				t.Fatalf("%+v", e)
			}
			raw, _ := json.Marshal(e)
			if !strings.Contains(string(raw), "\"observed\":{") {
				t.Fatalf("%s", raw)
			}
			return
		}
	}
	t.Fatal("no observed event")
}

func TestVerificationAbortPassesSchema(t *testing.T) {
	f, cfg, job, state := setup(t, "hang", kindprotocol.OpObserve, 30, 10, nil)
	raw, err := os.ReadFile("../kindprotocol/testdata/examples/request.verify.json")
	if err != nil {
		t.Fatal(err)
	}
	req, err := kindprotocol.DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	req.Kind.Name = "fake"
	job.KindOperation.Request, _ = json.Marshal(req)
	job.KindOperation.Operation = string(req.Operation)
	f.cancel.Store(true)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	// The fake kind only writes this marker after DecodeRequest succeeds.
	if _, err := os.Stat(filepath.Join(state, "aborted")); err != nil {
		t.Fatal("abort did not pass DecodeRequest:", err)
	}
}

func TestImageFailuresAreNotStarted(t *testing.T) {
	for _, fail := range []string{"pull", "run"} {
		t.Run(fail, func(t *testing.T) {
			f, cfg, job, _ := setup(t, "docker", kindprotocol.OpObserve, 30, 0, nil)
			cfg.Docker = installFake(t, t.TempDir(), "docker")
			t.Setenv("OYZU_DOCKER_FAIL", fail)
			// A missing image forces pull; run failure models daemon/name/entrypoint errors.
			if fail == "pull" {
				t.Setenv("OYZU_DOCKER_MISSING", "1")
			}
			job.KindOperation.Image = "registry/kind@sha256:" + strings.Repeat("b", 64)
			if err := Run(context.Background(), cfg, job); err != nil {
				t.Fatal(err)
			}
			var none runnerclient.KindNoResult
			if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Started || none.Code != "kind-not-started" {
				t.Fatalf("%s", f.finish)
			}
		})
	}
}

func TestInvalidOuterKindCreatesNoState(t *testing.T) {
	for _, image := range []string{"", "registry/kind@sha256:" + strings.Repeat("b", 64)} {
		f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
		cfg.StateDir = filepath.Join(t.TempDir(), "must-not-exist")
		job.KindOperation.Kind.Name, job.KindOperation.Image = "..", image
		if err := Run(context.Background(), cfg, job); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(cfg.StateDir); !os.IsNotExist(err) {
			t.Fatalf("state touched: %v", err)
		}
		if !strings.Contains(string(f.finish["no_result"]), "kind-not-started") {
			t.Fatalf("%s", f.finish)
		}
	}
}

func TestEventQueueBoundsAndReportsLoss(t *testing.T) {
	f, cfg, _, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	u := newUploader(cfg.Client, cfg.Token, cfg.Log)
	for range 100 {
		u.add(runnerclient.KindEvent{Type: "log", Message: strings.Repeat("x", 128<<10)})
	}
	if u.bytes > maxPendingBytes || u.dropped == 0 {
		t.Fatalf("bytes=%d dropped=%d", u.bytes, u.dropped)
	}
	u.flush(context.Background())
	for _, e := range f.events {
		if strings.Contains(e.Message, "dropped ") {
			return
		}
	}
	t.Fatal("missing loss marker")
}

func TestOutputIsBounded(t *testing.T) {
	out := &limitedBuffer{max: 32}
	if n, err := out.Write([]byte(strings.Repeat("x", 4096))); n != 4096 || err != nil {
		t.Fatal(n, err)
	}
	if !out.over || out.b.Len() != 32 {
		t.Fatal("output not bounded")
	}
}

func TestChildCannotOutliveTimeout(t *testing.T) {
	f, cfg, job, _ := setup(t, "child-parent", kindprotocol.OpObserve, 1, 0, nil)
	marker := filepath.Join(t.TempDir(), "survived")
	pid := filepath.Join(t.TempDir(), "pid")
	t.Setenv("OYZU_CHILD_MARKER", marker)
	t.Setenv("OYZU_CHILD_PID", pid)
	start := time.Now()
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("surviving child held stderr open")
	}
	if _, err := os.Stat(pid); err != nil {
		t.Fatal("child was never started:", err)
	}
	time.Sleep(max(0, 2500*time.Millisecond-time.Since(start)))
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("child survived cancellation")
	}
	if !strings.Contains(string(f.finish["no_result"]), "timed-out") {
		t.Fatalf("%s", f.finish)
	}
}

func TestAbortStopsOnShutdownAndLeaseLoss(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "lease"}[lost], func(t *testing.T) {
			f, cfg, job, state := setup(t, "hang-abort", kindprotocol.OpObserve, 60, 30, nil)
			f.cancel.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			stopStarted := make(chan time.Time, 1)
			if lost {
				cfg.LeaseExpires = time.Now().Add(30 * time.Second)
				var leaseArmed atomic.Bool
				useServer(t, &cfg, func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/heartbeat") {
						if leaseArmed.Load() {
							<-r.Context().Done()
							return
						}
						expires := time.Now().Add(30 * time.Second)
						if _, err := os.Stat(filepath.Join(state, "aborted")); err == nil {
							// Start the short lease only once the abort is running.
							start := time.Now()
							expires = start.Add(500 * time.Millisecond)
							leaseArmed.Store(true)
							stopStarted <- start
						}
						json.NewEncoder(w).Encode(runnerclient.KindBeat{Cancel: true, Expires: expires})
						return
					}
					f.ServeHTTP(w, r)
				})
			} else {
				go func() {
					for {
						if _, err := os.Stat(filepath.Join(state, "aborted")); err == nil {
							stopStarted <- time.Now()
							cancel()
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(10 * time.Millisecond):
						}
					}
				}()
			}
			err := Run(ctx, cfg, job)
			select {
			case start := <-stopStarted:
				if time.Since(start) > 5*time.Second {
					t.Fatal("abort ignored stop")
				}
			default:
				t.Fatalf("abort never started before stop: %v", err)
			}
			if lost && !errors.Is(err, ErrLost) {
				t.Fatalf("lease error: %v", err)
			}
			if !lost && err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(state, "aborted")); err != nil {
				t.Fatal("abort never started")
			}
		})
	}
}

func TestFailedLedgerSaveIsRecoveredAndPreferred(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	job.KindOperation.Ledger = true
	var fail atomic.Bool
	fail.Store(true)
	useServer(t, &cfg, func(w http.ResponseWriter, req *http.Request) {
		if fail.Load() && strings.HasSuffix(req.URL.Path, "/ledger") {
			http.Error(w, "unavailable", 503)
			return
		}
		f.ServeHTTP(w, req)
	})
	r := &run{cfg: cfg, job: job, op: job.KindOperation, log: cfg.Log, events: newUploader(cfg.Client, cfg.Token, cfg.Log)}
	l, err := r.ledger(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.path, "execution"), []byte("applied"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.saveLedgerWithin(context.Background(), l, 30*time.Millisecond)
	l.remove()
	if _, err := os.Stat(l.recovery); err != nil {
		t.Fatal("lost recovery:", err)
	}
	recovered, err := r.ledger(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.remove()
	if b, _ := os.ReadFile(filepath.Join(recovered.path, "execution")); string(b) != "applied" || !recovered.recovered {
		t.Fatal("remote empty ledger won over unsaved local copy")
	}
	fail.Store(false)
	r.saveLedgerWithin(context.Background(), recovered, time.Second)
	if f.saves != 1 {
		t.Fatal("recovery was not saved")
	}
	if _, err := os.Stat(l.recovery); !os.IsNotExist(err) {
		t.Fatal("recovery remains after successful save")
	}
	job.KindOperation.RecordID = "other-target"
	other, err := r.ledger(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer other.remove()
	if other.recovery == l.recovery {
		t.Fatal("target ledgers share a recovery path")
	}
}
func TestMessagesAndObservedStateAreMaskedBeforeQueueing(t *testing.T) {
	_, cfg, _, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	u := newUploader(cfg.Client, cfg.Token, cfg.Log)
	u.mask.Add("secret-value", "connector-value", "id-token-value")
	u.add(runnerclient.KindEvent{Type: "log", Message: cfg.Token + " secret-value connector-value id-token-value"})
	u.add(runnerclient.KindEvent{Type: "observed", Observed: &kindprotocol.ObservedState{
		AsOf: time.Now().UTC(), Components: []kindprotocol.ObservedComponent{{Component: "web", Health: kindprotocol.Healthy, Message: "secret-value"}},
	}})
	raw, _ := json.Marshal(u.pending)
	for _, secret := range []string{cfg.Token, "secret-value", "connector-value", "id-token-value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("unmasked credential queued")
		}
	}
	if u.pending[0].Message != "*** *** *** ***" || u.pending[1].Observed.Components[0].Message != "***" {
		t.Fatalf("%s", raw)
	}
}

func TestLedgerSaveRetriesBeforeDiscardingCheckpoint(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	job.KindOperation.Ledger = true
	var attempts atomic.Int32
	useServer(t, &cfg, func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/ledger") && attempts.Add(1) == 1 {
			http.Error(w, "retry", 503)
			return
		}
		f.ServeHTTP(w, req)
	})
	r := &run{cfg: cfg, job: job, op: job.KindOperation, log: cfg.Log, events: newUploader(cfg.Client, cfg.Token, cfg.Log)}
	l, err := r.ledger(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer l.remove()
	if err := os.WriteFile(filepath.Join(l.path, "execution"), []byte("applied"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.saveLedgerWithin(context.Background(), l, time.Second)
	if attempts.Load() != 2 || f.saves != 1 {
		t.Fatalf("attempts=%d saves=%d", attempts.Load(), f.saves)
	}
	if _, err := os.Stat(l.recovery); !os.IsNotExist(err) {
		t.Fatal("saved checkpoint was not removed")
	}
}
