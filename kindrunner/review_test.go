package kindrunner

import (
	"context"
	"encoding/json"
	"errors"
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
