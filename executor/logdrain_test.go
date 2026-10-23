package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

type logDeliveryServer struct {
	runs        *fakeRuns
	status      int
	recover     bool
	mu          sync.Mutex
	calls       []string
	finishedAt  time.Time
	afterFinish int
	wrongToken  bool
	outcome     chan struct{}
}

func (s *logDeliveryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/runner/v1/")
	if path == "job/finish" {
		s.mu.Lock()
		s.calls = append(s.calls, path)
		s.mu.Unlock()
		s.runs.ServeHTTP(w, r)
		s.mu.Lock()
		s.finishedAt = time.Now()
		s.mu.Unlock()
		close(s.outcome)
		return
	}
	if path != "job/logs" && path != "job/logs/finish" {
		s.runs.ServeHTTP(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, path)
	if r.Header.Get("Authorization") != "Bearer oyzu_job_ok" {
		s.wrongToken = true
		w.WriteHeader(401)
		return
	}
	status := s.status
	if !s.finishedAt.IsZero() {
		s.afterFinish++
		if s.recover {
			status = 0
		}
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if path == "job/logs/finish" {
		_ = json.NewEncoder(w).Encode(runnerclient.LogAck{State: "complete"})
		return
	}
	var chunk runnerclient.LogChunk
	if json.NewDecoder(r.Body).Decode(&chunk) != nil {
		w.WriteHeader(400)
		return
	}
	_ = json.NewEncoder(w).Encode(runnerclient.LogAck{NextSeq: chunk.Seq + 1})
}

func setupLogDelivery(t *testing.T, status int, recover bool) (*logDeliveryServer, Config) {
	t.Helper()
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build", "cli"))
	s := &logDeliveryServer{runs: runs, status: status, recover: recover, outcome: make(chan struct{})}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	cfg.Client = runnerclient.New(server.URL, server.Client())
	cfg.LogDrainTimeout = time.Second
	cfg.SecretsDir = t.TempDir()
	return s, cfg
}

func assertLogSpoolRemoved(t *testing.T, cfg Config) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(cfg.SecretsDir, ".oyzu-log-*"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("spool remains after Run: %v (%v)", paths, err)
	}
}

func TestRunLogDrainBeforeOutcome(t *testing.T) {
	s, cfg := setupLogDelivery(t, 0, false)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	logsFinished := slices.Index(s.calls, "job/logs/finish")
	jobFinished := slices.Index(s.calls, "job/finish")
	if logsFinished < 0 || jobFinished <= logsFinished || s.afterFinish != 0 || s.wrongToken {
		t.Fatalf("fast delivery ordering/token: %v, after=%d, wrong token=%v", s.calls, s.afterFinish, s.wrongToken)
	}
	assertLogSpoolRemoved(t, cfg)
}

func TestRunLogDrainAfterOutcome(t *testing.T) {
	for _, recover := range []bool{false, true} {
		name := "expires"
		if recover {
			name = "recovers"
		}
		t.Run(name, func(t *testing.T) {
			s, cfg := setupLogDelivery(t, http.StatusServiceUnavailable, recover)
			cfg.LogDrainTimeout = 500 * time.Millisecond
			done := make(chan error, 1)
			go func() { done <- Run(context.Background(), cfg) }()
			// Always join Run before the server and work directory are removed.
			joined := false
			defer func() {
				if !joined {
					<-done
				}
			}()
			select {
			case <-s.outcome:
			case <-time.After(5 * time.Second):
				t.Fatal("log outage prevented reporting the outcome")
			}
			s.runs.mu.Lock()
			state := s.runs.finished.State
			s.runs.mu.Unlock()
			if state != "succeeded" {
				t.Fatalf("upload failure changed outcome: %s", state)
			}
			paths, err := filepath.Glob(filepath.Join(cfg.SecretsDir, ".oyzu-log-*", "entries.ndjson"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("spool missing at job finish: %v (%v)", paths, err)
			}
			if _, err := os.Stat(paths[0]); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				joined = true
				t.Fatalf("Run returned before draining after the outcome: %v", err)
			default:
			}
			select {
			case err := <-done:
				joined = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Run exceeded the post-finish drain window")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.afterFinish == 0 || s.wrongToken {
				t.Fatalf("no delivery with the same token after job finish: %v", s.calls)
			}
			logsFinished := slices.Index(s.calls, "job/logs/finish")
			if recover {
				if logsFinished <= slices.Index(s.calls, "job/finish") {
					t.Fatalf("recovered log was not finished after the outcome: %v", s.calls)
				}
			} else if logsFinished >= 0 || time.Since(s.finishedAt) < cfg.LogDrainTimeout {
				t.Fatalf("drain window did not start at job finish: %v (%s)", s.calls, time.Since(s.finishedAt))
			}
			assertLogSpoolRemoved(t, cfg)
		})
	}
}

func TestRunLogDrainStopsOn404(t *testing.T) {
	s, cfg := setupLogDelivery(t, http.StatusNotFound, false)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Equal(s.calls, []string{"job/logs", "job/finish"}) || s.afterFinish != 0 {
		t.Fatalf("404 did not stop delivery: %v", s.calls)
	}
	assertLogSpoolRemoved(t, cfg)
}
