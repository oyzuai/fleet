package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

type actionDriverFake struct {
	run      func(context.Context) runnerclient.ActionCompletion
	readyErr error
}

func (d actionDriverFake) Ready(context.Context) error { return d.readyErr }
func (d actionDriverFake) RunAction(ctx context.Context, _ runnerclient.ActionOwner, _ runnerclient.ActionAssignment, _ runnerclient.ActionInputs) runnerclient.ActionCompletion {
	return d.run(ctx)
}

func TestActionDispatchNeverUsesNativeSource(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "driver", true: "missing driver"}[missing], func(t *testing.T) {
			var routes []string
			var mu sync.Mutex
			finished := runnerclient.ActionCompletion{}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				routes = append(routes, r.URL.Path)
				mu.Unlock()
				switch r.URL.Path {
				case "/runner/v1/job/start":
					var startup runnerclient.StartupAssignment
					json.NewDecoder(r.Body).Decode(&startup)
					if (startup.ActionRuntime == runnerclient.ActionRuntime) == missing {
						t.Error("wrong runtime advertisement")
					}
					json.NewEncoder(w).Encode(runnerclient.Started{JobToken: "job", Expires: time.Now().Add(time.Minute), Job: runnerclient.Job{ID: 1, Attempt: 1, Kind: runnerclient.ActionJob, Action: &runnerclient.ActionAssignment{InstanceID: "instance", OperationID: "operation", Image: "image@sha256:" + strings.Repeat("a", 64), OutputStyle: "paths", WorkspaceBytes: runnerclient.MaxWorkspaceBytes, WorkspaceInodes: runnerclient.MaxWorkspaceInodes, Arguments: []string{"tool"}, TimeoutSeconds: 10, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}}})
				case "/runner/v1/job/action/inputs":
					json.NewEncoder(w).Encode(runnerclient.ActionInputs{})
				case "/runner/v1/job/action/finish":
					json.NewDecoder(r.Body).Decode(&finished)
					w.WriteHeader(204)
				default:
					t.Errorf("unexpected native/control route: %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer s.Close()
			dir := t.TempDir()
			token := filepath.Join(dir, "startup")
			os.WriteFile(token, []byte("once"), 0600)
			cfg := Config{Client: runnerclient.New(s.URL, nil), StartupTokenFile: token, WorkDir: filepath.Join(dir, "source"), Git: "must-not-run", Oyzu: "must-not-run", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			if !missing {
				cfg.ActionDriver = actionDriverFake{run: func(context.Context) runnerclient.ActionCompletion {
					code := 7
					return runnerclient.ActionCompletion{ExitCode: &code, TerminationConfirmed: true}
				}}
			}
			if err := Run(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if missing && finished.ErrorCode != "FAILED_PRECONDITION" || !missing && (finished.ExitCode == nil || *finished.ExitCode != 7 || finished.ErrorCode != "") {
				t.Fatalf("completion: %+v", finished)
			}
			if _, err := os.Stat(cfg.WorkDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("native source directory was created")
			}
		})
	}
}

func TestActionLeaseLossFencesLateCompletion(t *testing.T) {
	finishes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runner/v1/job/action/inputs":
			json.NewEncoder(w).Encode(runnerclient.ActionInputs{})
		case "/runner/v1/job/heartbeat":
			w.WriteHeader(http.StatusUnauthorized)
		case "/runner/v1/job/action/finish":
			finishes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	a := &runnerclient.ActionAssignment{InstanceID: "instance", OperationID: "operation", Image: "image@sha256:" + strings.Repeat("a", 64), OutputStyle: "paths", WorkspaceBytes: runnerclient.MaxWorkspaceBytes, WorkspaceInodes: runnerclient.MaxWorkspaceInodes, Arguments: []string{"tool"}, TimeoutSeconds: 10, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}
	cfg := Config{Client: runnerclient.New(s.URL, nil), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ActionDriver: actionDriverFake{run: func(ctx context.Context) runnerclient.ActionCompletion {
		<-ctx.Done()
		return runnerclient.ActionCompletion{TerminationConfirmed: true}
	}}}
	err := runAction(context.Background(), cfg, runnerclient.Started{JobToken: "live", Expires: time.Now().Add(100 * time.Millisecond), HeartbeatSeconds: 1, Job: runnerclient.Job{Kind: runnerclient.ActionJob, Action: a}})
	if !errors.Is(err, errLost) || finishes != 0 {
		t.Fatalf("lease loss published late result: %v, %d", err, finishes)
	}
}

func TestActionCancellationDiscardsSuccessfulLinkGraphBeforeFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var finished runnerclient.ActionCompletion
	finishes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runner/v1/job/action/inputs":
			json.NewEncoder(w).Encode(runnerclient.ActionInputs{})
		case "/runner/v1/job/action/finish":
			finishes++
			json.NewDecoder(r.Body).Decode(&finished)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	a := &runnerclient.ActionAssignment{InstanceID: "instance", OperationID: "operation", Image: "image@sha256:" + strings.Repeat("a", 64), Arguments: []string{"tool"}, OutputStyle: "paths", WorkspaceBytes: runnerclient.MaxWorkspaceBytes, WorkspaceInodes: runnerclient.MaxWorkspaceInodes, TimeoutSeconds: 10, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}
	cfg := Config{Client: runnerclient.New(s.URL, nil), Log: slog.New(slog.DiscardHandler), ActionDriver: actionDriverFake{run: func(context.Context) runnerclient.ActionCompletion {
		cancel()
		zero := 0
		return runnerclient.ActionCompletion{ExitCode: &zero, TerminationConfirmed: true, Stdout: []byte("success"), Symlinks: []runnerclient.ActionSymlink{{Path: "out", Target: "."}}, WorkspaceNodes: []runnerclient.ActionNode{{Path: "out", Kind: "symlink", Target: "."}}}
	}}}
	if err := runAction(ctx, cfg, runnerclient.Started{JobToken: "live", Expires: time.Now().Add(time.Minute), Job: runnerclient.Job{Kind: runnerclient.ActionJob, Action: a}}); err != nil {
		t.Fatal(err)
	}
	if finishes != 1 || finished.ErrorCode != "CANCELLED" || !finished.TerminationConfirmed || finished.ExitCode != nil || len(finished.Stdout)+len(finished.Stderr)+len(finished.Files)+len(finished.Directories)+len(finished.Symlinks)+len(finished.WorkspaceNodes) != 0 {
		t.Fatalf("cancelled completion: %+v", finished)
	}
}
