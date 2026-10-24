package manager

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/executor"
	"github.com/oyzuai/fleet/runnerclient"
)

// TestHelperProcess is the job runner the process driver tests start: this
// test binary again, told what to do by POOLMANAGER_HELPER.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("POOLMANAGER_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "decision-echo":
		args := slices.Index(os.Args, "--")
		if args < 0 || !errors.Is(executor.Command(os.Args[args+1:], quiet()), runnerclient.ErrUnauthenticated) {
			os.Exit(42)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "readtoken":
		// The executor runs inside its job directory, so both paths it is
		// given must be absolute and the token must be readable.
		code := 0
		for i, a := range os.Args {
			if (a == "--startup-token-file" || a == "--work-dir") && i+1 < len(os.Args) && !filepath.IsAbs(os.Args[i+1]) {
				code = 4
			}
			if a == "--startup-token-file" && i+1 < len(os.Args) {
				if _, err := os.ReadFile(os.Args[i+1]); err != nil {
					code = 5
				}
			}
		}
		os.Exit(code)
	default:
		code, _ := strconv.Atoi(mode)
		os.Exit(code)
	}
}

// Real process driver, executor command and HTTP client. The controlled server
// refuses before issuing work; this qualifies transport, not native execution.
func TestProcessDriverExecutionDecisionEcho(t *testing.T) {
	const decision = "11111111-2222-4333-8444-555555555555"
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in runnerclient.StartupAssignment
		if r.URL.Path == "/runner/v1/job/start" && r.Header.Get("Authorization") == "Bearer task-startup" && json.NewDecoder(r.Body).Decode(&in) == nil {
			received <- in.ExecutionTrustDecision
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	p := helperDriver(t, "decision-echo")
	p.Server = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h, err := p.Start(ctx, "0", runnerclient.Claim{JobID: 17, Attempt: 3, StartupToken: "task-startup", ExecutionTrustDecision: decision})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Teardown(context.Background(), h)
	exit, err := p.Wait(ctx, h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("executor command did not reach controlled startup refusal: %+v %v", exit, err)
	}
	select {
	case got := <-received:
		if got != decision {
			t.Fatal("manager/driver/executor handoff lost the server reference")
		}
	default:
		t.Fatal("executor never echoed its claimed reference")
	}
	if _, err := os.Stat(filepath.Join(h.Ref, StartupTokenFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("executor did not consume its one-read startup file")
	}
}

func helperDriver(t *testing.T, mode string) *Process {
	t.Helper()
	t.Setenv("POOLMANAGER_HELPER", mode)
	work := t.TempDir()
	return &Process{
		Runner:  os.Args[0],
		Args:    []string{"-test.run=^TestHelperProcess$", "--"},
		Server:  "http://runs.invalid",
		Manager: 7, WorkDir: work, LogDir: filepath.Join(work, "logs"), Slots: 2,
		ExtraEnv: []string{"POOLMANAGER_HELPER"}, StopGrace: time.Second, Log: quiet(),
	}
}

func TestProcessDriverRunsAJobInASlot(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		clean bool
		code  int
	}{{"0", true, 0}, {"3", false, 3}} {
		t.Run("exit "+tc.mode, func(t *testing.T) {
			p := helperDriver(t, tc.mode)
			ctx := context.Background()
			c, err := p.Capacity(ctx)
			if err != nil || c.Max != 2 || c.Running != 0 || len(c.Ready) != 2 || c.Room() != 0 {
				t.Fatalf("capacity = %+v, %v", c, err)
			}
			h, err := p.Start(ctx, c.Ready[0], runnerclient.Claim{JobID: 11, Attempt: 1, StartupToken: "oyzu_start_x"})
			if err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(h.Ref, StartupTokenFile)); err != nil || string(b) != "oyzu_start_x" {
				t.Fatalf("startup token file = %q, %v", b, err)
			}
			if c, _ := p.Capacity(ctx); c.Running != 1 || slices.Contains(c.Ready, h.Slot) {
				t.Fatalf("capacity while running = %+v", c)
			}
			if _, err := p.Start(ctx, h.Slot, runnerclient.Claim{JobID: 12, Attempt: 1}); err == nil {
				t.Fatal("started a second job in a busy slot")
			}
			exit, err := p.Wait(ctx, h)
			if err != nil || exit.Clean() != tc.clean || exit.Reason != ExitExited || exit.Code != tc.code {
				t.Fatalf("exit = %+v, %v", exit, err)
			}
			if err := p.Teardown(ctx, h); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(h.Ref); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the job directory was kept")
			}
			if c, _ := p.Capacity(ctx); c.Running != 0 || len(c.Ready) != 2 {
				t.Fatalf("capacity after teardown = %+v", c)
			}
		})
	}
}

func TestProcessDriverTeardownStopsARunningJob(t *testing.T) {
	p := helperDriver(t, "sleep")
	ctx := context.Background()
	h, err := p.Start(ctx, "0", runnerclient.Claim{JobID: 11, Attempt: 1, StartupToken: "x"})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	// A done context stops the waiting, not the runner.
	if _, err := p.Wait(waitCtx, h); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait = %v", err)
	}
	stopped := make(chan error)
	go func() { stopped <- p.Teardown(ctx, h) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("teardown did not stop the runner")
	}
	if _, err := os.Stat(h.Ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the job directory was kept")
	}
}

func TestProcessDriverReapsOnlyItsOwnDeadJobs(t *testing.T) {
	p := helperDriver(t, "sleep")
	ctx := context.Background()
	mine := p.jobsDir()
	others := filepath.Join(p.WorkDir, "manager-8")
	for _, d := range []string{
		filepath.Join(mine, "job-1-1-aaaa"), filepath.Join(mine, "job-2-1-bbbb"),
		filepath.Join(mine, "notes"), filepath.Join(others, "job-1-1-cccc"),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h, err := p.Start(ctx, "0", runnerclient.Claim{JobID: 3, Attempt: 1, StartupToken: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Teardown(ctx, h) }()
	// Job 2 is live elsewhere in the manager; job 3 is this driver's own.
	if err := p.Reap(ctx, []JobID{2}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		filepath.Join(mine, "job-1-1-aaaa"):   false,
		filepath.Join(mine, "job-2-1-bbbb"):   true,
		filepath.Join(mine, "notes"):          true,
		filepath.Join(others, "job-1-1-cccc"): true,
		h.Ref:                                 true,
	} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("%s exists = %v, want %v", path, err == nil, want)
		}
	}
}

func TestProcessDriverFacts(t *testing.T) {
	p := &Process{Docker: true}
	f, err := p.Facts(context.Background())
	if err != nil || f[FactIsolation] != "process" || f[FactDocker] != "true" || f[FactOS] == "" || f[FactArch] == "" {
		t.Fatalf("facts = %v, %v", f, err)
	}
	if n, err := strconv.Atoi(f[FactCPU]); err != nil || n < 1 {
		t.Fatalf("cpu fact = %q", f[FactCPU])
	}
	if f[FactEgress] != EgressOpen || f[FactUntrusted] != "" {
		t.Fatalf("a process pool must be open and never untrusted: %v", f)
	}
}

func TestProcessDriverTellsOyzuWhenThereIsNoDocker(t *testing.T) {
	environ := func() []string {
		return []string{"PATH=/bin", "OYZU_NO_DOCKER=0", "SECRET=x"}
	}
	has := func(env []string, kv string) bool { return slices.Contains(env, kv) }

	without := (&Process{environ: environ}).env()
	if !has(without, "OYZU_NO_DOCKER=1") || has(without, "OYZU_NO_DOCKER=0") || has(without, "SECRET=x") || !has(without, "PATH=/bin") {
		t.Fatalf("env without Docker = %v", without)
	}
	with := (&Process{Docker: true, environ: environ, ExtraEnv: []string{"OYZU_NO_DOCKER"}}).env()
	if has(with, "OYZU_NO_DOCKER=1") || !has(with, "OYZU_NO_DOCKER=0") {
		t.Fatalf("env with Docker = %v", with)
	}
	if env := (&Process{Docker: true, environ: environ}).env(); slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "OYZU_NO_DOCKER=") }) {
		t.Fatalf("env with Docker and no pass-through = %v", env)
	}
}
