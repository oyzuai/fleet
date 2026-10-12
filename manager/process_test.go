package manager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

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
	case "execution-args":
		for i, arg := range os.Args {
			if arg == "--" {
				raw, _ := json.Marshal(os.Args[i+1:])
				if err := os.WriteFile(os.Getenv("POOLMANAGER_ARGS_FILE"), raw, 0o600); err != nil {
					os.Exit(1)
				}
				os.Exit(0)
			}
		}
		os.Exit(1)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		code, _ := strconv.Atoi(mode)
		os.Exit(code)
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
}
