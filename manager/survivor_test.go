package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// A manager restarted after a crash finds its predecessor's executor still
// running: it keeps the workspace, counts the slot, and cleans up only once
// the executor exits.
func TestProcessDriverAdoptsASurvivingExecutor(t *testing.T) {
	crashed := helperDriver(t, "sleep")
	ctx := context.Background()
	h, err := crashed.Start(ctx, "0", runnerclient.Claim{JobID: 21, Attempt: 2, StartupToken: "x"})
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := crashed.proc(h)
	r, err := readRecord(h.Ref)
	if err != nil || r.PID != pr.cmd.Process.Pid || r.Job != 21 || r.Attempt != 2 {
		t.Fatalf("record = %+v, %v", r, err)
	}

	// The new manager has no memory of it.
	restarted := &Process{Manager: crashed.Manager, WorkDir: crashed.WorkDir, Slots: 2, Log: quiet(), poll: 10 * time.Millisecond}
	if err := restarted.Reap(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.Ref, StartupTokenFile)); err != nil {
		t.Fatalf("the survivor's workspace was removed: %v", err)
	}
	c, _ := restarted.Capacity(ctx)
	if c.Running != 1 || len(c.Ready) != 1 {
		t.Fatalf("capacity with a survivor = %+v", c)
	}
	// A second reap neither adopts it twice nor removes it.
	_ = restarted.Reap(ctx, nil)
	if c, _ := restarted.Capacity(ctx); c.Running != 1 {
		t.Fatalf("capacity after a second reap = %+v", c)
	}

	_ = pr.cmd.Process.Kill()
	<-pr.done
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, _ := restarted.Capacity(ctx)
		if _, err := os.Stat(h.Ref); errors.Is(err, os.ErrNotExist) && c.Running == 0 && len(c.Ready) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the exited survivor was not cleaned up: %+v", c)
		}
		time.Sleep(10 * time.Millisecond)
	}
	pr.log.Close()
}

// A record whose process is gone, or whose PID now belongs to another
// process, is a dead executor: its directory goes and nothing is killed.
func TestProcessDriverReapsDeadAndReusedRecords(t *testing.T) {
	p := helperDriver(t, "0")
	ctx := context.Background()
	self, err := processStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	dirs := map[string]record{
		"job-1-1-dead": {PID: 1 << 22, Start: "1", Job: 1, Attempt: 1},
		"job-2-1-reus": {PID: os.Getpid(), Start: self + "0", Job: 2, Attempt: 1},
		"job-3-1-live": {PID: os.Getpid(), Start: self, Job: 3, Attempt: 1},
	}
	for name, r := range dirs {
		dir := filepath.Join(p.jobsDir(), name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeRecord(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	torn := filepath.Join(p.jobsDir(), "job-4-1-torn")
	_ = os.MkdirAll(torn, 0o700)
	_ = os.WriteFile(filepath.Join(torn, executorRecord), []byte(`{"pid":`), 0o600)

	if err := p.Reap(ctx, nil); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"job-1-1-dead": false, "job-2-1-reus": false, "job-3-1-live": true, "job-4-1-torn": true} {
		if _, err := os.Stat(filepath.Join(p.jobsDir(), name)); (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", name, err == nil, want)
		}
	}
	// This test process, whose PID the records named, is still here.
	if _, err := processStart(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if c, _ := p.Capacity(ctx); c.Running != 1 {
		t.Fatalf("capacity = %+v", c)
	}
}

func TestProcessStartIdentifiesAProcess(t *testing.T) {
	a, err := processStart(os.Getpid())
	if err != nil || a == "" {
		t.Fatalf("processStart(self) = %q, %v", a, err)
	}
	if b, _ := processStart(os.Getpid()); b != a {
		t.Fatalf("start time changed: %q then %q", a, b)
	}
	if _, err := processStart(1 << 22); !errors.Is(err, errProcessGone) {
		t.Fatalf("processStart(missing) = %v", err)
	}
}
