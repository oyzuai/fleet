package manager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestActionManagerReleasesOnlyAfterSuccessfulCleanup(t *testing.T) {
	for _, failing := range []bool{false, true} {
		p := helperDriver(t, "3")
		p.ActionEngine = "trusted-engine"
		var events []string
		var mu sync.Mutex
		p.ActionCleanup = func(context.Context, runnerclient.ActionOwner) error {
			mu.Lock()
			events = append(events, "cleanup")
			mu.Unlock()
			if failing {
				return errors.New("cleanup failed")
			}
			return nil
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			events = append(events, "release")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"released":false}`)
		}))
		claim := runnerclient.Claim{JobID: 42, Attempt: 3, StartupToken: "startup"}
		h, err := p.Start(context.Background(), "0", claim)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		m := &Manager{cfg: Config{Driver: p, Client: runnerclient.New(server.URL, nil), Now: time.Now, TeardownTimeout: time.Second}, access: runnerclient.AccessToken{Token: "access", Expires: time.Now().Add(time.Hour)}}
		m.watch(context.Background(), quiet(), h, claim, nil)
		server.Close()
		want := []string{"cleanup"}
		if !failing {
			want = append(want, "release")
		}
		if !slices.Equal(events, want) {
			t.Fatalf("release ordering: got %v want %v", events, want)
		}
	}
}

func TestActionTeardownRetainsSlotUntilRecovery(t *testing.T) {
	p := helperDriver(t, "sleep")
	p.Slots = 1
	p.ActionEngine = "trusted-engine"
	failing := true
	p.ActionCleanup = func(_ context.Context, owner runnerclient.ActionOwner) error {
		if owner.ManagerID != p.Manager || owner.JobID != 42 || owner.Attempt != 3 {
			t.Fatal("unbound cleanup identity")
		}
		if failing {
			return errors.New("engine unavailable")
		}
		return nil
	}
	ctx := context.Background()
	h, err := p.Start(ctx, "0", runnerclient.Claim{JobID: 42, Attempt: 3, StartupToken: "startup"})
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := p.proc(h)
	defer func() { pr.cmd.Process.Kill(); <-pr.done; pr.log.Close() }()
	pr.cmd.Process.Kill()
	<-pr.done
	if err = p.Teardown(ctx, h); err == nil {
		t.Fatal("cleanup failure was accepted")
	}
	if c, _ := p.Capacity(ctx); c.Running != 1 || len(c.Ready) != 0 {
		t.Fatalf("failed cleanup released slot: %+v", c)
	}
	if _, err = os.Stat(h.Ref); err != nil {
		t.Fatal("recovery directory removed", err)
	}
	failing = false
	if err = p.Reap(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := p.Capacity(ctx); c.Running != 0 || len(c.Ready) != 1 {
		t.Fatalf("recovery did not release slot: %+v", c)
	}
}

func TestActionRestartRecoveryRejectsMismatchedOwnerAndBlocksCapacity(t *testing.T) {
	p := &Process{Manager: 7, WorkDir: t.TempDir(), Slots: 1}
	dir := filepath.Join(p.jobsDir(), "job-42-3-recovery")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := runnerclient.ActionOwner{ManagerID: 8, JobID: 42, Attempt: 3, Directory: dir}
	if err := runnerclient.WriteActionOwner(owner); err != nil {
		t.Fatal(err)
	}
	called := false
	p.ActionCleanup = func(context.Context, runnerclient.ActionOwner) error { called = true; return nil }
	if err := p.Reap(context.Background(), nil); err == nil || called {
		t.Fatal("mismatched ownership reached engine cleanup")
	}
	if c, _ := p.Capacity(context.Background()); c.Running != 1 || len(c.Ready) != 0 {
		t.Fatalf("invalid recovery released capacity: %+v", c)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("invalid recovery identity was discarded", err)
	}
}

func TestActionRecoverySurvivesUnrelatedKindListingFailure(t *testing.T) {
	p := &Process{Manager: 7, WorkDir: t.TempDir(), Slots: 1, Docker: true, ActionEngine: "separate-trusted-engine"}
	dir := filepath.Join(p.jobsDir(), "job-42-3-recovery")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := runnerclient.ActionOwner{ManagerID: 7, JobID: 42, Attempt: 3, Directory: dir}
	if err := runnerclient.WriteActionOwner(owner); err != nil {
		t.Fatal(err)
	}
	called := false
	p.ActionCleanup = func(_ context.Context, actual runnerclient.ActionOwner) error {
		if actual != owner {
			t.Fatal("wrong owner")
		}
		called = true
		return nil
	}
	// The action engine is independently injected. The native-kind CLI is absent.
	t.Setenv("PATH", t.TempDir())
	if err := p.Reap(context.Background(), nil); err == nil || !called {
		t.Fatalf("kind failure bypassed action recovery: called=%t err=%v", called, err)
	}
	if c, _ := p.Capacity(context.Background()); c.Running != 1 || len(c.Ready) != 0 {
		t.Fatalf("unreconciled kind resources freed capacity: %+v", c)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("recovery directory removed while native kinds were unobserved", err)
	}
}

func TestActionAdoptedExitKeepsFailedCleanupBlockedForReaper(t *testing.T) {
	crashed := helperDriver(t, "sleep")
	crashed.ActionEngine = "trusted-engine"
	ctx := context.Background()
	h, err := crashed.Start(ctx, "0", runnerclient.Claim{JobID: 42, Attempt: 3, StartupToken: "startup"})
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := crashed.proc(h)
	defer func() { pr.cmd.Process.Kill(); <-pr.done; pr.log.Close() }()
	restarted := &Process{Manager: crashed.Manager, WorkDir: crashed.WorkDir, Slots: 1, poll: time.Millisecond}
	restarted.ActionCleanup = func(context.Context, runnerclient.ActionOwner) error { return errors.New("engine unavailable") }
	if err = restarted.Reap(ctx, nil); err != nil {
		t.Fatal(err)
	}
	pr.cmd.Process.Kill()
	<-pr.done
	deadline := time.Now().Add(5 * time.Second)
	for {
		restarted.mu.Lock()
		blocked := len(restarted.blocked)
		restarted.mu.Unlock()
		if blocked == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("adopted cleanup did not retain blocked slot")
		}
		time.Sleep(time.Millisecond)
	}
	if c, _ := restarted.Capacity(ctx); c.Running != 1 || len(c.Ready) != 0 {
		t.Fatalf("adopted exit freed slot before cleanup: %+v", c)
	}
	restarted.ActionCleanup = func(context.Context, runnerclient.ActionOwner) error { return nil }
	if err = restarted.Reap(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := restarted.Capacity(ctx); c.Running != 0 || len(c.Ready) != 1 {
		t.Fatalf("retry recovery failed: %+v", c)
	}
}
