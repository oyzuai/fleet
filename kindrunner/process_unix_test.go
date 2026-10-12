//go:build !windows

package kindrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
)

func TestShutdownGivesMainAndAbortGraceButLeaseLossDoesNot(t *testing.T) {
	for _, abort := range []bool{false, true} {
		for _, lost := range []bool{false, true} {
			name := map[bool]string{false: "main", true: "abort"}[abort] + "/" + map[bool]string{false: "shutdown", true: "lease"}[lost]
			t.Run(name, func(t *testing.T) {
				f, cfg, job, state := setup(t, "ok", kindprotocol.OpObserve, 60, 30, nil)
				cfg.StopGrace = 2 * time.Second
				f.cancel.Store(abort)
				script := filepath.Join(cfg.KindsDir, "kind-fake")
				if err := os.Remove(script); err != nil {
					t.Fatal(err)
				}
				body := `#!/bin/sh
IFS= read -r request
phase=main
case "$request" in *'"operation":"abort"'*) phase=abort ;; esac
trap 'sleep 0.2; touch "$OYZU_KIND_STATE_DIR/$phase-stopped"; exit 0' TERM
touch "$OYZU_KIND_STATE_DIR/$phase-ready"
while :; do sleep 0.1; done
`
				if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
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
				phases := []string{"main"}
				if abort {
					phases = append(phases, "abort")
				}
				deadline := time.Now().Add(10 * time.Second)
				for _, phase := range phases {
					for {
						if _, err := os.Stat(filepath.Join(state, phase+"-ready")); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("%s never started", phase)
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
				cause := context.Canceled
				if lost {
					cause = ErrLost
				}
				cancel(cause)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("kind did not stop")
				}
				if lost && !errors.Is(runErr, ErrLost) || !lost && runErr != nil {
					t.Fatalf("Run: %v", runErr)
				}
				for _, phase := range phases {
					_, err := os.Stat(filepath.Join(state, phase+"-stopped"))
					if lost && !os.IsNotExist(err) || !lost && err != nil {
						t.Fatalf("%s graceful stop, lost=%v: %v", phase, lost, err)
					}
				}
			})
		}
	}
}

func TestShellChildHoldingStderrDiesAtTimeout(t *testing.T) {
	_, cfg, job, state := setup(t, "ok", kindprotocol.OpObserve, 1, 0, nil)
	script := filepath.Join(cfg.KindsDir, "kind-fake")
	// Remove the symlink before replacing it with the reproduction script.
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\nsleep 20 &\necho $! > \"$OYZU_KIND_STATE_DIR/child.pid\"\nexec sleep 60\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("descendant held stderr past timeout")
	}
	raw, err := os.ReadFile(filepath.Join(state, "child.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); ; {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		// An orphan can remain a zombie until the host's init reaps it.
		if stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil && strings.Contains(string(stat), ") Z ") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("child still running")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
