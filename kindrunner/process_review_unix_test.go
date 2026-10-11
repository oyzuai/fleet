//go:build !windows

package kindrunner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
)

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
