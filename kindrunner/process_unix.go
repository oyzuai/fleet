//go:build !windows

package kindrunner

import (
	"os/exec"
	"sync"
	"syscall"
)

type processGroup struct {
	mu  sync.Mutex
	pid int
}

func prepareProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func attachProcess(cmd *exec.Cmd) (*processGroup, error) {
	return &processGroup{pid: cmd.Process.Pid}, nil
}
func (g *processGroup) signal(sig syscall.Signal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pid > 0 {
		_ = syscall.Kill(-g.pid, sig)
	}
}
func (g *processGroup) terminate() { g.signal(syscall.SIGTERM) }
func (g *processGroup) kill()      { g.signal(syscall.SIGKILL) }
func (g *processGroup) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pid > 0 {
		_ = syscall.Kill(-g.pid, syscall.SIGKILL)
		g.pid = 0
	}
}
