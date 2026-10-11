//go:build !windows

package manager

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts cmd as the leader of a new process group, so the
// executor and everything it starts can be stopped together, and a signal
// meant for the manager's terminal does not reach it.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup kills the process group led by pid.
func killGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
