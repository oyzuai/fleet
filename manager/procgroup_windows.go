package manager

import (
	"os"
	"os/exec"
	"syscall"
)

// ownProcessGroup starts cmd in a new process group, so a console interrupt
// meant for the manager does not reach it.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// killGroup kills the process pid; Windows has no group signal.
func killGroup(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
