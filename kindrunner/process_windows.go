package kindrunner

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	createJob     = kernel32.NewProc("CreateJobObjectW")
	setJob        = kernel32.NewProc("SetInformationJobObject")
	assignJob     = kernel32.NewProc("AssignProcessToJobObject")
	terminateJob  = kernel32.NewProc("TerminateJobObject")
	resumeProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtResumeProcess")
)

// jobLimits is JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type jobLimits struct {
	processTime, jobTime                           int64
	flags                                          uint32
	minimum, maximum                               uintptr
	active                                         uint32
	affinity                                       uintptr
	priority, scheduling                           uint32
	io                                             [6]uint64
	processMemory, jobMemory, peakProcess, peakJob uintptr
}

type processGroup struct {
	mu  sync.Mutex
	job syscall.Handle
}

// Suspended creation prevents children escaping before assignment to the job.
func prepareProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x4} }

func attachProcess(cmd *exec.Cmd) (*processGroup, error) {
	handle, _, err := createJob.Call(0, 0)
	if handle == 0 {
		return nil, fmt.Errorf("create kind job: %w", err)
	}
	g := &processGroup{job: syscall.Handle(handle)}
	limits := jobLimits{flags: 0x2000} // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ok, _, err := setJob.Call(handle, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		g.close()
		return nil, fmt.Errorf("set kind job limits: %w", err)
	}
	proc, err := syscall.OpenProcess(0x100|0x1|0x800|0x400, false, uint32(cmd.Process.Pid))
	if err != nil {
		g.close()
		return nil, err
	}
	defer syscall.CloseHandle(proc)
	ok, _, err = assignJob.Call(handle, uintptr(proc))
	if ok == 0 {
		g.close()
		return nil, fmt.Errorf("assign kind to job: %w", err)
	}
	status, _, _ := resumeProcess.Call(uintptr(proc))
	if status != 0 {
		g.close()
		return nil, fmt.Errorf("resume kind: NTSTATUS %#x", status)
	}
	return g, nil
}

// Windows has no SIGTERM for a job; both stop phases terminate the whole job.
func (g *processGroup) terminate() { g.kill() }
func (g *processGroup) kill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.job != 0 {
		terminateJob.Call(uintptr(g.job), 1)
	}
}
func (g *processGroup) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.job != 0 {
		syscall.CloseHandle(g.job)
		g.job = 0
	}
}
