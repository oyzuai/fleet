package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// StartupTokenFile is the file in a job's directory that holds its startup
// token. The runner reads and deletes it before doing anything else.
const StartupTokenFile = "startup-token"

// passEnv is the environment a runner inherits: what a build needs to find
// its tools and caches on Windows, macOS and Linux. Nothing else reaches it,
// so nothing the manager was started with (credentials included) leaks into
// a job.
var passEnv = []string{
	"PATH", "PATHEXT", "SystemRoot", "SystemDrive", "windir", "ComSpec", "OS",
	"TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
	"APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
	"NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "USER", "USERNAME", "LOGNAME",
	"LANG", "LC_ALL", "TZ", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "DOCKER_HOST",
}

// defaultStopGrace is how long a runner has to report after it is asked to
// stop, before it is killed.
const defaultStopGrace = 30 * time.Second

// Process is the local process driver: each job runs as a fresh oyzu-executor
// process with its own directory on this machine, removed at teardown.
// Slots are always ready, so Provision does nothing. Jobs share the host,
// so the pool reports oyzu.io/isolation=process.
type Process struct {
	// Runner is the oyzu-executor executable.
	Runner string
	// Args are passed to every runner before the job's own flags, such as
	// --oyzu.
	Args []string
	// Server is the runs URL the runner calls.
	Server string
	// Manager is this manager's id; its job directories live under
	// WorkDir/manager-<id>, so Reap never touches another manager's.
	Manager int64
	// WorkDir holds one directory per job.
	WorkDir string
	// LogDir keeps each runner's output, named after the job and attempt.
	LogDir string
	// Slots is how many jobs run at once; at least 1.
	Slots int
	// Docker reports that jobs may use this host's Docker or BuildKit.
	Docker bool
	// Renovate reports that Renovate is installed and Args name it to the
	// runner, so the pool takes renovate jobs.
	Renovate bool
	// ExtraEnv names more variables to pass through, beside passEnv.
	ExtraEnv []string
	// StopGrace is how long a runner may report after an interrupt before
	// it is killed; defaultStopGrace when 0.
	StopGrace time.Duration
	Log       *slog.Logger
	// environ is the manager's environment; os.Environ when nil.
	environ func() []string

	mu    sync.Mutex
	inUse map[SlotID]*proc
}

// proc is one running runner.
type proc struct {
	cmd  *exec.Cmd
	dir  string
	log  *os.File
	done chan struct{}
	err  error // cmd.Wait's result, set before done closes
}

var _ Driver = (*Process)(nil)

func (p *Process) slots() int { return max(1, p.Slots) }

func (p *Process) jobsDir() string {
	return filepath.Join(p.WorkDir, fmt.Sprintf("manager-%d", p.Manager))
}

// Facts implements Driver.
func (p *Process) Facts(context.Context) (Facts, error) {
	f := Facts{
		FactOS:        runtime.GOOS,
		FactArch:      runtime.GOARCH,
		FactCPU:       strconv.Itoa(runtime.NumCPU()),
		FactIsolation: "process",
		FactDocker:    strconv.FormatBool(p.Docker),
	}
	if p.Renovate {
		f[FactRenovate] = "true"
	}
	return f, nil
}

// Capacity implements Driver.
func (p *Process) Capacity(context.Context) (Capacity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := Capacity{Max: p.slots(), Running: len(p.inUse)}
	for i := range p.slots() {
		id := SlotID(strconv.Itoa(i))
		if _, busy := p.inUse[id]; !busy {
			c.Ready = append(c.Ready, id)
		}
	}
	return c, nil
}

// Provision implements Driver. Process slots are always ready.
func (p *Process) Provision(context.Context, int) error { return nil }

// Start implements Driver.
func (p *Process) Start(_ context.Context, slot SlotID, c runnerclient.Claim) (Handle, error) {
	p.mu.Lock()
	if p.inUse == nil {
		p.inUse = map[SlotID]*proc{}
	}
	if _, busy := p.inUse[slot]; busy {
		p.mu.Unlock()
		return Handle{}, fmt.Errorf("slot %s is not ready", slot)
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	dir := filepath.Join(p.jobsDir(), fmt.Sprintf("job-%d-%d-%s", c.JobID, c.Attempt, hex.EncodeToString(suffix)))
	pr := &proc{dir: dir, done: make(chan struct{})}
	p.inUse[slot] = pr
	p.mu.Unlock()

	h := Handle{Slot: slot, Job: c.JobID, Attempt: c.Attempt, Ref: pr.dir}
	if err := p.start(pr, c); err != nil {
		close(pr.done)
		return h, err
	}
	return h, nil
}

func (p *Process) start(pr *proc, c runnerclient.Claim) error {
	if err := os.MkdirAll(pr.dir, 0o700); err != nil {
		return err
	}
	// The executor runs with cmd.Dir = pr.dir, so the paths it is given must not
	// depend on the manager's own working directory.
	jobDir, err := filepath.Abs(pr.dir)
	if err != nil {
		return err
	}
	tokenFile := filepath.Join(jobDir, StartupTokenFile)
	if err := writeAtomic(tokenFile, []byte(c.StartupToken)); err != nil {
		return err
	}
	if err := os.MkdirAll(p.LogDir, 0o700); err != nil {
		return err
	}
	logFile, err := os.Create(filepath.Join(p.LogDir, fmt.Sprintf("job-%d-attempt-%d.log", c.JobID, c.Attempt)))
	if err != nil {
		return err
	}
	args := append(append([]string{}, p.Args...),
		"--server", p.Server, "--startup-token-file", tokenFile, "--work-dir", filepath.Join(jobDir, "work"))
	cmd := exec.Command(p.Runner, args...)
	cmd.Dir = pr.dir
	cmd.Env = p.env()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("oyzu-executor: %w", err)
	}
	pr.cmd, pr.log = cmd, logFile
	go func() {
		pr.err = cmd.Wait()
		close(pr.done)
	}()
	return nil
}

func (p *Process) proc(h Handle) (*proc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.inUse[h.Slot]
	if !ok || pr.dir != h.Ref {
		return nil, fmt.Errorf("no executor %s in slot %s", h.Ref, h.Slot)
	}
	return pr, nil
}

// Wait implements Driver.
func (p *Process) Wait(ctx context.Context, h Handle) (Exit, error) {
	pr, err := p.proc(h)
	if err != nil {
		return Exit{}, err
	}
	select {
	case <-ctx.Done():
		return Exit{}, ctx.Err()
	case <-pr.done:
	}
	if pr.cmd == nil {
		return Exit{Reason: ExitLost, Code: -1, Detail: "the runner never started"}, nil
	}
	return processExit(pr.cmd.ProcessState, pr.err, pr.log.Name()), nil
}

// processExit turns a finished process into an Exit. A process ended by a
// signal it did not ask for (the OOM killer, someone's kill) was lost.
func processExit(ps *os.ProcessState, waitErr error, logName string) Exit {
	detail := "log " + logName
	if ps == nil {
		return Exit{Reason: ExitLost, Code: -1, Detail: fmt.Sprintf("%v (%s)", waitErr, detail)}
	}
	if code := ps.ExitCode(); code >= 0 {
		return Exit{Reason: ExitExited, Code: code, Detail: detail}
	}
	return Exit{Reason: ExitLost, Code: -1, Detail: fmt.Sprintf("%s (%s)", ps, detail)}
}

// Teardown implements Driver. A runner still running is interrupted, given
// StopGrace to report, then killed.
func (p *Process) Teardown(_ context.Context, h Handle) error {
	pr, err := p.proc(h)
	if err != nil {
		return err
	}
	if pr.cmd != nil {
		select {
		case <-pr.done:
		default:
			grace := p.StopGrace
			if grace <= 0 {
				grace = defaultStopGrace
			}
			_ = interrupt(pr.cmd.Process)
			t := time.NewTimer(grace)
			select {
			case <-pr.done:
			case <-t.C:
				_ = pr.cmd.Process.Kill()
				<-pr.done
			}
			t.Stop()
		}
		pr.log.Close()
	}
	err = os.RemoveAll(pr.dir)
	p.mu.Lock()
	delete(p.inUse, h.Slot)
	p.mu.Unlock()
	return err
}

// Reap implements Driver. It removes job directories under this manager's
// directory that belong to no live job and no runner this driver started,
// such as those a crashed manager left. A runner orphaned by such a crash
// is not killed: process IDs are reused, so killing by a recorded ID could
// hit an unrelated process. Its job tokens stop working when its lease
// expires.
func (p *Process) Reap(_ context.Context, live []JobID) error {
	entries, err := os.ReadDir(p.jobsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keepJob := map[JobID]bool{}
	for _, j := range live {
		keepJob[j] = true
	}
	p.mu.Lock()
	keepDir := map[string]bool{}
	for _, pr := range p.inUse {
		keepDir[filepath.Base(pr.dir)] = true
	}
	p.mu.Unlock()
	var errs []error
	for _, e := range entries {
		job, ok := jobOfDir(e.Name())
		if !ok || keepDir[e.Name()] || keepJob[job] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(p.jobsDir(), e.Name())); err != nil {
			errs = append(errs, err)
		} else if p.Log != nil {
			p.Log.Info("reaped a job directory", "dir", e.Name())
		}
	}
	return errors.Join(errs...)
}

// jobOfDir parses the job id from a job-<job>-<attempt>-<suffix> name.
func jobOfDir(name string) (JobID, bool) {
	rest, ok := strings.CutPrefix(name, "job-")
	if !ok {
		return 0, false
	}
	id, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(id, 10, 64)
	return n, err == nil
}

func (p *Process) env() []string {
	environ := p.environ
	if environ == nil {
		environ = os.Environ
	}
	keep := append(append([]string{}, passEnv...), p.ExtraEnv...)
	var out []string
	for _, kv := range environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		for _, k := range keep {
			if strings.EqualFold(name, k) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// interrupt asks a process to stop, or kills it where it cannot be asked.
func interrupt(proc *os.Process) error {
	if err := proc.Signal(os.Interrupt); err != nil {
		return proc.Kill()
	}
	return nil
}
