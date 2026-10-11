// Package kindrunner is the executor half of a kind job (IMPL-376): the job
// runner a pool manager starts runs one deployment kind operation. It pulls
// the run's secrets into a private directory, starts the kind (a built-in
// kind as a host process from the kinds directory, any other kind as its
// pinned image through the host's Docker), writes the request on its
// standard input, streams its events to runs as it writes them, enforces the
// manifest's timeout, turns a cancel into the kind's abort where it has one,
// and finishes with the kind's result, or with why there is none.
package kindrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/oyzuai/fleet/internal/masking"
	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

const (
	// ContainerSecretsDir and ContainerStateDir are where an image kind sees
	// its secrets and its state.
	ContainerSecretsDir = "/run/oyzu/secrets"
	ContainerStateDir   = "/var/lib/oyzu/kind"
	// ContainerPlanFilesDir is where an image kind sees its plan files.
	ContainerPlanFilesDir = "/run/oyzu/plan"
	// maxResult bounds what a kind may write on standard output.
	maxResult = 4 << 20
	// flushEvery and flushAt decide when events are posted.
	flushEvery = time.Second
	flushAt    = 100
	// finishTimeout bounds reporting the result, even on shutdown.
	finishTimeout       = 30 * time.Second
	finalFlushTimeout   = 2 * time.Second
	processDrainTimeout = 2 * time.Second
	maxEventLine        = 1 << 20
	maxPendingBytes     = 4 << 20
	// defaultStopGrace is how long a kind has to exit after SIGTERM.
	defaultStopGrace = 10 * time.Second
)

// ErrLost means runs took the job back; nothing is reported.
var ErrLost = errors.New("runs took the kind job back: the lease ran out or a credential was revoked")

// Config configures one kind job.
type Config struct {
	Client *runnerclient.Client
	// Token is the job token.
	Token          string
	HeartbeatEvery time.Duration
	LeaseExpires   time.Time
	// KindsDir holds the built-in kinds' executables, kind-<name> (kind-<name>.exe on Windows).
	KindsDir string
	// StateDir is where kinds keep state between runs on this host, one
	// directory per kind. It must outlive the job.
	StateDir string
	// SecretsDir is where a private directory for the run's secrets is
	// made; the system temp directory by default. Point it at a tmpfs.
	SecretsDir string
	// Docker is the docker CLI for image kinds; "docker" by default.
	Docker string
	// DockerNetwork is the network image kinds join (docker run --network);
	// Docker's default bridge when empty. A pool whose targets are on the
	// host's loopback, as in a development stack, names "host".
	DockerNetwork string
	// DockerEnv names variables of the runner's own environment that image
	// kinds also get (docker run -e NAME), such as a proxy or, in a
	// development stack, the endpoints of local fakes. A built-in kind sees
	// the runner's whole environment; an image kind only these.
	DockerEnv []string
	// StopGrace is how long a kind has after SIGTERM before it is killed.
	StopGrace time.Duration
	Log       *slog.Logger
}

// Run runs the kind operation of job and reports its result.
func Run(ctx context.Context, cfg Config, job runnerclient.Job) error {
	op := job.KindOperation
	if op == nil {
		return errors.New("not a kind job")
	}
	if cfg.Docker == "" {
		cfg.Docker = "docker"
	}
	if cfg.StopGrace <= 0 {
		cfg.StopGrace = defaultStopGrace
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	log := cfg.Log.With("job", job.ID, "attempt", job.Attempt, "record", op.RecordID,
		"kind", op.Kind.Name+"@"+op.Kind.Version, "operation", op.Operation)
	log.Info("kind job started", "placement", op.Placement)
	r := &run{cfg: cfg, job: job, op: op, log: log, cancel: make(chan struct{})}
	r.events = newUploader(cfg.Client, cfg.Token, log)

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.heartbeat(runCtx, stop) }()
	go func() { defer wg.Done(); r.events.run(runCtx) }()

	result, none := r.execute(runCtx)
	if none != nil {
		none.Message = r.events.mask.String(none.Message)
	}
	stop(nil)
	wg.Wait()
	if errors.Is(context.Cause(runCtx), ErrLost) {
		log.Warn("kind job taken back before it finished")
		return ErrLost
	}
	flushCtx, flushDone := context.WithTimeout(context.WithoutCancel(ctx), finalFlushTimeout)
	r.events.flush(flushCtx)
	flushDone()
	finishCtx, done := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer done()
	if err := retry(finishCtx, func(ctx context.Context) error { return cfg.Client.KindFinish(ctx, cfg.Token, result, none) }); err != nil {
		return fmt.Errorf("report the result: %w", err)
	}
	if none != nil {
		log.Info("kind job finished without a result", "code", none.Code, "detail", none.Message)
	} else {
		log.Info("kind job finished")
	}
	return nil
}

type run struct {
	cfg    Config
	job    runnerclient.Job
	op     *runnerclient.KindOperation
	log    *slog.Logger
	events *uploader

	cancelOnce sync.Once
	cancel     chan struct{}
}

// heartbeat renews the lease, notices a cancel, and stops the run when runs
// refuses the token.
func (r *run) heartbeat(ctx context.Context, stop context.CancelCauseFunc) {
	runnerclient.WatchLease(ctx, r.cfg.HeartbeatEvery, r.cfg.LeaseExpires,
		func(ctx context.Context) (time.Time, error) {
			beat, err := r.cfg.Client.KindHeartbeat(ctx, r.cfg.Token)
			if err == nil && beat.Cancel {
				r.cancelOnce.Do(func() { close(r.cancel) })
			}
			return beat.Expires, err
		},
		func() { r.log.Warn("kind lease expired or refused; stopping the kind"); stop(ErrLost) },
		func(err error) { r.log.Warn("kind job heartbeat failed", "error", err) })
}

// retry gives each attempt a separate deadline inside the reporting budget.
// A refused token is not proof a previous finish landed; return it to the caller.
func retry(ctx context.Context, call func(context.Context) error) error {
	var err error
	for delay := 100 * time.Millisecond; ; delay = min(delay*2, 2*time.Second) {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = call(attempt)
		cancel()
		if err == nil || errors.Is(err, runnerclient.ErrUnauthenticated) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}
}

// execute pulls the secrets, runs the kind and reads its result. It returns
// the result's JSON, or why there is none.
func (r *run) execute(ctx context.Context) (json.RawMessage, *runnerclient.KindNoResult) {
	if !safeName.MatchString(r.op.Kind.Name) {
		return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: "invalid kind name"}
	}
	secrets, err := r.secrets(ctx)
	if err != nil {
		return nil, &runnerclient.KindNoResult{Code: "secrets-unavailable", Message: err.Error()}
	}
	defer secrets.remove()
	req, err := kindprotocol.DecodeRequest(r.op.Request)
	if err != nil {
		return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: "the request is not valid: " + err.Error()}
	}
	plans, err := r.planFiles(ctx, req)
	if err != nil {
		return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: err.Error()}
	}
	defer plans.remove()
	ledger, err := r.ledger(ctx)
	if err != nil {
		return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: err.Error()}
	}
	defer ledger.remove()
	dirs := jobDirs{secrets: secrets, plans: plans, ledger: ledger}
	main, err := r.start(ctx, r.op.Request, dirs, "")
	if err != nil {
		return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: err.Error()}
	}
	timeout := time.NewTimer(time.Duration(r.op.TimeoutSeconds) * time.Second)
	defer timeout.Stop()
	var reason string
	select {
	case <-main.done:
	case <-timeout.C:
		reason = "timed-out"
		r.events.local("warn", fmt.Sprintf("The kind ran past its %d second %s timeout; stopping it.", r.op.TimeoutSeconds, r.op.Operation))
		main.stop(r.cfg.StopGrace)
	case <-r.cancel:
		reason = "cancelled"
		r.abort(ctx, req, dirs, main)
	case <-ctx.Done():
		main.stop(0)
	}
	if !main.wait(3*processDrainTimeout + r.cfg.StopGrace) {
		return nil, &runnerclient.KindNoResult{Code: "crashed", Message: "kind did not stop before the drain deadline", Started: true}
	}
	if r.op.Image != "" {
		var exit *exec.ExitError
		if errors.As(main.exitErr, &exit) && exit.ExitCode() >= 125 && exit.ExitCode() <= 127 {
			return nil, &runnerclient.KindNoResult{Code: "kind-not-started", Message: r.events.mask.String(main.exitErr.Error())}
		}
	}
	r.saveLedger(ctx, ledger)
	res, problem := main.result(req)
	if res != nil {
		if err := r.savePlanFiles(ctx, req, res, plans); err != nil {
			return nil, &runnerclient.KindNoResult{Code: "plan-file-unsaved", Message: err.Error(), Started: true}
		}
		return res, nil
	}
	switch {
	case reason != "":
	case main.exitErr != nil:
		reason = "crashed"
	default:
		reason = "no-result"
	}
	msg := problem
	if main.exitErr != nil {
		msg = fmt.Sprintf("%s (%v)", problem, main.exitErr)
	}
	return nil, &runnerclient.KindNoResult{Code: reason, Message: msg, Started: true}
}

// abort stops a running operation after someone cancelled it: through the
// kind's abort operation where it declares one, then by signal if the
// operation is still running a grace period later.
func (r *run) abort(ctx context.Context, req *kindprotocol.Request, dirs jobDirs, main *process) {
	if r.op.AbortTimeoutSeconds <= 0 || req.Operation == kindprotocol.OpAbort {
		r.events.local("info", "Cancelled; the kind has no abort operation, so it is being stopped.")
		main.stop(r.cfg.StopGrace)
		return
	}
	r.events.local("info", "Cancelled; running the kind's abort operation.")
	ab := *req
	ab.Operation = kindprotocol.OpAbort
	ab.ApprovedPlan, ab.TrafficPercent, ab.RollbackTo, ab.Verification = nil, nil, nil, nil
	raw, err := json.Marshal(&ab)
	if err == nil {
		_, err = kindprotocol.DecodeRequest(raw)
	}
	if err == nil {
		var p *process
		if p, err = r.start(ctx, raw, dirs, "abort"); err == nil {
			t := time.NewTimer(time.Duration(r.op.AbortTimeoutSeconds) * time.Second)
			select {
			case <-p.done:
			case <-t.C:
				p.stop(r.cfg.StopGrace)
			case <-ctx.Done():
				main.stop(0)
				p.stop(0)
			}
			t.Stop()
			if !p.wait(3 * processDrainTimeout) {
				main.stop(0)
				return
			}
			if res, problem := p.result(&ab); res != nil {
				var out kindprotocol.Result
				_ = json.Unmarshal(res, &out)
				r.events.local("info", "The abort operation finished: "+string(out.Outcome)+".")
			} else {
				r.events.local("warn", "The abort operation gave no result: "+problem)
			}
		}
	}
	if err != nil {
		r.events.local("warn", "The abort operation could not start: "+err.Error())
	}
	select {
	case <-main.done:
	case <-ctx.Done():
		main.stop(0)
	case <-time.After(r.cfg.StopGrace):
		main.stop(r.cfg.StopGrace)
	}
}

// process is one running kind process.
type process struct {
	group   *processGroup
	cmd     *exec.Cmd
	stdout  *limitedBuffer
	done    chan struct{}
	exitErr error
	cleanup func()
}

// stop signals the whole process group and kills it after the grace period.
func (p *process) stop(grace time.Duration) {
	p.group.terminate()
	p.wait(grace)
	p.group.kill()
}

func (p *process) wait(timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return true
	case <-timer.C:
		return false
	}
}

// result reads the process's standard output as the result for req. The
// exit code does not matter; the result decides (IMPL-336).
func (p *process) result(req *kindprotocol.Request) (json.RawMessage, string) {
	if p.stdout.over {
		return nil, fmt.Sprintf("the kind wrote more than %d bytes on standard output", maxResult)
	}
	out := bytes.TrimSpace(p.stdout.b.Bytes())
	if len(out) == 0 {
		return nil, "the kind wrote no result"
	}
	res, err := kindprotocol.DecodeResult(out)
	if err != nil {
		return nil, "the kind's result is not valid: " + err.Error()
	}
	if res.Operation != req.Operation || res.ExecutionID != req.ExecutionID {
		return nil, fmt.Sprintf("the kind answered %s (%s), not %s (%s)", res.Operation, res.ExecutionID, req.Operation, req.ExecutionID)
	}
	return out, ""
}

var imagePinned = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// jobDirs are the private directories a job gives its kind, each nil when
// the job has none.
type jobDirs struct {
	secrets *secretDir
	plans   *planDir
	ledger  *ledgerDir
}

// start starts the kind with request on its standard input. label marks the
// events of a second process, such as an abort.
func (r *run) start(ctx context.Context, request []byte, dirs jobDirs, label string) (*process, error) {
	secrets, plans, ledger := dirs.secrets, dirs.plans, dirs.ledger
	name := r.op.Kind.Name
	if !safeName.MatchString(name) {
		return nil, fmt.Errorf("invalid kind name %q", name)
	}
	stateDir := filepath.Join(r.cfg.StateDir, name)
	if rel, err := filepath.Rel(r.cfg.StateDir, stateDir); err != nil || rel != name {
		return nil, errors.New("kind state directory escapes its root")
	}
	if r.cfg.StateDir == "" {
		return nil, errors.New("the runner has no kind state directory")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("make the kind's state directory: %w", err)
	}
	var cmd *exec.Cmd
	cleanup := func() {}
	if r.op.Image == "" {
		file := "kind-" + name
		if runtime.GOOS == "windows" {
			file += ".exe"
		}
		path := filepath.Join(r.cfg.KindsDir, file)
		if r.cfg.KindsDir == "" || !safeName.MatchString(name) {
			return nil, fmt.Errorf("built-in kind %q is not installed on this pool", name)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("built-in kind %q is not installed on this pool: %w", name, err)
		}
		cmd = exec.Command(path)
		cmd.Env = append(os.Environ(), "OYZU_KIND_STATE_DIR="+stateDir)
		if secrets != nil {
			cmd.Env = append(append(secrets.scrub(cmd.Env), "OYZU_SECRETS_DIR="+secrets.path), secrets.vars(secrets.path)...)
		}
		if plans != nil {
			cmd.Env = append(cmd.Env, "OYZU_PLAN_FILES_DIR="+plans.path)
		}
		if ledger != nil {
			cmd.Env = append(cmd.Env, "OYZU_KIND_LEDGER_DIR="+ledger.path)
		}
	} else {
		if !imagePinned.MatchString(r.op.Image) {
			return nil, fmt.Errorf("kind image %q is not pinned by digest", r.op.Image)
		}
		pullCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		inspect := exec.CommandContext(pullCtx, r.cfg.Docker, "image", "inspect", r.op.Image)
		inspect.WaitDelay = processDrainTimeout
		if err := inspect.Run(); err != nil {
			pull := exec.CommandContext(pullCtx, r.cfg.Docker, "pull", r.op.Image)
			pull.WaitDelay = processDrainTimeout
			if err := pull.Run(); err != nil {
				cancel()
				return nil, fmt.Errorf("prepare kind image: %w", err)
			}
		}
		cancel()
		container := fmt.Sprintf("oyzu-kind-%d-%d", r.job.ID, r.job.Attempt)
		if label != "" {
			container += "-" + label
		}
		args := []string{"run", "--rm", "-i", "--name", container, "--pull", "missing",
			"--label", "oyzu.kind.job=" + strconv.FormatInt(r.job.ID, 10),
			"--label", "oyzu.kind.attempt=" + strconv.Itoa(r.job.Attempt),
			"--label", "oyzu.kind.runner=" + filepath.Dir(r.cfg.SecretsDir),
			"--label", "oyzu.kind.manager=" + filepath.Dir(filepath.Dir(r.cfg.SecretsDir)),
			"-e", "OYZU_KIND_STATE_DIR=" + ContainerStateDir, "-v", stateDir + ":" + ContainerStateDir}
		// The kind runs as the runner's own user, so it can write the
		// directories the runner made for it (0700, the runner's) and what
		// it leaves there stays the runner's to read and remove.
		if uid, gid := os.Getuid(), os.Getgid(); uid >= 0 && gid >= 0 {
			args = append(args, "--user", strconv.Itoa(uid)+":"+strconv.Itoa(gid))
		}
		if secrets != nil {
			args = append(args, "-e", "OYZU_SECRETS_DIR="+ContainerSecretsDir, "-v", secrets.path+":"+ContainerSecretsDir+":ro")
			for _, v := range secrets.vars(ContainerSecretsDir) {
				args = append(args, "-e", v)
			}
		}
		if plans != nil {
			args = append(args, "-e", "OYZU_PLAN_FILES_DIR="+ContainerPlanFilesDir, "-v", plans.path+":"+ContainerPlanFilesDir)
		}
		if ledger != nil {
			args = append(args, "-e", "OYZU_KIND_LEDGER_DIR="+ContainerLedgerDir, "-v", ledger.path+":"+ContainerLedgerDir)
		}
		if r.cfg.DockerNetwork != "" {
			args = append(args, "--network", r.cfg.DockerNetwork)
		}
		for _, name := range r.cfg.DockerEnv {
			if _, ok := os.LookupEnv(name); ok && envName.MatchString(name) {
				args = append(args, "-e", name)
			}
		}
		cmd = exec.Command(r.cfg.Docker, append(args, r.op.Image)...)
		cleanup = func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), processDrainTimeout)
			defer cancel()
			_ = exec.CommandContext(ctx, r.cfg.Docker, "rm", "-f", container).Run()
		}
	}
	p := &process{cmd: cmd, stdout: &limitedBuffer{max: maxResult}, done: make(chan struct{}), cleanup: cleanup}
	cmd.Stdin = bytes.NewReader(request)
	cmd.Stdout = p.stdout
	stderr := &eventWriter{run: r, label: label}
	cmd.Stderr = stderr
	cmd.WaitDelay = processDrainTimeout
	prepareProcess(cmd)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start kind %s: %w", name, err)
	}
	group, err := attachProcess(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cleanup()
		return nil, err
	}
	p.group = group
	go func() {
		p.exitErr = cmd.Wait()
		stderr.finish()
		p.group.close()
		p.cleanup()
		close(p.done)
	}()
	return p, nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// readEvents turns the kind's standard error into events: a line that is a
// valid event is kept as one, anything else as a log line (IMPL-336).
func (r *run) readEvents(stderr io.Reader, label string) {
	w := &eventWriter{run: r, label: label}
	_, _ = io.Copy(w, stderr)
	w.finish()
}

// eventWriter drains every byte. Lines over 1 MiB are dropped as a whole,
// so a truncated secret or JSON document is never emitted as a log line.
type eventWriter struct {
	run     *run
	label   string
	line    []byte
	dropped int
}

func (w *eventWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		line, rest, found := bytes.Cut(p, []byte{'\n'})
		if w.dropped > 0 || len(w.line)+len(line) > maxEventLine {
			w.dropped += len(w.line) + len(line)
			w.line = nil
		} else {
			w.line = append(w.line, line...)
		}
		if !found {
			break
		}
		w.finish()
		p = rest
	}
	return n, nil
}

func (w *eventWriter) finish() {
	if w.dropped > 0 {
		w.run.events.local("warn", fmt.Sprintf("dropped %d bytes from an oversized stderr line (limit 1 MiB)", w.dropped))
	} else {
		w.run.event(w.line, w.label)
	}
	w.line = nil
	w.dropped = 0
}

func (r *run) event(raw []byte, label string) {
	line := bytes.TrimSpace(raw)
	if len(line) == 0 {
		return
	}
	prefix := ""
	if label != "" {
		prefix = label + ": "
	}
	if line[0] == '{' {
		if ev, err := kindprotocol.DecodeEvent(line); err == nil {
			r.events.add(runnerclient.KindEvent{Time: ev.Time, Type: ev.Event.Type, Level: ev.Event.Level,
				Message: prefixed(prefix, ev.Event.Message), Percent: ev.Event.Percent, Observed: ev.Event.Observed})
			return
		}
	}
	r.events.add(runnerclient.KindEvent{Time: time.Now().UTC(), Type: "log", Level: "info", Message: prefix + string(line)})
}
func prefixed(prefix, msg string) string {
	if msg == "" {
		return ""
	}
	return prefix + msg
}

// secretDir is a private directory holding one file per secret and the
// target's connectors, with the variables that point a kind at them.
type secretDir struct {
	path string
	// env are variables the kind receives; unset are variables a built-in
	// kind must not inherit from the runner.
	env   []envVar
	unset []string
}

func (s *secretDir) remove() {
	if s != nil {
		_ = os.RemoveAll(s.path)
	}
}

// secrets pulls the run's secrets into a private directory, one file named
// after each secret, readable only by this user, and the target's connectors
// beside them. Nil when there are none.
func (r *run) secrets(ctx context.Context) (*secretDir, error) {
	if len(r.op.Secrets) == 0 && len(r.op.Connectors) == 0 {
		return nil, nil
	}
	var released []runnerclient.KindSecret
	if len(r.op.Secrets) > 0 {
		var err error
		if released, err = r.cfg.Client.KindSecrets(ctx, r.cfg.Token); err != nil {
			return nil, fmt.Errorf("pull the run's secrets: %w", err)
		}
	}
	defer func() {
		for _, s := range released {
			clear(s.Value)
		}
	}()
	dir, err := os.MkdirTemp(r.cfg.SecretsDir, "oyzu-kind-secrets-")
	if err != nil {
		return nil, err
	}
	sd := &secretDir{path: dir}
	for _, s := range released {
		r.events.mask.Add(string(s.Value))
		if !secretName.MatchString(s.Name) {
			sd.remove()
			return nil, fmt.Errorf("secret name %q is not a file name", s.Name)
		}
		if err := os.WriteFile(filepath.Join(dir, s.Name), s.Value, 0o400); err != nil {
			sd.remove()
			return nil, err
		}
	}
	if len(r.op.Connectors) > 0 {
		if err := r.connectors(ctx, sd); err != nil {
			sd.remove()
			return nil, err
		}
	}
	return sd, nil
}

var secretName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// uploader numbers events and posts them in batches.
type uploader struct {
	mask         *masking.Writer
	bytes        int
	dropped      int
	droppedBytes int
	client       *runnerclient.Client
	token        string
	log          *slog.Logger

	mu      sync.Mutex
	next    int
	pending []runnerclient.KindEvent
	kick    chan struct{}
}

func newUploader(c *runnerclient.Client, token string, log *slog.Logger) *uploader {
	return &uploader{mask: masking.NewWriter(io.Discard, masking.Forms(token)), client: c, token: token, log: log, kick: make(chan struct{}, 1)}
}

func (u *uploader) add(e runnerclient.KindEvent) {
	// Mask the JSON too: observed state can contain credential-bearing messages.
	raw, _ := json.Marshal(e)
	masked := u.mask.String(string(raw))
	if err := json.Unmarshal([]byte(masked), &e); err != nil {
		return
	}
	u.mu.Lock()
	e.N = u.next
	raw, _ = json.Marshal(e)
	if len(raw) > maxPendingBytes-u.bytes {
		u.dropped++
		u.droppedBytes += len(raw)
		u.mu.Unlock()
		return
	}
	u.bytes += len(raw)
	u.next++
	u.pending = append(u.pending, e)
	n := len(u.pending)
	u.mu.Unlock()
	if n >= flushAt || e.Type == "progress" {
		select {
		case u.kick <- struct{}{}:
		default:
		}
	}
}

// local adds an event the runner itself writes, about the kind.
func (u *uploader) local(level, msg string) {
	u.add(runnerclient.KindEvent{Time: time.Now().UTC(), Type: "log", Level: level, Message: "runner: " + msg})
}

func (u *uploader) run(ctx context.Context) {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-u.kick:
		}
		u.flush(ctx)
	}
}

// flush posts what is pending. A failed post keeps the events for the next.
func (u *uploader) flush(ctx context.Context) {
	for {
		u.mu.Lock()
		if u.dropped > 0 && u.bytes < maxPendingBytes-512 {
			marker := runnerclient.KindEvent{N: u.next, Time: time.Now().UTC(), Type: "log", Level: "warn",
				Message: fmt.Sprintf("runner: dropped %d events/%d bytes while the event queue was full", u.dropped, u.droppedBytes)}
			u.next++
			u.pending = append(u.pending, marker)
			raw, _ := json.Marshal(marker)
			u.bytes += len(raw)
			u.dropped, u.droppedBytes = 0, 0
		}
		batch := append([]runnerclient.KindEvent(nil), u.pending[:min(len(u.pending), flushAt*5)]...)
		u.mu.Unlock()
		if len(batch) == 0 {
			return
		}
		if err := u.client.KindEvents(ctx, u.token, batch); err != nil {
			u.log.Warn("posting kind events failed", "error", err, "pending", strconv.Itoa(len(batch)))
			return
		}
		u.mu.Lock()
		clear(u.pending[:len(batch)])
		u.pending = u.pending[len(batch):]
		u.bytes = 0
		for _, e := range u.pending {
			raw, _ := json.Marshal(e)
			u.bytes += len(raw)
		}
		u.mu.Unlock()
	}
}

// limitedBuffer keeps at most max bytes and notes whether more came.
type limitedBuffer struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room < len(p) {
		l.over = true
		l.b.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return l.b.Write(p)
}

// DefaultStateDir is where kinds keep state when the pool names no
// directory.
func DefaultStateDir() string {
	if base, err := os.UserCacheDir(); err == nil {
		return filepath.Join(base, "oyzu", "kinds")
	}
	return filepath.Join(os.TempDir(), "oyzu-kinds")
}
