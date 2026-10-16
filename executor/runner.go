// Package executor runs one job: it spends the startup token its manager
// mounted as a file, fetches the commit with a read-only token for that one
// repository, runs the binding's oyzu command, heartbeats while it runs and
// reports the outcome. It holds only job-scoped credentials, in memory, and
// never passes them to the build.
package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/oyzuai/fleet/kindrunner"
	"github.com/oyzuai/fleet/runnerclient"
)

const (
	// summaryLines is how much of the end of the output the check run shows.
	summaryLines = 60
	// finishTimeout bounds reporting after the build, even on shutdown.
	finishTimeout = 30 * time.Second
)

// Config configures one run.
type Config struct {
	Client *runnerclient.Client
	// StartupTokenFile is read once and deleted.
	StartupTokenFile string
	// StartupTokenEnv, used when StartupTokenFile is empty, names an
	// environment variable holding the token, for executors whose files are
	// read-only (a Kubernetes Secret). It is read once and unset, so no
	// child process inherits it.
	StartupTokenEnv string
	// WorkDir is where the source is checked out; it must not exist or be empty.
	WorkDir string
	// SecretsDir is where the job's file secrets are written, in a private
	// directory removed when the job ends; the system temp directory by
	// default. Point it at a tmpfs so they never reach a disk.
	SecretsDir string
	// JobDir is the owner directory the process manager reaps for kind jobs.
	JobDir string
	// GitURL is the Git host, https://github.com by default.
	GitURL string
	// Git and Oyzu are the executables; "git" and "oyzu" on PATH by default.
	Git  string
	Oyzu string
	// Renovate is the Renovate executable; renovate jobs fail without one.
	Renovate string
	// GitHubAPI is the Git host's REST API, for Renovate;
	// https://api.github.com by default.
	GitHubAPI string
	// GitAuthor is who lock fix commits are by, "Name <email>";
	// DefaultGitAuthor when empty.
	GitAuthor string
	// KindsDir holds the built-in deployment kinds, kind-<name>, and
	// KindStateDir is where kinds keep state between jobs on this host; both
	// only for kind jobs. Docker is the docker CLI image kinds run with.
	KindsDir     string
	KindStateDir string
	Docker       string
	// DockerNetwork is the network image kinds join; see
	// kindrunner.Config.DockerNetwork.
	DockerNetwork string
	// DockerEnv names runner variables image kinds also get; see
	// kindrunner.Config.DockerEnv.
	DockerEnv []string
	// EgressGateway is the pool's egress gateway proxy URL on this job's
	// network (OYZU_EGRESS_GATEWAY). When set, the job waits until the
	// gateway knows it, the credential proxy always starts and chains
	// through the gateway, and blocked destinations are logged and listed in
	// the summary.
	EgressGateway string
	Log           *slog.Logger
	// LogDrainTimeout bounds delivery after job finish; zero is 15 minutes.
	// The pre-outcome wait is the smaller of this value and 30 seconds.
	LogDrainTimeout time.Duration
}

// Run reports the outcome, then drains any pending logs before returning.
// It also returns when runs says the job is no longer this runner's.
func Run(ctx context.Context, cfg Config) error {
	if cfg.GitURL == "" {
		cfg.GitURL = "https://github.com"
	}
	if cfg.Git == "" {
		cfg.Git = "git"
	}
	if cfg.Oyzu == "" {
		cfg.Oyzu = "oyzu"
	}
	if cfg.GitHubAPI == "" {
		cfg.GitHubAPI = "https://api.github.com"
	}
	if cfg.GitAuthor == "" {
		cfg.GitAuthor = DefaultGitAuthor
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	var startup string
	var err error
	if cfg.StartupTokenFile != "" {
		startup, err = readOnce(cfg.StartupTokenFile)
	} else {
		startup, err = readEnvOnce(cfg.StartupTokenEnv)
	}
	if err != nil {
		return err
	}
	if cfg.EgressGateway != "" {
		if err := waitGateway(ctx, cfg.EgressGateway); err != nil {
			return err
		}
	}
	st, err := cfg.Client.Start(ctx, startup)
	if err != nil {
		return fmt.Errorf("start the job: %w", err)
	}
	job := st.Job
	if job.Kind == runnerclient.KindOperationJob {
		return kindrunner.Run(ctx, kindrunner.Config{
			Client: cfg.Client, Token: st.JobToken, LeaseExpires: st.Expires, HeartbeatEvery: time.Duration(st.HeartbeatSeconds) * time.Second,
			KindsDir: cfg.KindsDir, StateDir: cfg.KindStateDir, SecretsDir: cfg.SecretsDir, Owner: cfg.JobDir, Docker: cfg.Docker, DockerNetwork: cfg.DockerNetwork, DockerEnv: cfg.DockerEnv, Log: cfg.Log,
		}, job)
	}
	log := cfg.Log.With("job", job.ID, "attempt", job.Attempt, "correlation_id", job.CorrelationID)
	log.Info("job started", "repository", job.Repository, "sha", job.HeadSHA, "command", strings.Join(job.Command, " "))

	// The build runs under a context that ends when runs takes the job back.
	buildCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	every := time.Duration(st.HeartbeatSeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		heartbeat(buildCtx, cfg.Client, st.JobToken, every, cancel, log, st.Expires)
	}()

	completion := nativeCompletion{}
	outcome, capture := execute(buildCtx, cfg, st.JobToken, startup, job, log, &completion)
	drain := cfg.LogDrainTimeout
	if drain <= 0 || drain > logDrainWindow {
		drain = logDrainWindow
	}
	if capture != nil {
		defer capture.cleanup()
		capture.wait(min(logOutcomeWait, drain))
	}
	cancel(nil)
	wg.Wait()
	if errors.Is(context.Cause(buildCtx), errLost) {
		return errLost
	}
	if errors.Is(context.Cause(buildCtx), errCancelRequested) {
		outcome = cancellationOutcome(outcome, completion.confirmed)
	}
	if ctx.Err() != nil && outcome.State != "succeeded" && !errors.Is(context.Cause(buildCtx), errCancelRequested) {
		outcome = runnerclient.Outcome{State: "cancelled", Summary: "The runner was stopped before the job finished."}
	}
	finishCtx, done := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer done()
	if err := cfg.Client.Finish(finishCtx, st.JobToken, outcome); err != nil {
		var conflict *runnerclient.StatusError
		if outcome.State != "succeeded" || !errors.As(err, &conflict) || conflict.Status != http.StatusConflict {
			return fmt.Errorf("report the outcome: %w", err)
		}
		// Cancellation can win after native success but before Finish commits.
		// Recheck the existing directive, then acknowledge only locally proven
		// current-invocation completion; never infer stop from the 409 itself.
		_, requested, beatErr := cfg.Client.HeartbeatStatus(finishCtx, st.JobToken)
		if beatErr != nil || !requested {
			return fmt.Errorf("report the outcome: %w", err)
		}
		outcome = cancellationOutcome(outcome, completion.confirmed)
		if err := cfg.Client.Finish(finishCtx, st.JobToken, outcome); err != nil {
			return fmt.Errorf("report the stopped outcome: %w", err)
		}
	}
	log.Info("job finished", "state", outcome.State)
	// The server's log-only token window starts at job finish. Keep the
	// original token and spool alive while the uploader drains that window.
	if capture != nil && !capture.wait(drain) {
		log.Warn("log drain window expired; log remains incomplete")
	}
	return nil
}

var errLost = errors.New("runs took the job back: the lease ran out or a credential was revoked")
var errCancelRequested = errors.New("runs requested cancellation; awaiting native stop confirmation")

func heartbeat(ctx context.Context, c *runnerclient.Client, token string, every time.Duration, cancel context.CancelCauseFunc, log *slog.Logger, expires time.Time) {
	runnerclient.WatchLease(ctx, every, expires,
		func(ctx context.Context) (time.Time, error) {
			expires, requested, err := c.HeartbeatStatus(ctx, token)
			if err == nil && requested {
				cancel(errCancelRequested)
			}
			return expires, err
		},
		func() { log.Warn("lease expired or refused; stopping the build"); cancel(errLost) },
		func(err error) { log.Warn("heartbeat failed", "error", err) })
}

// readOnce reads the startup token and deletes the file, so nothing started
// later in the job can find it.
func readOnce(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the startup token: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("delete the startup token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("the startup token file is empty")
	}
	return tok, nil
}

func readEnvOnce(name string) (string, error) {
	if name == "" {
		return "", errors.New("no startup token file or variable")
	}
	tok := strings.TrimSpace(os.Getenv(name))
	if err := os.Unsetenv(name); err != nil {
		return "", fmt.Errorf("unset the startup token variable: %w", err)
	}
	if tok == "" {
		return "", fmt.Errorf("the startup token variable %s is empty", name)
	}
	return tok, nil
}

var (
	shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// repoPattern is a GitHub owner/name, which cannot climb out of the URL.
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
)

// execute runs the job by its operation, and says how it went.
func execute(ctx context.Context, cfg Config, token, startup string, job runnerclient.Job, log *slog.Logger, completion *nativeCompletion) (runnerclient.Outcome, *logCapture) {
	if job.Kind == "slice" && job.Operation != "build" {
		return failedWith("PLAN_MISMATCH", "An admitted slice must execute its assigned native build."), nil
	}
	switch job.Operation {
	case "renovate":
		return renovate(ctx, cfg, token, startup, job, log), nil
	case "lock":
		return lockFix(ctx, cfg, token, startup, job, log), nil
	}
	return build(ctx, cfg, token, startup, job, log, completion)
}

// build checks out the commit and runs the oyzu command.
func build(ctx context.Context, cfg Config, token, startup string, job runnerclient.Job, log *slog.Logger, completion *nativeCompletion) (outcome runnerclient.Outcome, capture *logCapture) {
	_, name, _ := strings.Cut(job.Repository, "/")
	if !shaPattern.MatchString(job.HeadSHA) || !repoPattern.MatchString(job.Repository) || strings.Trim(name, ".") == "" ||
		(job.AffectedBase != "" && !shaPattern.MatchString(job.AffectedBase)) {
		return failedWith("INVALID_JOB", "The job names an invalid repository or commit."), nil
	}
	if len(job.Command) < 2 || job.Command[0] != "oyzu" {
		return failedWith("INVALID_JOB", "The job's command is not an oyzu command."), nil
	}
	var input []byte
	if job.Kind == "slice" {
		var err error
		input, err = sliceInput(cfg.WorkDir, job)
		if err != nil {
			return failedWith("PLAN_MISMATCH", err.Error()), nil
		}
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return failed("Could not create the work directory: " + err.Error()), nil
	}
	src, err := cfg.Client.Source(ctx, token)
	if err != nil {
		return failedWith("SOURCE_UNAVAILABLE", "Could not get a token to read the repository: "+err.Error()), nil
	}
	secrets := []string{token, startup, src.Token, "x-access-token:" + src.Token}
	forms := maskForms(secrets...)
	capture = newLogCapture(ctx, cfg, token, job, log)
	capture.system("Checking out source.\n", &runnerclient.LogEvent{Kind: "task", State: "running"})
	started := time.Now()
	defer func() {
		duration := time.Since(started).Milliseconds()
		capture.system("Job command finished.\n", &runnerclient.LogEvent{Kind: "finished", Status: outcome.State, ExitCode: outcome.ExitCode, DurationMS: &duration})
		capture.finish()
	}()
	if err := checkout(ctx, cfg, src.Token, job); err != nil {
		msg := replaceForms(err.Error(), forms)
		log.Warn("checkout failed", "error", msg)
		return failedWith("SOURCE_UNAVAILABLE", "Could not check out "+job.HeadSHA+": "+msg), capture
	}
	if job.Operation == "run" {
		declared, err := declaresTask(filepath.Join(cfg.WorkDir, "oyzu.toml"), job.Task)
		if err != nil {
			return failedWith("RUNNER_ERROR", "Could not read `oyzu.toml` at "+job.HeadSHA+": "+err.Error()), capture
		}
		if !declared {
			return runnerclient.Outcome{State: "skipped", Summary: fmt.Sprintf("`oyzu.toml` at `%s` declares no task `%s`.", job.HeadSHA, job.Task)}, capture
		}
	}

	// Build output goes into the masked tail and log spool, never to the runner's own
	// stdout: that is the pool host's log, which is for admins and must not
	// carry what a build printed. A plan's stdout is the plan record, kept
	// whole up to its limit and sent to runs, which reads it.
	var out tail
	var record bytes.Buffer
	outSink := &logSink{dst: &out, capture: capture, stream: "stdout"}
	errSink := &logSink{dst: &out, capture: capture, stream: "stderr"}
	stdout, stderr := newMaskWriter(outSink, forms), newMaskWriter(errSink, forms)
	if job.Kind == "plan" {
		outSink.dst = &capped{w: &record, n: runnerclient.MaxPlanRecord + 1}
	}
	defer func() {
		_, _ = stdout.Flush(), stderr.Flush()
		outSink.close()
		errSink.close()
	}()
	env := buildEnv(os.Environ())
	if job.Kind != "plan" && len(job.Secrets) > 0 {
		secretEnv, cleanup, err := pullSecrets(ctx, cfg, token, job.Secrets, func(v string) {
			stdout.Add(v)
			stderr.Add(v)
		})
		defer cleanup()
		if err != nil {
			msg := replaceForms(err.Error(), forms)
			log.Warn("build secrets not delivered", "error", msg)
			return failed("Could not get the job's build secrets: " + msg), capture
		}
		env = withEnv(env, secretEnv)
	}
	var proxy *egressProxy
	// A plan runs without credentials: no ID token, no egress.
	if job.Kind != "plan" {
		broker, err := startIDBroker(cfg.Client, token, func(idToken string) {
			stdout.Add(idToken)
			stderr.Add(idToken)
		})
		if err != nil {
			return failed("Could not start the ID token endpoint: " + err.Error()), capture
		}
		defer broker.stop()
		stdout.Add(broker.secret)
		stderr.Add(broker.secret)
		env = append(env, broker.env()...)
		egress, err := cfg.Client.Egress(ctx, token)
		if err != nil {
			return failed("Could not get the job's egress grants: " + err.Error()), capture
		}
		if len(egress.Grants) > 0 || cfg.EgressGateway != "" {
			proxy, err = startEgress(egress, func(ctx context.Context) (runnerclient.Egress, error) {
				return cfg.Client.Egress(ctx, token)
			}, func(values ...string) {
				stdout.Add(values...)
				stderr.Add(values...)
			}, log, cfg.EgressGateway)
			if err != nil {
				return failed("Could not start the egress proxy: " + err.Error()), capture
			}
			defer proxy.stop()
			env = proxy.env(env)
		}
	}
	var denials *denialWatcher
	if cfg.EgressGateway != "" {
		denials = newDenialWatcher(cfg.EgressGateway, func(line string) { capture.system(line, nil) }, log)
		watchCtx, stopWatching := context.WithCancel(ctx)
		defer stopWatching()
		go denials.run(watchCtx)
	}
	args := append([]string{}, job.Command[1:]...)
	if job.Kind == "slice" {
		args = []string{"__oyzu-build-worker", "execute"}
	} else if job.Kind != "plan" && (job.Operation == "build" || job.Operation == "run") && !slices.Contains(args, "--json") {
		args = append([]string{"--json"}, args...)
	}
	capture.system("Starting oyzu.\n", &runnerclient.LogEvent{Kind: "task", State: "running"})
	var interruptedAt atomic.Int64
	var forced atomic.Bool
	runNative := func(arguments []string, request []byte, output io.Writer) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, cfg.Oyzu, arguments...)
		cmd.Dir, cmd.Env = cfg.WorkDir, env
		if request != nil {
			cmd.Stdin = bytes.NewReader(request)
		}
		cmd.Stdout, cmd.Stderr = output, stderr
		cmd.Cancel = func() error {
			interruptedAt.Store(time.Now().UnixNano())
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				err := cmd.Process.Kill()
				forced.Store(err == nil)
				return err
			}
			return nil
		}
		cmd.WaitDelay = 20 * time.Second
		return cmd, cmd.Run()
	}
	previous := nativeCompletionRecord(cfg.WorkDir)
	cmd, err := runNative(args, input, stdout)
	var retainedOutputs []runnerclient.Output
	var retainedCompletion []byte
	transferFailed, retryRecordInvalid := false, false
	executionWaited := cmd.ProcessState != nil && cmd.ProcessState.Exited() && !forced.Load()
	// Transfer recovery stays inside this live assignment and its lease. Never
	// check out source again, repeat native preparation, or request a new attempt
	// merely because the completed immutable contribution could not be uploaded.
	if job.Kind == "slice" && ctx.Err() == nil && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 5 {
		capture.system("Retrying retained build contribution upload; native commands will not run again.\n", nil)
		root, rootErr := filepath.Abs(filepath.Join(cfg.WorkDir, filepath.Dir(ManifestPath)))
		if rootErr != nil {
			return failedWith("RUNNER_ERROR", "Retained contribution directory is unavailable: "+rootErr.Error()), capture
		}
		request, _ := json.Marshal(struct {
			Root    string `json:"root"`
			Handoff string `json:"handoff"`
		}{root, job.Handoff})
		var result bytes.Buffer
		cmd, err = runNative([]string{"__oyzu-build-worker", "retry-handoff"}, request,
			io.MultiWriter(stdout, &capped{w: &result, n: maxManifest + 1}))
		transferFailed = err != nil
		if err == nil {
			retainedOutputs, err = retainedHandoffOutputs(result.Bytes())
			retryRecordInvalid = err != nil
			if err == nil && executionWaited {
				retainedCompletion = retainedNativeCompletion(nativeCompletionRecord(cfg.WorkDir), result.Bytes())
			}
		}
	}
	// A signal/WaitDelay-killed CLI is not proof that its native children
	// cleaned up. Only a normal wait plus its fresh finalized native record
	// can acknowledge stopping this build invocation.
	stopWithinGrace := interruptedAt.Load() == 0 || time.Since(time.Unix(0, interruptedAt.Load())) < cmd.WaitDelay
	if job.Operation == "build" && cmd.ProcessState != nil && cmd.ProcessState.Exited() && !forced.Load() && stopWithinGrace {
		current := nativeCompletionRecord(cfg.WorkDir)
		if retainedCompletion != nil {
			current = retainedCompletion
		}
		completion.confirmed = freshNativeCompletion(previous, current)
	}
	_, _ = stdout.Flush(), stderr.Flush()
	outSink.close()
	errSink.close()
	if cmd.ProcessState == nil {
		return failed("Could not run oyzu: " + err.Error()), capture
	}
	code := cmd.ProcessState.ExitCode()
	summary := fmt.Sprintf("`%s` on `%s` exited %d.\n\n```text\n%s\n```", strings.Join(job.Command, " "), job.HeadSHA, code, out.String())
	if err != nil && code == 0 {
		summary += "\n\nCompleted contribution validation failed: " + replaceForms(err.Error(), forms)
	}
	if proxy != nil {
		if r := proxy.report(); r != "" {
			summary += "\n\n" + r
		}
	}
	if denials != nil {
		// One last read, so a request made just before the build ended is
		// in the summary.
		pollCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		denials.poll(pollCtx)
		done()
		if r := denials.report(); r != "" {
			summary += "\n\n" + r
		}
	}
	switch {
	case err == nil && job.Kind == "plan":
		rec := bytes.TrimSpace(record.Bytes())
		if len(rec) > runnerclient.MaxPlanRecord || !json.Valid(rec) {
			return runnerclient.Outcome{State: "failed", ExitCode: &code,
				Summary: fmt.Sprintf("`%s` on `%s` printed no readable plan.\n\n```text\n%s\n```", strings.Join(job.Command, " "), job.HeadSHA, out.String())}, capture
		}
		return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: summary, Plan: rec}, capture
	case err == nil && job.Operation == "build":
		// What the build made is published by runs (IMPL-450); a manifest
		// runs cannot read publishes nothing but fails nothing either.
		outputs, oerr := retainedOutputs, error(nil)
		if outputs == nil {
			outputs, oerr = readOutputs(cfg.WorkDir)
		}
		if oerr != nil {
			log.Warn("build manifest not read", "error", oerr)
			summary += "\n\nNothing from this build is published: " + replaceForms(oerr.Error(), forms)
		}
		return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: summary, Outputs: outputs}, capture
	case err == nil:
		return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: summary}, capture
	case ctx.Err() != nil:
		if errors.Is(context.Cause(ctx), errCancelRequested) {
			return cancellationOutcome(runnerclient.Outcome{State: "failed", ExitCode: &code, Summary: summary}, completion.confirmed), capture
		}
		return runnerclient.Outcome{State: "cancelled", Summary: summary}, capture
	}
	if retryRecordInvalid {
		return runnerclient.Outcome{State: "failed", ExitCode: &code, ReasonCode: "RUNNER_ERROR", Summary: summary}, capture
	}
	if transferFailed {
		return runnerclient.Outcome{State: "failed", ExitCode: &code, ReasonCode: "HANDOFF_PUSH_FAILED", Summary: summary}, capture
	}
	return runnerclient.Outcome{State: "failed", ExitCode: &code, Summary: summary}, capture
}

type nativeCompletion struct{ confirmed bool }

func cancellationOutcome(previous runnerclient.Outcome, confirmed bool) runnerclient.Outcome {
	if !confirmed {
		return runnerclient.Outcome{State: "failed", ExitCode: previous.ExitCode, ReasonCode: "RUNNER_ERROR",
			Summary: "Cancellation requested, but native termination was not confirmed by a fresh completed build record.\n\n" + previous.Summary}
	}
	return runnerclient.Outcome{State: "cancelled", ExitCode: previous.ExitCode,
		Summary: "Native build stopped after cancellation was requested.\n\n" + previous.Summary}
}

func nativeCompletionRecord(directory string) []byte {
	file, err := os.Open(filepath.Join(directory, filepath.FromSlash(ManifestPath)))
	if err != nil {
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxManifest+1))
	if err != nil || len(data) > maxManifest {
		return nil
	}
	return data
}

func freshNativeCompletion(previous, current []byte) bool {
	if len(current) == 0 || bytes.Equal(previous, current) {
		return false
	}
	var before, record struct {
		SchemaVersion string `json:"schemaVersion"`
		Kind          string `json:"kind"`
		RunID         string `json:"runId"`
		Status        string `json:"status"`
	}
	_ = json.Unmarshal(previous, &before)
	return json.Unmarshal(current, &record) == nil && record.SchemaVersion == "v1alpha1" && record.Kind == "build-manifest" &&
		record.RunID != "" && record.RunID != before.RunID && (record.Status == "succeeded" || record.Status == "interrupted")
}

// buildEnv is the runner's environment without anything that would let the
// build reach for an ID token some other way.
func buildEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		if strings.HasPrefix(kv, EnvIDTokenURL+"=") || strings.HasPrefix(kv, EnvIDTokenRequestToken+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// failed is a failure before oyzu exited, which runs counts against the
// executor unless a more specific code says otherwise.
func failed(summary string) runnerclient.Outcome {
	return failedWith("RUNNER_ERROR", summary)
}

func failedWith(code, summary string) runnerclient.Outcome {
	return runnerclient.Outcome{State: "failed", Summary: summary, ReasonCode: code}
}

// checkout fetches exactly the job's commit. The token goes to git as an
// HTTP header through the environment, so it is in neither the process
// arguments nor the repository's config. Ordinary builds get the commit alone;
// plans and admitted slices get the same blobless history so native preparation
// observes the same version context and affected-build merge base.
func checkout(ctx context.Context, cfg Config, token string, job runnerclient.Job) error {
	auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	remote := strings.TrimRight(cfg.GitURL, "/") + "/" + job.Repository + ".git"
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http."+strings.TrimRight(cfg.GitURL, "/")+"/.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic "+auth,
	)
	steps := [][]string{
		{"init", "--quiet"},
		{"fetch", "--quiet", "--depth", "1", "--no-tags", remote, job.HeadSHA},
		{"checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	if job.Kind == "plan" || job.Kind == "slice" {
		fetch := []string{"fetch", "--quiet", "--filter=blob:none", "--no-tags", "origin", job.HeadSHA}
		if job.AffectedBase != "" && job.AffectedBase != job.HeadSHA {
			fetch = append(fetch, job.AffectedBase)
		}
		steps = [][]string{
			{"init", "--quiet"},
			{"remote", "add", "origin", remote},
			{"config", "remote.origin.promisor", "true"},
			{"config", "remote.origin.partialclonefilter", "blob:none"},
			fetch,
			{"checkout", "--quiet", "--detach", job.HeadSHA},
		}
		if job.AffectedBase != "" && job.AffectedBase != job.HeadSHA {
			// oyzu runs without the token, so fetch the base's side of every
			// changed file now.
			steps = append(steps, []string{"diff", "--numstat", job.AffectedBase, job.HeadSHA})
		}
	}
	for _, args := range steps {
		cmd := exec.CommandContext(ctx, cfg.Git, args...)
		cmd.Dir, cmd.Env = cfg.WorkDir, env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.ReplaceAll(strings.TrimSpace(stderr.String()), token, "***")
			return fmt.Errorf("git %s: %w: %s", args[0], err, msg)
		}
	}
	return nil
}

// capped keeps the first n bytes written to it and drops the rest.
type capped struct {
	w io.Writer
	n int
}

func (c *capped) Write(b []byte) (int, error) {
	if c.n > 0 {
		k := min(len(b), c.n)
		if _, err := c.w.Write(b[:k]); err != nil {
			return 0, err
		}
		c.n -= k
	}
	return len(b), nil
}

// declaresTask reports whether oyzu.toml declares tasks.<task>. A missing file
// declares nothing; a file that cannot be read or parsed is an error, so the
// job fails instead of being skipped for the wrong reason.
func declaresTask(path, task string) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var doc struct {
		Tasks map[string]any `toml:"tasks"`
	}
	if err := toml.Unmarshal(b, &doc); err != nil {
		return false, err
	}
	_, ok := doc.Tasks[task]
	return ok, nil
}

// tail keeps the last summaryLines lines written to it.
type tail struct {
	mu    sync.Mutex
	lines []string
	part  string
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	const maxTailLine = 64 << 10
	rest := p
	for {
		line, after, found := bytes.Cut(rest, []byte{'\n'})
		if len(line) >= maxTailLine {
			t.part = string(line[len(line)-maxTailLine:])
		} else {
			keep := min(len(t.part), maxTailLine-len(line))
			t.part = t.part[len(t.part)-keep:] + string(line)
		}
		if !found {
			break
		}
		t.lines = append(t.lines, t.part)
		if len(t.lines) > summaryLines {
			t.lines = t.lines[len(t.lines)-summaryLines:]
		}
		t.part = ""
		rest = after
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := t.lines
	if t.part != "" {
		lines = append(append([]string{}, lines...), t.part)
	}
	return strings.Join(lines, "\n")
}
