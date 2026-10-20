package executor

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// The two jobs that write to the repository. Each asks runs for a token that
// can write only when it needs one, and neither hands that token to oyzu.

// DefaultGitAuthor is who lock fix and Renovate commits are by when the
// runner is not told otherwise.
const DefaultGitAuthor = "Oyzu <oyzu@users.noreply.github.com>"

// Preset is the oyzu Renovate preset: what a renovate job runs with when the
// repository has no Renovate configuration of its own, and what one that
// has can extend.
//
//go:embed renovate/oyzu.json
var Preset []byte

// lockCommand is the only command the preset's post-upgrade tasks may run.
const lockCommand = "^oyzu lock$"

// lockFiles are the files oyzu lock writes. A lock fix pushes only these.
var lockFiles = []string{"apks.lock.yaml", "debs.lock.yaml", "oyzu.lock", "rpms.lock.yaml"}

var (
	// branchPattern is a branch name a push can name without escaping.
	branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	authorPattern = regexp.MustCompile(`^([^<>\n]+) <([^<>\s]+@[^<>\s]+)>$`)
)

// renovate runs unmodified Renovate on the job's repository with the oyzu
// preset as its global configuration. Renovate clones the default branch
// itself with a token that can push its own branches and open pull
// requests; post-upgrade tasks may run only oyzu lock.
func renovate(ctx context.Context, cfg Config, token, startup string, job runnerclient.Job, log *slog.Logger) runnerclient.Outcome {
	_, name, _ := strings.Cut(job.Repository, "/")
	if !repoPattern.MatchString(job.Repository) || strings.Trim(name, ".") == "" {
		return failedWith("INVALID_JOB", "The job names an invalid repository.")
	}
	if cfg.Renovate == "" {
		return failed("This executor has no Renovate. Start its pool manager with --renovate.")
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return failed("Could not create the work directory: " + err.Error())
	}
	conf, err := renovateConfig(cfg, job.Repository)
	if err != nil {
		return failed("Could not write Renovate's configuration: " + err.Error())
	}
	confFile := filepath.Join(cfg.WorkDir, "renovate.json")
	if err := os.WriteFile(confFile, conf, 0o600); err != nil {
		return failed("Could not write Renovate's configuration: " + err.Error())
	}
	wt, err := cfg.Client.WriteToken(ctx, token)
	if err != nil {
		return failed("Could not get a token that can open pull requests: " + err.Error())
	}
	forms := maskForms(token, startup, wt.Token, "x-access-token:"+wt.Token)
	env := append(withoutPrefix(cfg.environ(), "RENOVATE_"),
		"RENOVATE_TOKEN="+wt.Token,
		"RENOVATE_CONFIG_FILE="+confFile,
		"LOG_LEVEL=info",
	)
	what := "Renovate on " + job.Repository
	code, out, err := runTool(ctx, cfg.Renovate, nil, cfg.WorkDir, env, forms)
	log.Info("renovate finished", "exit_code", code, "error", err)
	return toolOutcome(ctx, what, code, out, err)
}

// renovateConfig is the preset with the settings only the platform sets:
// one repository on the Git host, no onboarding pull request, the preset
// standing in for a repository that has no configuration, and oyzu lock as
// the only command its post-upgrade tasks may run.
func renovateConfig(cfg Config, repository string) ([]byte, error) {
	var c map[string]any
	if err := json.Unmarshal(Preset, &c); err != nil {
		return nil, err
	}
	delete(c, "$schema")
	c["platform"] = "github"
	c["endpoint"] = strings.TrimRight(cfg.GitHubAPI, "/") + "/"
	c["repositories"] = []string{repository}
	c["onboarding"] = false
	c["requireConfig"] = "optional"
	c["allowedCommands"] = []string{lockCommand}
	c["gitAuthor"] = cfg.GitAuthor
	c["baseDir"] = filepath.Join(cfg.WorkDir, "renovate-work")
	return json.MarshalIndent(c, "", "  ")
}

// lockFix checks out the branch's commit, runs oyzu lock and, when that
// changed locks, commits them and pushes the commit to the branch. The push
// only fast-forwards: if the branch moved on meanwhile, nothing is pushed and
// the newer commit's own lock job does the work. Only lock files are ever
// committed.
func lockFix(ctx context.Context, cfg Config, token, startup string, job runnerclient.Job, log *slog.Logger) runnerclient.Outcome {
	_, name, _ := strings.Cut(job.Repository, "/")
	if !shaPattern.MatchString(job.HeadSHA) || !repoPattern.MatchString(job.Repository) || strings.Trim(name, ".") == "" {
		return failedWith("INVALID_JOB", "The job names an invalid repository or commit.")
	}
	if job.HeadBranch == "" {
		return runnerclient.Outcome{State: "skipped", Summary: "`oyzu lock` needs a branch to push to, and this commit has none."}
	}
	if !branchPattern.MatchString(job.HeadBranch) || strings.Contains(job.HeadBranch, "..") || strings.HasSuffix(job.HeadBranch, ".lock") {
		return failedWith("INVALID_JOB", "The job names a branch the lock fix will not push to.")
	}
	userName, userEmail, ok := splitAuthor(cfg.GitAuthor)
	if !ok {
		return failed("The runner's --git-author is not \"Name <email>\".")
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return failed("Could not create the work directory: " + err.Error())
	}
	src, err := cfg.Client.Source(ctx, token)
	if err != nil {
		return failedWith("SOURCE_UNAVAILABLE", "Could not get a token to read the repository: "+err.Error())
	}
	forms := maskForms(token, startup, src.Token, "x-access-token:"+src.Token)
	if err := checkout(ctx, cfg, src.Token, job); err != nil {
		msg := replaceForms(err.Error(), forms)
		log.Warn("checkout failed", "error", msg)
		return failedWith("SOURCE_UNAVAILABLE", "Could not check out "+job.HeadSHA+": "+msg)
	}

	what := "`oyzu lock` on `" + job.HeadSHA + "`"
	code, out, err := runTool(ctx, cfg.Oyzu, []string{"lock"}, cfg.WorkDir, cfg.environ(), forms)
	if err != nil || code != 0 {
		return toolOutcome(ctx, what, code, out, err)
	}
	status, err := git(ctx, cfg, "", "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return failed("Could not read what oyzu lock changed: " + replaceForms(err.Error(), forms))
	}
	changed, others := lockChanges(status)
	if len(others) > 0 {
		return failed(fmt.Sprintf("%s changed files other than locks, so nothing was pushed: `%s`.", what, strings.Join(others, "`, `")))
	}
	if len(changed) == 0 {
		return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: "Every lock is current at `" + job.HeadSHA + "`; nothing to push."}
	}
	if _, err := git(ctx, cfg, "", append([]string{"add", "--"}, changed...)...); err != nil {
		return failed("Could not stage the locks: " + replaceForms(err.Error(), forms))
	}
	msg := "Update locks with oyzu lock\n\nThe platform regenerated " + strings.Join(changed, ", ") +
		" because they were stale at " + job.HeadSHA + ".\n"
	if _, err := git(ctx, cfg, "", "-c", "user.name="+userName, "-c", "user.email="+userEmail, "-c", "commit.gpgsign=false",
		"commit", "--quiet", "--no-verify", "-m", msg); err != nil {
		return failed("Could not commit the locks: " + replaceForms(err.Error(), forms))
	}
	head, err := git(ctx, cfg, "", "rev-parse", "HEAD")
	if err != nil {
		return failed("Could not read the lock commit: " + replaceForms(err.Error(), forms))
	}
	commit := strings.TrimSpace(head)

	// Only now, with oyzu finished, ask for a token that can push.
	wt, err := cfg.Client.WriteToken(ctx, token)
	if err != nil {
		return failed("Could not get a token that can push to " + job.HeadBranch + ": " + err.Error())
	}
	forms = maskForms(token, startup, src.Token, "x-access-token:"+src.Token, wt.Token, "x-access-token:"+wt.Token)
	remote := strings.TrimRight(cfg.GitURL, "/") + "/" + job.Repository + ".git"
	if _, err := git(ctx, cfg, wt.Token, "push", "--quiet", "--no-verify", remote, "HEAD:refs/heads/"+job.HeadBranch); err != nil {
		msg := replaceForms(err.Error(), forms)
		log.Warn("lock push failed", "error", msg)
		return failed(fmt.Sprintf("Could not push the regenerated locks to `%s`; the branch may have moved on: %s", job.HeadBranch, msg))
	}
	log.Info("locks pushed", "branch", job.HeadBranch, "commit", commit, "files", strings.Join(changed, ","))
	return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: fmt.Sprintf(
		"Pushed `%s` to `%s` with regenerated %s. Its own checks run next.\n\n```text\n%s\n```",
		commit, job.HeadBranch, "`"+strings.Join(changed, "`, `")+"`", out)}
}

// lockChanges splits `git status --porcelain -z` into changed lock files and
// anything else. A rename counts as anything else.
func lockChanges(status string) (locks, others []string) {
	entries := strings.Split(status, "\x00")
	for i := 0; i < len(entries); i++ {
		e := entries[i]
		if len(e) < 4 {
			continue
		}
		xy, p := e[:2], e[3:]
		if strings.ContainsAny(xy, "RC") {
			// The next entry is the rename's source.
			others = append(others, p)
			i++
			continue
		}
		if slices.Contains(lockFiles, path.Base(p)) {
			locks = append(locks, p)
		} else {
			others = append(others, p)
		}
	}
	slices.Sort(locks)
	slices.Sort(others)
	return locks, others
}

func splitAuthor(a string) (name, email string, ok bool) {
	m := authorPattern.FindStringSubmatch(a)
	if m == nil {
		return "", "", false
	}
	return strings.TrimSpace(m[1]), m[2], true
}

// git runs git in the work directory and returns its stdout. With a token,
// the token goes to git as an HTTP header through the environment, never in
// its arguments or the repository's config.
func git(ctx context.Context, cfg Config, token string, args ...string) (string, error) {
	env := append(cfg.environ(), "GIT_TERMINAL_PROMPT=0")
	if token != "" {
		auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http."+strings.TrimRight(cfg.GitURL, "/")+"/.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+auth,
		)
	}
	cmd := exec.CommandContext(ctx, cfg.Git, args...)
	cmd.Dir, cmd.Env = cfg.WorkDir, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "***")
		}
		return "", fmt.Errorf("git %s: %w: %s", gitVerb(args), err, msg)
	}
	return stdout.String(), nil
}

// gitVerb is the subcommand among git's arguments, past any -c settings.
func gitVerb(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			continue
		}
		return args[i]
	}
	return ""
}

// runTool runs a tool to completion with its output masked into a tail,
// interrupting it when ctx ends. It returns the exit code (-1 when it never
// ran) and the tail.
func runTool(ctx context.Context, exe string, args []string, dir string, env, forms []string) (int, string, error) {
	var out tail
	w := newMaskWriter(&out, forms)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Cancel = func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 20 * time.Second
	err := cmd.Run()
	_ = w.Flush()
	if cmd.ProcessState == nil {
		return -1, out.String(), err
	}
	return cmd.ProcessState.ExitCode(), out.String(), err
}

// toolOutcome is how a tool's run went.
func toolOutcome(ctx context.Context, what string, code int, out string, err error) runnerclient.Outcome {
	if code < 0 {
		return failed("Could not run " + what + ": " + err.Error())
	}
	summary := fmt.Sprintf("%s exited %d.\n\n```text\n%s\n```", what, code, out)
	switch {
	case err == nil:
		return runnerclient.Outcome{State: "succeeded", ExitCode: &code, Summary: summary}
	case ctx.Err() != nil:
		return runnerclient.Outcome{State: "cancelled", Summary: summary}
	}
	return runnerclient.Outcome{State: "failed", ExitCode: &code, Summary: summary}
}

// withoutPrefix drops the variables whose names start with prefix.
func withoutPrefix(env []string, prefix string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}
