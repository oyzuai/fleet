package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

// fakeRenovate records what it was started with and prints its token, which
// the runner must mask.
func fakeRenovate() {
	conf, _ := os.ReadFile(os.Getenv("RENOVATE_CONFIG_FILE"))
	rec, _ := json.Marshal(map[string]any{
		"token": os.Getenv("RENOVATE_TOKEN"), "config": json.RawMessage(conf), "stray": os.Getenv("RENOVATE_STRAY"),
	})
	_ = os.WriteFile(os.Getenv("FAKE_RENOVATE_LOG"), rec, 0o600)
	fmt.Println("INFO: Repository started (repository=oyzuai/platform)")
	fmt.Println("DEBUG: using token ghs_write")
	code, _ := strconv.Atoi(os.Getenv("FAKE_RENOVATE_EXIT"))
	os.Exit(code)
}

func renovateJob() runnerclient.Job {
	return runnerclient.Job{ID: 9, Attempt: 1, Kind: "build", Repository: "oyzuai/platform", Operation: "renovate", Command: []string{"renovate"}}
}

func TestRenovateRunsWithThePresetAndAWriteToken(t *testing.T) {
	runs, cfg, _ := setup(t, renovateJob())
	cfg.Renovate, _ = os.Executable()
	cfg.GitHubAPI = "https://api.github.example"
	logFile := filepath.Join(t.TempDir(), "renovate.json")
	t.Setenv("FAKE_RENOVATE_LOG", logFile)
	t.Setenv("RENOVATE_STRAY", "inherited")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" || strings.Contains(o.Summary, "ghs_write") || !strings.Contains(o.Summary, "Repository started") {
		t.Fatalf("outcome = %+v", o)
	}
	var rec struct {
		Token  string
		Stray  string
		Config map[string]any
	}
	b, _ := os.ReadFile(logFile)
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Token != "ghs_write" || rec.Stray != "" || runs.writeTokens != 1 {
		t.Fatalf("Renovate got token %q, stray %q; write tokens %d", rec.Token, rec.Stray, runs.writeTokens)
	}
	c := rec.Config
	for k, want := range map[string]any{
		"platform": "github", "endpoint": "https://api.github.example/", "onboarding": false, "requireConfig": "optional",
		"repositories": []any{"oyzuai/platform"}, "allowedCommands": []any{"^oyzu lock$"}, "gitAuthor": DefaultGitAuthor,
	} {
		if !reflect.DeepEqual(c[k], want) {
			t.Fatalf("config %s = %v, want %v", k, c[k], want)
		}
	}
	if _, ok := c["customManagers"]; !ok || c["$schema"] != nil || c["token"] != nil {
		t.Fatalf("config is not the preset plus platform settings: %v", c)
	}
	tasks, _ := c["postUpgradeTasks"].(map[string]any)
	if !reflect.DeepEqual(tasks["commands"], []any{"oyzu lock"}) {
		t.Fatalf("post-upgrade tasks = %v", tasks)
	}
}

func TestRenovateFailsWithoutRenovate(t *testing.T) {
	runs, cfg, _ := setup(t, renovateJob())
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "--renovate") || runs.writeTokens != 0 {
		t.Fatalf("outcome = %+v, write tokens %d", o, runs.writeTokens)
	}
}

func TestRenovateReportsItsFailure(t *testing.T) {
	runs, cfg, _ := setup(t, renovateJob())
	cfg.Renovate, _ = os.Executable()
	t.Setenv("FAKE_RENOVATE_LOG", filepath.Join(t.TempDir(), "renovate.json"))
	t.Setenv("FAKE_RENOVATE_EXIT", "1")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || o.ExitCode == nil || *o.ExitCode != 1 {
		t.Fatalf("outcome = %+v", o)
	}
}

func lockJob(branch string) runnerclient.Job {
	return runnerclient.Job{ID: 9, Attempt: 1, Kind: "build", Repository: "oyzuai/platform", HeadSHA: sha, HeadBranch: branch,
		Operation: "lock", Command: []string{"oyzu", "lock"}}
}

// gitCalls reads the fake git's log: each call's arguments and auth header.
func gitCalls(t *testing.T, gitLog string) []struct {
	Args   []string
	Header string
} {
	t.Helper()
	b, _ := os.ReadFile(gitLog)
	var out []struct {
		Args   []string
		Header string
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var c struct {
			Args   []string
			Header string
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestLockFixPushesOnlyLocks(t *testing.T) {
	runs, cfg, gitLog := setup(t, lockJob("feature/libpq"))
	t.Setenv("FAKE_GIT_STATUS", ` M services/api/debs.lock.yaml\0?? oyzu.lock\0`)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	o := runs.finished
	if o == nil || o.State != "succeeded" || !strings.Contains(o.Summary, "fedcba9876543210") || !strings.Contains(o.Summary, "feature/libpq") {
		t.Fatalf("outcome = %+v", o)
	}
	calls := gitCalls(t, gitLog)
	var add, push []string
	var pushHeader string
	for _, c := range calls {
		switch gitVerb(c.Args) {
		case "add":
			add = c.Args
		case "push":
			push, pushHeader = c.Args, c.Header
		}
	}
	if !reflect.DeepEqual(add, []string{"add", "--", "oyzu.lock", "services/api/debs.lock.yaml"}) {
		t.Fatalf("add = %v", add)
	}
	if !reflect.DeepEqual(push, []string{"push", "--quiet", "--no-verify", "https://github.example/oyzuai/platform.git", "HEAD:refs/heads/feature/libpq"}) {
		t.Fatalf("push = %v", push)
	}
	if want := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_write")); pushHeader != want {
		t.Fatalf("push header = %q", pushHeader)
	}
	for _, c := range calls {
		if gitVerb(c.Args) != "push" && strings.Contains(c.Header, base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_write"))) {
			t.Fatalf("git %v got the write token", c.Args)
		}
	}
	if runs.writeTokens != 1 {
		t.Fatalf("write tokens = %d", runs.writeTokens)
	}
}

func TestLockFixPushesNothingWhenCurrent(t *testing.T) {
	runs, cfg, gitLog := setup(t, lockJob("feature/libpq"))
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "succeeded" || !strings.Contains(o.Summary, "nothing to push") || runs.writeTokens != 0 {
		t.Fatalf("outcome = %+v, write tokens %d", o, runs.writeTokens)
	}
	for _, c := range gitCalls(t, gitLog) {
		if v := gitVerb(c.Args); v == "commit" || v == "push" {
			t.Fatalf("ran git %v", c.Args)
		}
	}
}

func TestLockFixRefusesOtherChanges(t *testing.T) {
	runs, cfg, gitLog := setup(t, lockJob("feature/libpq"))
	t.Setenv("FAKE_GIT_STATUS", ` M debs.lock.yaml\0 M Dockerfile\0R  new.lock.yaml\0old.yaml\0`)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "`Dockerfile`, `new.lock.yaml`") || runs.writeTokens != 0 {
		t.Fatalf("outcome = %+v, write tokens %d", o, runs.writeTokens)
	}
	for _, c := range gitCalls(t, gitLog) {
		if v := gitVerb(c.Args); v == "add" || v == "push" {
			t.Fatalf("ran git %v", c.Args)
		}
	}
}

func TestLockFixReportsARejectedPush(t *testing.T) {
	runs, cfg, _ := setup(t, lockJob("feature/libpq"))
	t.Setenv("FAKE_GIT_STATUS", ` M debs.lock.yaml\0`)
	t.Setenv("FAKE_GIT_FAIL", "push")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "failed" || !strings.Contains(o.Summary, "may have moved on") || strings.Contains(o.Summary, "ghs_write") {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestLockFixNeedsASafeBranch(t *testing.T) {
	for branch, state := range map[string]string{"": "skipped", "-delete": "failed", "a/../main": "failed", "x.lock": "failed"} {
		runs, cfg, _ := setup(t, lockJob(branch))
		if err := Run(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if o := runs.finished; o == nil || o.State != state || runs.writeTokens != 0 {
			t.Fatalf("branch %q: outcome = %+v", branch, o)
		}
	}
}

func TestLockChanges(t *testing.T) {
	locks, others := lockChanges("?? a/apks.lock.yaml\x00 M rpms.lock.yaml\x00 D README.md\x00")
	if !reflect.DeepEqual(locks, []string{"a/apks.lock.yaml", "rpms.lock.yaml"}) || !reflect.DeepEqual(others, []string{"README.md"}) {
		t.Fatalf("lockChanges = %v, %v", locks, others)
	}
}
