package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestAffectedBuildCheckoutHasCompleteBaselineWithoutHistory(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git unavailable: " + err.Error())
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	command := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	command(source, "init", "--quiet")
	commit := func(content string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(source, "input.txt"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		command(source, "add", ".")
		command(source, "commit", "--quiet", "-m", content)
		return command(source, "rev-parse", "HEAD")
	}
	ancestor := commit("ancestor")
	base := commit("baseline input")
	head := commit("head input")
	command(source, "branch", "unrelated")
	unrelated := commit("unrelated tip")
	remote := filepath.Join(root, "repo.git")
	command(root, "clone", "--quiet", "--bare", source, remote)
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	job := runnerclient.Job{Kind: "build", Operation: "build", Repository: "repo", HeadSHA: head, AffectedBase: base}
	if err := checkout(context.Background(), Config{Git: git, GitURL: "file://" + filepath.ToSlash(root), WorkDir: work}, "test-token", job); err != nil {
		t.Fatal(err)
	}
	if got := command(work, "rev-parse", "HEAD"); got != head {
		t.Fatalf("HEAD=%s want %s", got, head)
	}
	if got := command(work, "show", base+":input.txt"); got != "baseline input" {
		t.Fatalf("baseline blob=%q", got)
	}
	if got := command(work, "show", head+":input.txt"); got != "head input" {
		t.Fatalf("head blob=%q", got)
	}
	for _, absent := range []string{ancestor, unrelated} {
		cmd := exec.Command(git, "cat-file", "-e", absent+"^{commit}")
		cmd.Dir = work
		if err := cmd.Run(); err == nil {
			t.Fatalf("fetched unrequested history/tip %s", absent)
		}
	}
	bad := filepath.Join(root, "missing-base")
	if err := os.Mkdir(bad, 0700); err != nil {
		t.Fatal(err)
	}
	job.AffectedBase = strings.Repeat("a", 40)
	if err := checkout(context.Background(), Config{Git: git, GitURL: "file://" + filepath.ToSlash(root), WorkDir: bad}, "test-token", job); err == nil {
		t.Fatal("missing requested baseline silently accepted")
	}
}
