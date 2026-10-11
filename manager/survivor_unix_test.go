//go:build !windows

package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// An adopted survivor keeps its kind containers as well as its directory.
func TestReaperKeepsASurvivorsKindContainers(t *testing.T) {
	p := &Process{WorkDir: t.TempDir(), Manager: 7, Docker: true, Log: quiet()}
	self, err := processStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	survivorDir := filepath.Join(p.jobsDir(), "job-5-1-live")
	if err := os.MkdirAll(survivorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(survivorDir, record{PID: os.Getpid(), Start: self, Job: 5, Attempt: 1}); err != nil {
		t.Fatal(err)
	}
	dead := filepath.Join(p.jobsDir(), "job-6-1-dead")
	bin := t.TempDir()
	log := filepath.Join(bin, "removed")
	rows := filepath.Join(bin, "containers")
	data := "kept\t" + survivorDir + "\t5\ngone\t" + dead + "\t6\n"
	if err := os.WriteFile(rows, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = ps ]; then cat \"$REAPER_ROWS\"; else echo \"$*\" >> \"$REAPER_LOG\"; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("REAPER_ROWS", rows)
	t.Setenv("REAPER_LOG", log)
	if err := p.Reap(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if removed, _ := os.ReadFile(log); string(removed) != "rm -f gone\n" {
		t.Fatalf("removed: %q", removed)
	}
	if _, err := os.Stat(survivorDir); err != nil {
		t.Fatal("the survivor's directory was removed")
	}
}
