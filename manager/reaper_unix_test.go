//go:build !windows

package manager

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReaperRemovesLabelledContainersEvenWithoutJobDirectory(t *testing.T) {
	p := &Process{WorkDir: t.TempDir(), Manager: 7, Docker: true}
	dead := filepath.Join(p.jobsDir(), "job-1-1-dead")
	missing := filepath.Join(p.jobsDir(), "job-3-1-gone")
	live := filepath.Join(p.jobsDir(), "job-2-1-live")
	foreign := filepath.Join(p.WorkDir, "manager-8", "job-4-1-other")
	secret := filepath.Join(dead, "kind-tmp", "secrets", "key")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("test"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "removed")
	rows := filepath.Join(bin, "containers")
	data := "dead\t" + dead + "\t1\nmissing\t" + missing + "\t3\nlive\t" + live + "\t2\nforeign\t" + foreign + "\t4\n"
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
	if err := p.Reap(context.Background(), []JobID{2}); err != nil {
		t.Fatal(err)
	}
	removed, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(removed) != "rm -f dead\nrm -f missing\n" {
		t.Fatalf("removed: %s", removed)
	}
	if _, err := os.Stat(secret); !os.IsNotExist(err) {
		t.Fatal("secret survived reaping")
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("live job removed")
	}
	if strings.Contains(string(removed), "foreign") {
		t.Fatal("foreign container removed")
	}
}
