package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandDefaultSecretsDoesNotCreateBesideWorkDir(t *testing.T) {
	// A file as the parent makes any attempted sibling mkdir fail, even as root.
	parent := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Command([]string{"--server", "http://runs.invalid", "--work-dir", filepath.Join(parent, "work"),
		"--startup-token-file", filepath.Join(t.TempDir(), "missing")}, nil)
	if err == nil || !strings.Contains(err.Error(), "read the startup token") {
		t.Fatalf("default secrets directory prevented startup: %v", err)
	}
}

func TestCommandCreatesExplicitSecretsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	err := Command([]string{"--server", "http://runs.invalid", "--work-dir", "/work", "--secrets-dir", dir,
		"--job-dir", t.TempDir(), "--startup-token-file", filepath.Join(t.TempDir(), "missing")}, nil)
	if err == nil || !strings.Contains(err.Error(), "read the startup token") {
		t.Fatalf("explicit secrets directory prevented startup: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("secrets directory missing: %v", err)
	}
}
