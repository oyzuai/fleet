package manager

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestProcessPassesPrivateSecretsAndOwnerDirectories(t *testing.T) {
	p := helperDriver(t, "0")
	ctx := context.Background()
	h, err := p.Start(ctx, "0", runnerclient.Claim{JobID: 11, Attempt: 1, StartupToken: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Teardown(ctx, h) }()
	pr, err := p.proc(h)
	if err != nil {
		t.Fatal(err)
	}
	jobDir, err := filepath.Abs(h.Ref)
	if err != nil {
		t.Fatal(err)
	}
	secretsDir := filepath.Join(jobDir, "kind-tmp")
	for flag, want := range map[string]string{"--job-dir": jobDir, "--secrets-dir": secretsDir} {
		i := slices.Index(pr.cmd.Args, flag)
		if i < 0 || i+1 >= len(pr.cmd.Args) || pr.cmd.Args[i+1] != want {
			t.Fatalf("%s missing or wrong in %v", flag, pr.cmd.Args)
		}
	}
	info, err := os.Stat(secretsDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("secrets directory mode: %s", info.Mode())
	}
}
