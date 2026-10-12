package manager

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestProcessDriverRelativeWorkDir(t *testing.T) {
	t.Chdir(t.TempDir())
	p := helperDriver(t, "readtoken")
	p.WorkDir, p.LogDir = "jobs", filepath.Join("jobs", "logs")
	ctx := context.Background()
	c, err := p.Capacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Start(ctx, c.Ready[0], runnerclient.Claim{JobID: 21, Attempt: 1, StartupToken: "oyzu_start_x"})
	if err != nil {
		t.Fatal(err)
	}
	exit, err := p.Wait(ctx, h)
	if err != nil || !exit.Clean() {
		t.Fatalf("exit = %+v, %v (4: a path was relative, 5: the token could not be read)", exit, err)
	}
	_ = p.Teardown(ctx, h)
}
