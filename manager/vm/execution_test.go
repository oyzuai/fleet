package vm

import (
	"context"
	"testing"
	"time"

	"github.com/oyzuai/fleet/internal/executiontest"
)

func TestVMJobAssignmentEnforcesRequiredTrust(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	bootAll(t, d, cloud)
	c := capacity(t, d)
	h, err := d.Start(context.Background(), c.Ready[0], claim(41))
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.assignment(context.Background(), proof(h.Ref), cloud.address(h.Ref)+":1", time.Millisecond)
	if err != nil || a == nil {
		t.Fatal("VM assignment unavailable", err)
	}
	executiontest.RefuseMissingTrust(t, []string{"--server", "https://runs.example", "--work-dir", "/work", "--startup-token-file", "/run/startup"}, a.StartupToken)
}
