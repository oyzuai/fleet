package container

import (
	"context"
	"testing"

	"github.com/oyzuai/fleet/internal/executiontest"
	"github.com/oyzuai/fleet/runnerclient"
)

func TestContainerLaunchEnforcesRequiredTrust(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	if _, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 42, Attempt: 1, StartupToken: "container-start"}); err != nil {
		t.Fatal(err)
	}
	c, err := e.container("c1")
	if err != nil {
		t.Fatal(err)
	}
	executiontest.RefuseMissingTrust(t, c.spec.Cmd[1:], c.content["run/oyzu/startup-token"])
}
