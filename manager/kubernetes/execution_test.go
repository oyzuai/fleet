package kubernetes

import (
	"context"
	"testing"

	"github.com/oyzuai/fleet/internal/executiontest"
	"github.com/oyzuai/fleet/runnerclient"
)

func TestPodLaunchEnforcesRequiredTrust(t *testing.T) {
	api := newFakeAPI()
	d := newDriver(api)
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 42, Attempt: 1, StartupToken: "pod-start"})
	if err != nil {
		t.Fatal(err)
	}
	c := api.pods[h.Ref].pod.Spec.Containers[0]
	token := api.secrets[h.Ref+"-token"].Data["startup-token"]
	executiontest.RefuseMissingTrust(t, c.Args, string(token))
}
