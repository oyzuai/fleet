package manager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/oyzuai/fleet/internal/executiontest"
	"github.com/oyzuai/fleet/runnerclient"
)

func TestProcessLaunchEnforcesRequiredTrust(t *testing.T) {
	p := helperDriver(t, "execution-args")
	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("POOLMANAGER_ARGS_FILE", argsFile)
	p.ExtraEnv = append(p.ExtraEnv, "POOLMANAGER_ARGS_FILE")
	h, err := p.Start(context.Background(), "0", runnerclient.Claim{JobID: 42, Attempt: 1, StartupToken: "process-start"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Teardown(context.Background(), h) })
	exit, err := p.Wait(context.Background(), h)
	if err != nil || !exit.Clean() {
		t.Fatal("process launch failed", exit, err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(h.Ref, StartupTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	executiontest.RefuseMissingTrust(t, args, string(token))
}
