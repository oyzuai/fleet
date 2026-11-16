package manager

import (
	"context"
	"errors"
	"github.com/oyzuai/fleet/runnerclient"
	"strconv"
	"strings"
	"testing"
)

func TestActionCapabilityRequiresExplicitReadyRuntime(t *testing.T) {
	ctx := context.Background()
	p := &Process{}
	f, err := p.Facts(ctx)
	nativeCPU := f[FactCPU]
	if err != nil || f["oyzu.io/action-runtime"] != "" {
		t.Fatalf("ordinary process advertises action: %v %v", f, err)
	}
	p.ActionEngine = "unix:///private/engine.sock"
	if _, err := p.Facts(ctx); err == nil {
		t.Fatal("runtime advertised without probe")
	}
	p.ActionRuntimeReady = func(context.Context) error { return errors.New("engine unavailable") }
	if _, err := p.Facts(ctx); err == nil {
		t.Fatal("unavailable runtime advertised")
	}
	p.ActionRuntimeReady = func(context.Context) error { return nil }
	p.ActionCleanup = func(context.Context, runnerclient.ActionOwner) error { return nil }
	nativeCores, _ := strconv.ParseInt(nativeCPU, 10, 64)
	p.ActionCapacity = func(context.Context) (int64, int64, error) { return 8 << 30, nativeCores + 1, nil }
	f, err = p.Facts(ctx)
	if err != nil || f["oyzu.io/action-runtime"] != "linux-container" {
		t.Fatalf("ready runtime not advertised: %v %v", f, err)
	}
	for _, feature := range runnerclient.ActionFeatures {
		if f["oyzu.io/action-feature-"+feature] != "true" {
			t.Fatal("missing action feature")
		}
	}
	if f[FactCPU] != nativeCPU || f["oyzu.io/action-cpu"] != strconv.FormatInt(nativeCores+1, 10) || f["oyzu.io/action-memory-bytes"] != "8589934592" {
		t.Fatalf("action engine changed native capacity: %+v", f)
	}
	p.ExtraEnv = []string{"FLEET_ACTION_ENGINE"}
	p.environ = func() []string { return []string{"FLEET_ACTION_ENGINE=unix:///untrusted.sock"} }
	env := p.env()
	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "FLEET_ACTION_ENGINE=") {
			count++
			if kv != "FLEET_ACTION_ENGINE="+p.ActionEngine {
				t.Fatal("inherited endpoint replaced admitted engine")
			}
		}
	}
	if count != 1 {
		t.Fatalf("engine handoff: %v", env)
	}
}
