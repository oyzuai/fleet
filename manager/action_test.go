package manager

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestActionCapabilityRequiresExplicitReadyRuntime(t *testing.T) {
	ctx := context.Background()
	p := &Process{}
	f, err := p.Facts(ctx)
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
	f, err = p.Facts(ctx)
	if err != nil || f["oyzu.io/action-runtime"] != "linux-container" {
		t.Fatalf("ready runtime not advertised: %v %v", f, err)
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
