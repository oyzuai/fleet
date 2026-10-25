package container

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/runnerclient"
)

type anchorEngine struct {
	*fakeEngine
	inspectErr error
	drift      bool
	removeErr  string
	startErr   string
	removed    []string
	uncertain  string
}

func (e *anchorEngine) NamespaceAnchorRequired(context.Context) (bool, error) { return true, nil }
func (e *anchorEngine) InspectNamespaceAnchor(_ context.Context, id string, spec Spec) (anchorIdentity, error) {
	if e.inspectErr != nil {
		return anchorIdentity{}, e.inspectErr
	}
	c, err := e.container(id)
	if err != nil {
		return anchorIdentity{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !c.started || c.stopped || configurationDigest(c.spec) != configurationDigest(spec) {
		return anchorIdentity{}, errors.New("anchor stopped or changed")
	}
	ns := "namespace-1"
	if e.drift {
		ns = "namespace-2"
	}
	return anchorIdentity{Container: id, Image: spec.Image, Network: "bridge-id", Namespace: ns, Process: "pid-start", Configuration: configurationDigest(spec)}, nil
}
func (e *anchorEngine) Info(context.Context) (Info, error) {
	return Info{ID: "same-host", ServerVersion: "4.9.3", OSType: "linux"}, nil
}
func (e *anchorEngine) StartContainer(ctx context.Context, id string) error {
	c, err := e.container(id)
	if err != nil {
		return err
	}
	if c.spec.Labels[LabelRole] == e.startErr && e.startErr != "" {
		return errors.New("start failed")
	}
	return e.fakeEngine.StartContainer(ctx, id)
}
func (e *anchorEngine) RemoveContainer(ctx context.Context, id string) error {
	c, err := e.container(id)
	if err != nil {
		return nil
	}
	if c.spec.Labels[LabelRole] == e.removeErr && e.removeErr != "" {
		return errors.New("remove failed")
	}
	e.removed = append(e.removed, c.spec.Labels[LabelRole])
	return e.fakeEngine.RemoveContainer(ctx, id)
}
func (e *anchorEngine) InspectContainer(ctx context.Context, id string) (State, error) {
	if id == e.uncertain {
		return State{}, errors.New("observation unavailable")
	}
	return e.fakeEngine.InspectContainer(ctx, id)
}
func anchorDriver() (*Driver, *anchorEngine) {
	e := &anchorEngine{fakeEngine: newFakeEngine()}
	d, _ := sandboxDriver(e.fakeEngine, EgressEnforce)
	d.Engine = e
	d.pulled = true
	return d, e
}
func anchorJob(d *Driver, suffix string) (*job, map[string]string) {
	name := "oyzu-" + d.managerLabel() + "-job-" + suffix
	return &job{name: name}, map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelJob: suffix}
}

func TestAnchorTwoSlotsAndSoleStoreCycles(t *testing.T) {
	ctx := context.Background()
	d, e := anchorDriver()
	for cycle := 0; cycle < 2; cycle++ {
		a, al := anchorJob(d, "1")
		b, bl := anchorJob(d, "2")
		if _, _, err := d.openSandbox(ctx, a, al, 1, nil); err != nil {
			t.Fatal(err)
		}
		anchorID, gatewayID := d.anchor.id, d.gw.id
		if _, _, err := d.openSandbox(ctx, b, bl, 2, nil); err != nil {
			t.Fatal(err)
		}
		if d.anchor.id != anchorID || d.gw.id != gatewayID {
			t.Fatal("overlapping slot replaced pair")
		}
		if err := d.closeSandbox(ctx, a); err != nil {
			t.Fatal(err)
		}
		if err := d.checkPair(ctx); err != nil {
			t.Fatal(err)
		}
		if err := d.closeSandbox(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := d.Reap(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if len(e.containers) != 2 {
			t.Fatalf("pair not retained: %d", len(e.containers))
		}
		if err := d.Finalize(ctx); err != nil {
			t.Fatal(err)
		}
		if len(e.containers) != 0 || len(e.networks) != 0 {
			t.Fatal("resources survived finalization")
		}
		if !slices.Equal(e.removed[len(e.removed)-2:], []string{roleGateway, roleAnchor}) {
			t.Fatalf("wrong removal order %v", e.removed)
		}
		// A new manager lifecycle, never a replacement under accepted proof.
		d, _ = sandboxDriver(e.fakeEngine, EgressEnforce)
		d.Engine = e
		d.pulled = true
	}
}

func TestAnchorFaultRevokesAuthorityAndNeverRepairs(t *testing.T) {
	for _, fault := range []string{"missing", "stopped", "changed", "uncertain"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			d, e := anchorDriver()
			j, l := anchorJob(d, "1")
			if _, _, err := d.openSandbox(ctx, j, l, 1, nil); err != nil {
				t.Fatal(err)
			}
			d.mu.Lock()
			d.egressOK = true
			d.tested = true
			d.mu.Unlock()
			switch fault {
			case "missing":
				_ = e.fakeEngine.RemoveContainer(ctx, d.anchor.id)
			case "stopped":
				_ = e.StopContainer(ctx, d.anchor.id, time.Second)
			case "changed":
				e.drift = true
			case "uncertain":
				e.inspectErr = errors.New("timeout")
			}
			if _, err := d.Capacity(ctx); !errors.Is(err, readiness.ErrBoundaryChanged) {
				t.Fatalf("capacity accepted fault: %v", err)
			}
			f, err := d.Facts(ctx)
			if err != nil || f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
				t.Fatalf("authority survived: %v %v", f, err)
			}
			if _, err := d.Start(ctx, "0", runnerclient.Claim{}); err == nil {
				t.Fatal("accepted job")
			}
			if err := d.closeSandbox(ctx, j); err == nil {
				t.Fatal("disconnected uncertain namespace")
			}
			e.inspectErr = nil
			e.drift = false
			d.SetReadiness(&readiness.Binding{Challenge: "new"})
			if d.localBinding != nil {
				t.Fatal("fresh binding repaired fault")
			}
			if _, err := d.ensureGateway(ctx); err == nil {
				t.Fatal("silently replaced pair")
			}
			if err := d.Finalize(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAnchorBoundaryIncludesActualIdentity(t *testing.T) {
	ctx := context.Background()
	d, e := anchorDriver()
	b, err := d.ReadinessBoundary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.ReadinessBoundary(ctx)
	if err != nil || b.Fingerprint() != again.Fingerprint() {
		t.Fatalf("unstable boundary %v", err)
	}
	e.drift = true
	if _, err := d.ReadinessBoundary(ctx); !errors.Is(err, readiness.ErrBoundaryChanged) {
		t.Fatalf("stale proof accepted %v", err)
	}
	identity := d.anchor.identity
	identity.Namespace = "another-namespace"
	if configurationDigest(identity) == configurationDigest(d.anchor.identity) {
		t.Fatal("anchor omitted from runtime identity")
	}
}

func TestAnchorPartialCreationAndUncertainGatewayRemoval(t *testing.T) {
	for _, role := range []string{roleAnchor, roleGateway} {
		t.Run(role, func(t *testing.T) {
			d, e := anchorDriver()
			e.startErr = role
			if _, err := d.ensureGateway(context.Background()); err == nil {
				t.Fatal("start failure lost")
			}
			if len(e.containers) != 0 {
				t.Fatal("partial pair leaked")
			}
		})
	}
	for _, failure := range []string{"remove", "inspect"} {
		t.Run(failure, func(t *testing.T) {
			d, e := anchorDriver()
			ctx := context.Background()
			if _, err := d.ensureGateway(ctx); err != nil {
				t.Fatal(err)
			}
			anchorID := d.anchor.id
			if failure == "remove" {
				e.removeErr = roleGateway
			} else {
				e.uncertain = d.gw.id
			}
			if err := d.Finalize(ctx); err == nil {
				t.Fatal("uncertain removal accepted")
			}
			if _, err := e.container(anchorID); err != nil {
				t.Fatal("anchor removed before confirmed gateway absence")
			}
			e.removeErr = ""
			e.uncertain = ""
			if err := d.Finalize(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAnchorFinalizeDrainsProbesAndRefusesActiveJobs(t *testing.T) {
	d, _ := anchorDriver()
	ctx := context.Background()
	if _, err := d.ensureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	pctx, release, err := d.beginProbe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Finalize(ctx) }()
	select {
	case <-pctx.Done():
	case <-time.After(time.Second):
		t.Fatal("probe not cancelled")
	}
	select {
	case <-done:
		t.Fatal("retired active probe")
	default:
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.beginProbe(ctx); err == nil {
		t.Fatal("probe accepted after shutdown")
	}
	d, _ = anchorDriver()
	if _, err := d.ensureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	d.inUse = map[manager.SlotID]*job{"0": {name: "active"}}
	if err := d.Finalize(ctx); err == nil || !strings.Contains(err.Error(), "not drained") {
		t.Fatalf("active jobs lost: %v", err)
	}
}
