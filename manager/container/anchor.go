package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oyzuai/fleet/readiness"
)

const roleAnchor = "namespace-anchor"

// Only an engine which positively qualifies its local Podman implementation
// selects this workaround. Docker retains its ordinary gateway lifecycle.
type namespaceAnchorEngine interface {
	NamespaceAnchorRequired(context.Context) (bool, error)
	InspectNamespaceAnchor(context.Context, string, Spec) (anchorIdentity, error)
}

type anchorIdentity struct {
	Container, Image, Network, Namespace, Process, Configuration string
}
type namespaceAnchor struct {
	id       string
	spec     Spec
	identity anchorIdentity
}

func (d *Driver) anchorName() string { return fmt.Sprintf("oyzu-%d-namespace-anchor", d.Manager) }
func (d *Driver) anchorSpec() Spec {
	return Spec{Image: d.Image, Cmd: []string{"/bin/sleep", "infinity"}, User: d.user(), WorkDir: "/", Network: defaultNetwork,
		ReadOnly: true, PidsLimit: 16, MemoryBytes: 32 << 20, NanoCPUs: 100_000_000,
		Labels: map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelRole: roleAnchor}}
}

// gwMu owns the pair from creation through its final confirmed removal. A
// failed observation is latched: creating a new anchor cannot repair a gateway
// whose shared rootless namespace may already have disappeared.
func (d *Driver) pairFailure(err error) error {
	if d.pairFault == nil {
		d.pairFault = fmt.Errorf("%w: namespace anchor: %v", readiness.ErrBoundaryChanged, err)
	}
	d.mu.Lock()
	d.anchorInvalid, d.readinessPoisoned, d.factsDirty = true, true, true
	d.egressOK, d.localBinding, d.readinessPassedChallenge = false, nil, ""
	d.mu.Unlock()
	return d.pairFault
}
func (d *Driver) checkAnchorLocked(ctx context.Context) error {
	if d.pairFault != nil {
		return d.pairFault
	}
	if d.anchor == nil {
		return nil
	}
	e, ok := d.Engine.(namespaceAnchorEngine)
	if !ok {
		return d.pairFailure(errors.New("engine lost anchor inspection"))
	}
	actual, err := e.InspectNamespaceAnchor(ctx, d.anchor.id, d.anchor.spec)
	if err != nil {
		return d.pairFailure(err)
	}
	if actual != d.anchor.identity {
		return d.pairFailure(errors.New("anchor identity or configuration changed"))
	}
	return nil
}
func (d *Driver) checkPair(ctx context.Context) error {
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	return d.checkAnchorLocked(ctx)
}
func (d *Driver) createAnchorLocked(ctx context.Context) error {
	e, ok := d.Engine.(namespaceAnchorEngine)
	if !ok {
		return nil
	}
	required, err := e.NamespaceAnchorRequired(ctx)
	if err != nil {
		return err
	}
	if !required {
		return nil
	}
	if d.anchor != nil {
		return d.checkAnchorLocked(ctx)
	}
	spec := d.anchorSpec()
	id, err := d.Engine.CreateContainer(ctx, d.anchorName(), spec)
	if err != nil {
		return err
	}
	d.anchor = &namespaceAnchor{id: id, spec: spec}
	if err = d.Engine.StartContainer(ctx, id); err != nil {
		return d.pairFailure(err)
	}
	identity, err := e.InspectNamespaceAnchor(ctx, id, spec)
	if err != nil {
		return d.pairFailure(err)
	}
	d.anchor.identity = identity
	return nil
}

func configurationDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// A successful delete plus an authoritative absence observation is required
// before removing the namespace anchor. Transport failures are not absence.
func (d *Driver) removeConfirmed(ctx context.Context, id string) error {
	if err := d.Engine.RemoveContainer(ctx, id); err != nil {
		return err
	}
	_, err := d.Engine.InspectContainer(ctx, id)
	if errors.Is(err, errContainerNotFound) || isStatus(err, 404) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("confirm container removal: %w", err)
	}
	return errors.New("removed container still exists")
}

// retirePairLocked is used only after jobs/probes have drained. Keep the
// anchor alive whenever gateway removal cannot be confirmed.
func (d *Driver) retirePairLocked(ctx context.Context) error {
	if d.gw != nil {
		if err := d.removeConfirmed(ctx, d.gw.id); err != nil {
			return err
		}
		d.gw = nil
	}
	if d.anchor != nil {
		if err := d.removeConfirmed(ctx, d.anchor.id); err != nil {
			return err
		}
		d.anchor = nil
	}
	d.pairFault = nil
	return nil
}

func (d *Driver) beginProbe(ctx context.Context) (context.Context, func(), error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		return nil, nil, errors.New("container driver is stopping")
	}
	if d.probeCtx == nil {
		d.probeCtx, d.stopProbes = context.WithCancel(context.Background())
	}
	d.probes.Add(1)
	d.activeProbes++
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.probeCtx, cancel)
	return child, func() {
		stop()
		cancel()
		d.mu.Lock()
		d.activeProbes--
		d.mu.Unlock()
		d.probes.Done()
	}, nil
}

// Finalize follows the manager's job drain. Probe cancellation is separate
// from the manager's job context, so no asynchronous startup probe can race
// gateway/anchor retirement.
func (d *Driver) Finalize(ctx context.Context) error {
	d.mu.Lock()
	d.closing = true
	if d.stopProbes != nil {
		d.stopProbes()
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.probes.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	d.mu.Lock()
	busy := len(d.inUse) != 0
	d.mu.Unlock()
	if busy {
		return errors.New("container jobs have not drained; retaining gateway and anchor")
	}
	if err := d.cleanupPairNetworksLocked(ctx); err != nil {
		return err
	}
	return d.retirePairLocked(ctx)
}
func (d *Driver) cleanupPairNetworksLocked(ctx context.Context) error {
	networks, err := d.Engine.ListNetworks(ctx, map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel()})
	if err != nil {
		return err
	}
	for _, n := range networks {
		if n.Labels[LabelJob] == "" {
			return errors.New("unrecognized owned network; retaining gateway and anchor")
		}
		if err := d.removeNetworkLocked(ctx, n.Name, false); err != nil {
			return err
		}
	}
	return nil
}

// Avoid unbounded cleanup contexts on partial pair creation.
func pairCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}
