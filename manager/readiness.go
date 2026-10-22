package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/runnerclient"
)

// ReadinessDriver measures and checks its actual execution boundary. The
// manager owns protocol credentials; this interface receives none of them.
type ReadinessDriver interface {
	EnableReadiness()
	ReadinessBoundary(context.Context) (readiness.Boundary, error)
	ApplyReadinessMode(context.Context, string) (bool, error)
	SetReadiness(*readiness.Binding)
	ProbeReadiness(context.Context, readiness.Challenge) readiness.Result
	CheckReadiness(context.Context, *readiness.Binding) error
}

func (m *Manager) beginReadiness(ctx context.Context) error {
	d, ok := m.cfg.Driver.(ReadinessDriver)
	if !ok {
		d = &unsupportedReadinessDriver{driver: m.cfg.Driver}
	}
	m.readinessDriver = d
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	token, err := m.accessToken(ctx)
	if err != nil {
		return err
	}
	session, err := m.cfg.Client.ReadinessSession(ctx, token, hex.EncodeToString(boot[:]))
	if err != nil {
		return fmt.Errorf("open readiness session: %w", err)
	}
	if session.Enabled {
		if session.ID == "" {
			return errors.New("server returned an empty readiness session")
		}
		m.mu.Lock()
		m.readinessSession = session.ID
		m.mu.Unlock()
		d.EnableReadiness()
	}
	return nil
}

// readinessStep runs before claiming, even with zero ready capacity. Probing
// runs separately so manager liveness and capacity reports continue.
func (m *Manager) readinessStep(ctx context.Context, report runnerclient.Report) bool {
	m.mu.Lock()
	session := m.readinessSession
	m.mu.Unlock()
	if session == "" {
		return true
	}
	d := m.readinessDriver
	runCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	b, err := d.ReadinessBoundary(ctx)
	if err != nil {
		d.SetReadiness(nil)
		return false
	}
	token, err := m.accessToken(ctx)
	if err != nil {
		d.SetReadiness(nil)
		return false
	}
	m.mu.Lock()
	changed := m.readinessFingerprint != b.Fingerprint()
	m.mu.Unlock()
	if changed {
		d.SetReadiness(nil)
		if err = m.cfg.Client.Report(ctx, token, func() runnerclient.Report { report.Session = session; report.Boundary = &b; return report }()); err != nil {
			return false
		}
		m.mu.Lock()
		m.readinessFingerprint = b.Fingerprint()
		m.mu.Unlock()
	}
	work, err := m.cfg.Client.ReadinessWork(ctx, token, session)
	if err != nil {
		if errors.Is(err, runnerclient.ErrUnauthenticated) {
			d.SetReadiness(nil)
			m.forget()
		}
		return false
	}
	applied, err := d.ApplyReadinessMode(ctx, work.Mode)
	if err != nil || !applied {
		d.SetReadiness(nil)
		return false
	}
	actual, err := d.ReadinessBoundary(ctx)
	if err != nil || actual.Fingerprint() != b.Fingerprint() {
		d.SetReadiness(nil)
		return false
	}
	d.SetReadiness(work.Binding)
	if latch, ok := d.(interface{ ReadinessInvalidated() bool }); ok && latch.ReadinessInvalidated() && work.Binding != nil {
		// Retry a known violation that the watcher's bounded first delivery may
		// have lost. Once the server clears its binding this does not keep
		// advancing generations while a fresh measurement is pending.
		_ = m.cfg.Client.ReadinessInvalidate(ctx, token, session, work.Generation)
		return false
	}
	if work.Challenge != nil {
		c := *work.Challenge
		if c.Session != session || c.Fingerprint != b.Fingerprint() {
			d.SetReadiness(nil)
			return false
		}
		m.mu.Lock()
		busy := m.readinessBusy || m.readinessLastChallenge == c.ID
		if !busy {
			m.readinessBusy = true
			m.readinessLastChallenge = c.ID
		}
		m.mu.Unlock()
		if !busy {
			go m.measureReadiness(runCtx, d, c)
		}
	}
	return b.Mode != "enforce" || (work.Binding != nil && d.CheckReadiness(ctx, work.Binding) == nil)
}
func (m *Manager) measureReadiness(parent context.Context, d ReadinessDriver, c readiness.Challenge) {
	defer func() { m.mu.Lock(); m.readinessBusy = false; m.mu.Unlock() }()
	// Parent cancellation is deliberately separate from a short work-poll timeout.
	// The server challenge is an absolute bound, including result retries.
	ctx, cancel := context.WithDeadline(parent, c.Deadline)
	defer cancel()
	result := d.ProbeReadiness(ctx, c)
	for ctx.Err() == nil {
		token, err := m.accessToken(ctx)
		if err == nil {
			err = m.cfg.Client.ReadinessResult(ctx, token, result)
		}
		if err == nil {
			return
		}
		var status *runnerclient.StatusError
		if errors.Is(err, runnerclient.ErrUnauthenticated) || (errors.As(err, &status) && status.Status >= 400 && status.Status < 500) {
			return
		}
		if !sleep(ctx, 2*time.Second) {
			return
		}
	}
}

// Unqualified drivers report their limitation honestly. In particular an
// unpinned Kubernetes manager cannot certify all nodes with one pod probe.
type unsupportedReadinessDriver struct{ driver Driver }

func (d *unsupportedReadinessDriver) EnableReadiness() {}
func (d *unsupportedReadinessDriver) ReadinessBoundary(ctx context.Context) (readiness.Boundary, error) {
	facts, err := d.driver.Facts(ctx)
	if err != nil {
		return readiness.Boundary{}, err
	}
	kind := facts[FactIsolation]
	if kind == "pod" || kind == "sandboxed-pod" {
		kind = "kubernetes"
	}
	if kind != "vm" && kind != "kubernetes" {
		kind = "process"
	}
	return readiness.Boundary{Driver: kind, Support: "unsupported", Mode: "open"}, nil
}
func (d *unsupportedReadinessDriver) ApplyReadinessMode(_ context.Context, mode string) (bool, error) {
	return mode != "enforce", nil
}
func (d *unsupportedReadinessDriver) SetReadiness(*readiness.Binding) {}
func (d *unsupportedReadinessDriver) CheckReadiness(context.Context, *readiness.Binding) error {
	return errors.New("driver is not qualified for typed readiness")
}
func (d *unsupportedReadinessDriver) ProbeReadiness(_ context.Context, c readiness.Challenge) readiness.Result {
	r := readiness.Result{Challenge: c.ID, Session: c.Session, Generation: c.Generation, Fingerprint: c.Fingerprint, Suite: c.Suite}
	r.Aggregate()
	return r
}

// A live allocation must keep the measured network and pinned image as well as
// the boundary template. A known violation is reported before teardown returns.
type readinessAllocationChecker interface {
	CheckReadinessAllocation(context.Context, Handle, *readiness.Binding) error
}

func (m *Manager) checkReadinessAssignment(ctx context.Context, d ReadinessDriver, h Handle, b *readiness.Binding) error {
	err := d.CheckReadiness(ctx, b)
	if err == nil {
		if checker, ok := m.cfg.Driver.(readinessAllocationChecker); ok {
			err = checker.CheckReadinessAllocation(ctx, h, b)
		}
	}
	if err != nil {
		d.SetReadiness(nil)
		token, tokenErr := m.accessToken(ctx)
		if tokenErr == nil && errors.Is(err, readiness.ErrBoundaryChanged) {
			_ = m.cfg.Client.ReadinessInvalidate(ctx, token, b.Session, b.Generation)
		}
	}
	return err
}
