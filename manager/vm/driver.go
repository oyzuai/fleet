package vm

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// Defaults for the Driver's durations.
const (
	defaultBootTimeout  = 10 * time.Minute
	defaultMaxIdle      = 10 * time.Minute
	defaultMaxAge       = 24 * time.Hour
	defaultPollInterval = 15 * time.Second
	defaultLeaseGrace   = 5 * time.Minute
	// reapGrace leaves alone instances launched this recently, so a Create
	// whose id is not registered yet is never mistaken for a leftover.
	reapGrace = 2 * time.Minute
)

// Errors the handover reports to an instance's agent.
var (
	ErrUnknownInstance = errors.New("the instance is not one this manager launched for its pool")
	ErrWrongAddress    = errors.New("the request did not come from the instance's own address")
	ErrWrongImage      = errors.New("the instance was not booted from the pool's image")
	ErrAlreadyHanded   = errors.New("the instance already started its executor")
	ErrNotAssigned     = errors.New("the instance has not collected a job to report on")
)

// Driver runs each job on a fresh cloud VM. It keeps Warm booted instances
// ready, boots more on demand up to Max, hands a claimed job's startup token
// only to the instance that proves with its provider-signed identity that it
// is the one assigned, and destroys every instance after one job. It never
// puts a secret in user data or instance metadata.
//
// Instances report through Handler, which the manager serves inside the
// pool's network: an agent on each instance checks in when booted, collects
// its assignment, acknowledges it once the executor has the token, and
// reports how the executor exited. Until the acknowledgement the instance
// may collect the assignment again, so a response lost on the way does not
// strand the job; an instance that collected but never acknowledges is
// failed once the startup token and a job lease after it have run out.
type Driver struct {
	Cloud Cloud
	Spec  Spec
	// Pool and Manager name this manager; every instance is tagged with
	// them.
	Pool    string
	Manager int64
	// Warm is how many booted, unassigned instances to keep ready.
	Warm int
	// Max is the most instances the pool may have at once; at least 1.
	Max int
	// BootTimeout is how long an instance may take to check in before it
	// is destroyed as failed.
	BootTimeout time.Duration
	// MaxIdle is how long a ready instance beyond the warm count may wait
	// for a job before it is destroyed.
	MaxIdle time.Duration
	// MaxAge replaces ready instances older than this, so warm machines
	// pick up a new image.
	MaxAge time.Duration
	// PollInterval is how often Wait asks the provider about an assigned
	// instance.
	PollInterval time.Duration
	// LeaseGrace is how long past the startup token's expiry an instance
	// that collected its assignment may go without acknowledging it before
	// its slot is failed: at least the job lease runs gives a started
	// runner, so an executor that did start has lost its job by then. 5
	// minutes when 0.
	LeaseGrace time.Duration
	Log        *slog.Logger
	Now        func() time.Time

	mu       sync.Mutex
	pending  int
	machines map[string]*machine
	// creating tracks Create calls in flight, for tests.
	creating sync.WaitGroup
}

type phase int

const (
	booting phase = iota
	ready
	assigned
)

// machine is one tracked instance.
type machine struct {
	id      string
	phase   phase
	created time.Time
	readyAt time.Time
	address string
	claim   runnerclient.Claim
	// fetched is set once the agent collected the assignment, and handed
	// once it acknowledged starting the executor; after that the
	// assignment is not served again.
	fetched bool
	handed  bool
	// assignedCh closes when a job is assigned, waking a waiting agent.
	assignedCh chan struct{}
	// exited closes once exit is set.
	exited   chan struct{}
	finished bool
	exit     manager.Exit
}

var _ manager.Driver = (*Driver)(nil)

func (d *Driver) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Driver) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func (d *Driver) max() int { return max(1, d.Max) }

func or(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func (d *Driver) managerTag() string { return strconv.FormatInt(d.Manager, 10) }

// Facts implements manager.Driver: the shape's facts from the provider's
// catalogue, plus whole-machine isolation and a Docker daemon of each job's
// own.
func (d *Driver) Facts(ctx context.Context) (manager.Facts, error) {
	f, err := d.Cloud.Facts(ctx, d.Spec)
	if err != nil {
		return nil, err
	}
	out := manager.Facts{}
	maps.Copy(out, f)
	out[manager.FactIsolation] = "vm"
	out[manager.FactDocker] = "true"
	return out, nil
}

// Capacity implements manager.Driver. It first retires instances that
// never checked in, have idled too long beyond the warm count or are too
// old, and boots replacements to keep the warm count.
func (d *Driver) Capacity(ctx context.Context) (manager.Capacity, error) {
	d.housekeep(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	c := manager.Capacity{Max: d.max(), Provisioning: d.pending}
	for _, m := range d.readyLocked() {
		c.Ready = append(c.Ready, manager.SlotID(m.id))
	}
	for _, m := range d.machines {
		switch m.phase {
		case booting:
			c.Provisioning++
		case assigned:
			c.Running++
		}
	}
	return c, nil
}

// readyLocked lists ready instances, longest ready first.
func (d *Driver) readyLocked() []*machine {
	var out []*machine
	for _, m := range d.machines {
		if m.phase == ready {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b *machine) int {
		if c := a.readyAt.Compare(b.readyAt); c != 0 {
			return c
		}
		return cmp.Compare(a.id, b.id)
	})
	return out
}

func (d *Driver) housekeep(ctx context.Context) {
	now := d.now()
	type retire struct{ id, why string }
	var retired []retire
	d.mu.Lock()
	for id, m := range d.machines {
		switch {
		case m.phase == booting && now.Sub(m.created) > or(d.BootTimeout, defaultBootTimeout):
			retired = append(retired, retire{id, "it did not check in within the boot timeout"})
		case m.phase == ready && now.Sub(m.created) > or(d.MaxAge, defaultMaxAge):
			retired = append(retired, retire{id, "it reached the maximum age"})
		}
	}
	for _, r := range retired {
		delete(d.machines, r.id)
	}
	if surplus := len(d.readyLocked()) - d.Warm; surplus > 0 {
		for _, m := range d.readyLocked() {
			if surplus == 0 {
				break
			}
			if now.Sub(m.readyAt) > or(d.MaxIdle, defaultMaxIdle) {
				retired = append(retired, retire{m.id, "it idled beyond the warm count"})
				delete(d.machines, m.id)
				surplus--
			}
		}
	}
	warmGap := d.Warm - d.pending
	for _, m := range d.machines {
		if m.phase != assigned {
			warmGap--
		}
	}
	d.mu.Unlock()
	for _, r := range retired {
		d.log().Info("destroying an instance", "instance", r.id, "reason", r.why)
		if err := d.Cloud.Destroy(ctx, r.id); err != nil {
			d.log().Warn("destroying an instance failed; the reaper will retry", "instance", r.id, "error", err)
		}
	}
	if warmGap > 0 {
		_ = d.Provision(ctx, warmGap)
	}
}

// Provision implements manager.Driver. It asks the provider for n more
// instances, up to Max, and returns without waiting for them to boot.
func (d *Driver) Provision(ctx context.Context, n int) error {
	d.mu.Lock()
	n = min(n, d.max()-d.pending-len(d.machines))
	if n <= 0 {
		d.mu.Unlock()
		return nil
	}
	d.pending += n
	d.mu.Unlock()
	tags := map[string]string{TagPool: d.Pool, TagManager: d.managerTag()}
	ctx = context.WithoutCancel(ctx)
	for range n {
		d.creating.Add(1)
		go func() {
			defer d.creating.Done()
			id, err := d.Cloud.Create(ctx, d.Spec, tags)
			d.mu.Lock()
			d.pending--
			if err == nil {
				if d.machines == nil {
					d.machines = map[string]*machine{}
				}
				d.machines[id] = &machine{id: id, phase: booting, created: d.now(),
					assignedCh: make(chan struct{}), exited: make(chan struct{})}
			}
			d.mu.Unlock()
			if err != nil {
				d.log().Warn("booting an instance failed", "error", err)
				return
			}
			d.log().Info("booting an instance", "instance", id)
		}()
	}
	return nil
}

// Start implements manager.Driver: it assigns the claim to a ready
// instance, whose agent then collects the startup token through Handler.
func (d *Driver) Start(ctx context.Context, slot manager.SlotID, c runnerclient.Claim) (manager.Handle, error) {
	h := manager.Handle{Slot: slot, Job: c.JobID, Attempt: c.Attempt}
	d.mu.Lock()
	m := d.machines[string(slot)]
	if m == nil || m.phase != ready {
		d.mu.Unlock()
		return h, fmt.Errorf("instance %s is not ready", slot)
	}
	m.phase = assigned
	m.claim = c
	close(m.assignedCh)
	d.mu.Unlock()
	h.Ref = m.id
	if err := d.Cloud.Tag(ctx, m.id, map[string]string{TagJob: strconv.FormatInt(c.JobID, 10)}); err != nil {
		d.log().Warn("tagging an instance with its job failed", "instance", m.id, "error", err)
	}
	return h, nil
}

// Wait implements manager.Driver. It returns when the instance's agent
// reports the executor's exit, the provider stops or reclaims the instance,
// or the agent never collects its startup token before it expires.
func (d *Driver) Wait(ctx context.Context, h manager.Handle) (manager.Exit, error) {
	d.mu.Lock()
	m := d.machines[h.Ref]
	d.mu.Unlock()
	if m == nil {
		return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: "the instance is no longer tracked"}, nil
	}
	t := time.NewTicker(or(d.PollInterval, defaultPollInterval))
	defer t.Stop()
	for {
		select {
		case <-m.exited:
			return m.exit, nil
		case <-ctx.Done():
			return manager.Exit{}, ctx.Err()
		case <-t.C:
		}
		if exit, done := d.check(ctx, m); done {
			d.finish(m, exit)
		}
	}
}

// check looks for an assigned instance that will never report.
func (d *Driver) check(ctx context.Context, m *machine) (manager.Exit, bool) {
	d.mu.Lock()
	fetched, handed, expires := m.fetched, m.handed, m.claim.StartupExpires
	d.mu.Unlock()
	if !handed && !expires.IsZero() {
		now := d.now()
		switch {
		case !fetched && now.After(expires):
			return lost("the instance never collected its startup token"), true
		case fetched && now.After(expires.Add(or(d.LeaseGrace, defaultLeaseGrace))):
			return lost("the instance collected its startup token but never acknowledged starting the executor"), true
		}
	}
	found, err := d.Cloud.Describe(ctx, []string{m.id})
	if err != nil {
		d.log().Warn("describing an instance failed", "instance", m.id, "error", err)
		return manager.Exit{}, false
	}
	inst, ok := found[m.id]
	switch {
	case !ok || inst.State == StateGone || inst.State == StateStopping:
		if inst.Preempted {
			return lost("the provider reclaimed the spot instance"), true
		}
		detail := "the instance stopped"
		if inst.Detail != "" {
			detail += ": " + inst.Detail
		}
		return lost(detail), true
	}
	return manager.Exit{}, false
}

func lost(detail string) manager.Exit {
	return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: detail}
}

// finish records how an instance's executor ended, once.
func (d *Driver) finish(m *machine, exit manager.Exit) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m.finished {
		return
	}
	m.finished = true
	m.exit = exit
	close(m.exited)
}

// Teardown implements manager.Driver: the instance is destroyed, never
// returned to the pool. If destroying fails the instance is still dropped
// from tracking, so the reaper finds it by its tags and retries.
func (d *Driver) Teardown(ctx context.Context, h manager.Handle) error {
	if h.Ref == "" {
		return nil
	}
	d.mu.Lock()
	m := d.machines[h.Ref]
	delete(d.machines, h.Ref)
	d.mu.Unlock()
	if m != nil {
		d.finish(m, lost("the instance was torn down"))
	}
	return d.Cloud.Destroy(ctx, h.Ref)
}

// Reap implements manager.Driver: it destroys every instance tagged with
// this manager that it is not tracking and that serves no live job, such as
// what a crashed predecessor left behind.
func (d *Driver) Reap(ctx context.Context, live []manager.JobID) error {
	found, err := d.Cloud.List(ctx, d.managerTag())
	if err != nil {
		return err
	}
	keepJob := map[string]bool{}
	for _, j := range live {
		keepJob[strconv.FormatInt(j, 10)] = true
	}
	d.mu.Lock()
	tracked := map[string]bool{}
	for id := range d.machines {
		tracked[id] = true
	}
	d.mu.Unlock()
	now := d.now()
	var errs []error
	for _, inst := range found {
		switch {
		case inst.State == StateGone, tracked[inst.ID], now.Sub(inst.Launched) < reapGrace:
			continue
		case inst.Tags[TagJob] != "" && keepJob[inst.Tags[TagJob]]:
			continue
		}
		if err := d.Cloud.Destroy(ctx, inst.ID); err != nil {
			errs = append(errs, fmt.Errorf("destroy %s: %w", inst.ID, err))
			continue
		}
		d.log().Info("reaped an instance", "instance", inst.ID, "job", inst.Tags[TagJob])
	}
	return errors.Join(errs...)
}

// verify establishes which tracked instance an agent's request comes from:
// the provider-signed proof must name an instance this manager launched for
// its pool, from the pool's image, and the request must come from that
// instance's own private address. A proof can be replayed while it is valid:
// AWS's identity document never changes for an instance's life, and the
// tokens Google Cloud and Azure issue last about an hour. So the address
// check, and the handover closing once the instance acknowledges it, are what
// stop a copied proof from being used elsewhere, and agents fetch a fresh
// proof for every request.
func (d *Driver) verify(ctx context.Context, proof Proof, remote string) (*machine, error) {
	ident, err := d.Cloud.VerifyIdentity(ctx, proof)
	if err != nil {
		return nil, err
	}
	if ident.Image != d.Spec.Image {
		return nil, ErrWrongImage
	}
	d.mu.Lock()
	m := d.machines[ident.InstanceID]
	var address string
	if m != nil {
		address = m.address
	}
	d.mu.Unlock()
	if m == nil {
		return nil, ErrUnknownInstance
	}
	if address == "" {
		found, err := d.Cloud.Describe(ctx, []string{m.id})
		if err != nil {
			return nil, fmt.Errorf("describe %s: %w", m.id, err)
		}
		address = found[m.id].Address
		d.mu.Lock()
		m.address = address
		d.mu.Unlock()
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if address == "" || host != address {
		return nil, ErrWrongAddress
	}
	return m, nil
}

// checkIn marks a booted instance ready for a job.
func (d *Driver) checkIn(ctx context.Context, proof Proof, remote string) error {
	m, err := d.verify(ctx, proof, remote)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if m.phase == booting {
		m.phase = ready
		m.readyAt = d.now()
		d.log().Info("instance ready", "instance", m.id)
	}
	return nil
}

// assignment hands an instance its job's claim, waiting up to wait for one
// to be assigned. It returns nil when none was assigned yet. The same
// verified instance may collect it again until it acknowledges, so a lost
// response is retried rather than holding the slot.
func (d *Driver) assignment(ctx context.Context, proof Proof, remote string, wait time.Duration) (*runnerclient.Claim, error) {
	m, err := d.verify(ctx, proof, remote)
	if err != nil {
		return nil, err
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-m.assignedCh:
	case <-t.C:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if m.handed {
		return nil, ErrAlreadyHanded
	}
	m.fetched = true
	c := m.claim
	return &c, nil
}

// acknowledge records that the instance's executor has its startup token;
// the assignment is not served again. Acknowledging twice succeeds.
func (d *Driver) acknowledge(ctx context.Context, proof Proof, remote string) error {
	m, err := d.verify(ctx, proof, remote)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !m.fetched {
		return ErrNotAssigned
	}
	m.handed = true
	return nil
}

// reportExit records how the instance's executor exited.
func (d *Driver) reportExit(ctx context.Context, proof Proof, remote string, code int, detail string) error {
	m, err := d.verify(ctx, proof, remote)
	if err != nil {
		return err
	}
	// An exit report implies the acknowledgement it may have overtaken.
	d.mu.Lock()
	fetched := m.fetched
	m.handed = m.handed || fetched
	d.mu.Unlock()
	if !fetched {
		return ErrNotAssigned
	}
	d.finish(m, manager.Exit{Reason: manager.ExitExited, Code: code, Detail: detail})
	return nil
}
