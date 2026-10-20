package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/runnerclient"
	"github.com/oyzuai/fleet/telemetry"
)

const (
	// RotateAfter is how old the current key gets before the manager rotates it.
	RotateAfter = 30 * 24 * time.Hour
	// assertionTTL is how long a login or rotation assertion is valid; each
	// is used once, immediately.
	assertionTTL = time.Minute
	// refreshMargin is how long before expiry an access token is replaced.
	refreshMargin = time.Minute
	// rotateRetry spaces out rotation attempts that failed.
	rotateRetry = time.Minute
)

const (
	// reapEvery is how often the manager reaps what its executors left behind.
	reapEvery = 5 * time.Minute
	// releaseTimeout bounds handing a job back to runs.
	releaseTimeout = 30 * time.Second
	// reportEvery is how often the manager reports its facts and slots
	// when nothing changed; runs counts a report older than 30s as stale.
	reportEvery = 10 * time.Second
	// defaultStartTimeout bounds starting an executor when the claim carries
	// no startup expiry; a startup token lives about this long.
	defaultStartTimeout = 5 * time.Minute
	// defaultTeardownTimeout bounds tearing one executor down, so a stalled
	// engine or cluster cannot hold up a drain or a stop.
	defaultTeardownTimeout = 2 * time.Minute
)

// Config configures a Manager.
type Config struct {
	Client *runnerclient.Client
	Store  Store
	// Driver provisions and runs the pool's executors.
	Driver Driver
	// PollInterval is how long to wait after finding no job.
	PollInterval time.Duration
	// DrainTimeout is how long running jobs may keep going after the manager
	// is told to stop, before they are interrupted; 0 interrupts them at once.
	DrainTimeout time.Duration
	// TeardownTimeout bounds tearing one executor down; 2 minutes when 0.
	// A teardown cut short leaves the rest to the reaper.
	TeardownTimeout time.Duration
	// RotateAfter overrides the default key lifetime, for tests.
	RotateAfter time.Duration
	Log         *slog.Logger
	Now         func() time.Time
}

// Manager claims and runs jobs for one enrolled manager.
type Manager struct {
	cfg Config

	mu        sync.Mutex
	st        *State
	current   ed25519.PrivateKey
	next      ed25519.PrivateKey
	access    runnerclient.AccessToken
	lastRetry time.Time

	liveMu sync.Mutex
	live   map[JobID]int
	// starting holds slots whose Start is still running, so the claim loop
	// never offers them again.
	starting map[SlotID]bool
}

// Open loads an enrolled manager from cfg.Store.
func Open(cfg Config) (*Manager, error) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.RotateAfter <= 0 {
		cfg.RotateAfter = RotateAfter
	}
	if cfg.TeardownTimeout <= 0 {
		cfg.TeardownTimeout = defaultTeardownTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	st, err := cfg.Store.Load()
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("this manager is not enrolled; run enroll first")
	}
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, st: st}
	if m.current, err = cfg.Store.PrivateKey(st.Current); err != nil {
		return nil, err
	}
	if st.Next != nil {
		if m.next, err = cfg.Store.PrivateKey(*st.Next); err != nil {
			// A half-written rotation: start it again.
			m.cfg.Log.Warn("dropping the unreadable next key", "error", err)
			st.Next = nil
		}
	}
	return m, nil
}

// State returns a copy of the manager's state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.st
}

// Enroll generates a key, spends an enrollment or rekey token with it and
// saves the manager's state. Rekeying an enrolled manager replaces its keys
// here once runs has accepted the new one.
func Enroll(ctx context.Context, c *runnerclient.Client, s Store, server, audience, token, name string, now time.Time) (st *State, err error) {
	ctx, span := telemetry.Start(ctx, "fleet.manager.enroll", telemetry.Internal)
	defer func() {
		if st != nil {
			span.Int("oyzu.fleet.manager", st.ManagerID)
			span.Int("oyzu.fleet.key", st.Current.ID)
		}
		endSpan(span, ctx, err)
	}()
	prev, err := s.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, priv, err := s.NewKey(now)
	if err != nil {
		return nil, err
	}
	e, err := c.Enroll(ctx, token, name, priv.Public().(ed25519.PublicKey))
	if err != nil {
		_ = s.Remove(key)
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if prev != nil && (!e.Rekeyed || e.ManagerID != prev.ManagerID) {
		_ = s.Remove(key)
		if !e.Rekeyed {
			return nil, fmt.Errorf("this directory holds manager %d, so it needs a rekey token; the token just used "+
				"enrolled a new manager %d, which can be revoked with runs admin revoke-manager --manager %d",
				prev.ManagerID, e.ManagerID, e.ManagerID)
		}
		return nil, fmt.Errorf("this directory holds manager %d, but the rekey token is for manager %d", prev.ManagerID, e.ManagerID)
	}
	key.ID = e.KeyID
	st = &State{Server: server, Audience: audience, ManagerID: e.ManagerID, Pool: e.Pool, Name: e.Name, Current: key}
	if err := s.Save(st); err != nil {
		return nil, err
	}
	if prev != nil {
		_ = s.Remove(prev.Current)
		if prev.Next != nil {
			_ = s.Remove(*prev.Next)
		}
	}
	return st, nil
}

func jti() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *Manager) login(ctx context.Context, k Key, priv ed25519.PrivateKey) (tok runnerclient.AccessToken, err error) {
	ctx, span := telemetry.Start(ctx, "fleet.manager.login", telemetry.Internal)
	span.Int("oyzu.fleet.manager", m.st.ManagerID)
	span.Int("oyzu.fleet.key", k.ID)
	defer func() { endSpan(span, ctx, err) }()
	c := assertion.New(m.st.ManagerID, m.st.Audience, jti(), m.cfg.Now(), assertionTTL)
	a, err := assertion.Sign(priv, k.ID, assertion.TypeLogin, c)
	if err != nil {
		return runnerclient.AccessToken{}, err
	}
	return m.cfg.Client.Login(ctx, a)
}

// endSpan ends span with the outcome err implies. It records a bounded
// reason, never the error text, which can echo a server's detail.
func endSpan(span *telemetry.Span, ctx context.Context, err error) {
	o, reason := telemetry.Classify(ctx, err, 0, errors.Is(err, runnerclient.ErrUnauthenticated))
	if err != nil && !errors.Is(err, runnerclient.ErrUnauthenticated) {
		var se *runnerclient.StatusError
		if errors.As(err, &se) {
			o, reason = telemetry.Classify(ctx, err, se.Status, false)
		}
	}
	span.End(o, reason)
}

// accessToken returns a live access token, logging in when needed.
func (m *Manager) accessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.access.Token != "" && m.cfg.Now().Add(refreshMargin).Before(m.access.Expires) {
		return m.access.Token, nil
	}
	tok, err := m.login(ctx, m.st.Current, m.current)
	if err != nil {
		return "", err
	}
	m.access = tok
	return tok.Token, nil
}

// forget drops an access token runs refused.
func (m *Manager) forget() {
	m.mu.Lock()
	m.access = runnerclient.AccessToken{}
	m.mu.Unlock()
}

// Rotate moves rotation along by one step when it is due. It never takes
// the current key out of service until the new key has logged in, and
// tokens the old key issued stay valid, so job pickup never stops. Errors
// are returned for logging; the caller keeps claiming either way.
func (m *Manager) Rotate(ctx context.Context) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()
	if m.st.Next == nil && now.Sub(m.st.Current.Created) < m.cfg.RotateAfter {
		return nil
	}
	if now.Sub(m.lastRetry) < rotateRetry {
		return nil
	}
	m.lastRetry = now
	s := m.cfg.Store
	ctx, span := telemetry.Start(ctx, "fleet.manager.rotate", telemetry.Internal)
	span.Int("oyzu.fleet.manager", m.st.ManagerID)
	defer func() { endSpan(span, ctx, err) }()

	if m.st.Next == nil {
		k, priv, err := s.NewKey(now)
		if err != nil {
			return fmt.Errorf("generate the next key: %w", err)
		}
		m.st.Next, m.next = &k, priv
		// Saved before it is registered, so a restart resumes the same key.
		if err := s.Save(m.st); err != nil {
			return err
		}
	}
	if m.st.Next.ID == 0 {
		c := assertion.New(m.st.ManagerID, m.st.Audience, jti(), now, assertionTTL)
		c.NewKey = assertion.EncodeKey(m.next.Public().(ed25519.PublicKey))
		a, err := assertion.Sign(m.current, m.st.Current.ID, assertion.TypeRotation, c)
		if err != nil {
			return err
		}
		id, err := m.cfg.Client.RegisterKey(ctx, a)
		if err != nil {
			return fmt.Errorf("register the next key: %w", err)
		}
		m.st.Next.ID = id
		if err := s.Save(m.st); err != nil {
			return err
		}
	}
	// The new key's first login retires the old one at runs.
	tok, err := m.login(ctx, *m.st.Next, m.next)
	if err != nil {
		return fmt.Errorf("log in with the next key: %w", err)
	}
	old := m.st.Current
	m.st.Current, m.current = *m.st.Next, m.next
	m.st.Next, m.next = nil, nil
	m.access = tok
	if err := s.Save(m.st); err != nil {
		return err
	}
	m.lastRetry = time.Time{}
	m.cfg.Log.Info("rotated the manager key", "old_key", old.ID, "key", m.st.Current.ID)
	return s.Remove(old)
}

// Run claims and runs jobs until ctx is done. It claims only when the
// driver has a ready slot, so a lease never waits on a cold start, and asks
// the driver for more slots when the pool's eligible demand exceeds what is
// ready or on its way. An executor that ends badly hands its job back, which
// requeues it without using an attempt when the runner never started. When
// ctx is done the manager claims no more and lets running jobs finish for
// up to DrainTimeout before tearing them down. Executors start off the claim
// loop, so a stalled engine never keeps the manager from noticing a stop;
// a start still running when the drain ends is cut short.
func (m *Manager) Run(ctx context.Context) error {
	log := m.cfg.Log.With("manager", m.st.ManagerID, "pool", m.st.Pool)
	d := m.cfg.Driver
	facts, err := d.Facts(ctx)
	if err != nil {
		log.Warn("pool manager started; the driver reported no facts", "error", err)
	} else {
		log.Info("pool manager started", "facts", facts)
	}
	var reported runnerclient.Report
	var reportedAt time.Time
	// Jobs outlive ctx so that stopping the manager drains it instead of
	// cancelling the work in hand.
	jobCtx, stopJobs := context.WithCancel(context.WithoutCancel(ctx))
	defer stopJobs()
	var wg sync.WaitGroup
	defer func() {
		t := time.AfterFunc(m.cfg.DrainTimeout, func() {
			log.Warn("drain timeout reached; interrupting running jobs", "drain_timeout", m.cfg.DrainTimeout)
			stopJobs()
		})
		wg.Wait()
		t.Stop()
	}()
	// Whatever a predecessor left behind goes first.
	m.reap(ctx, log)
	lastReap := m.cfg.Now()
	for {
		if ctx.Err() != nil {
			log.Info("pool manager stopping; letting running jobs finish", "drain_timeout", m.cfg.DrainTimeout)
			return nil
		}
		if err := m.Rotate(ctx); err != nil {
			log.Warn("key rotation step failed; still using the current key", "error", err)
		}
		if m.cfg.Now().Sub(lastReap) >= reapEvery {
			m.reap(ctx, log)
			lastReap = m.cfg.Now()
			if f, err := d.Facts(ctx); err == nil {
				facts = f
			}
		}
		if fc, ok := d.(FactsChanger); ok && fc.FactsChanged() {
			if f, err := d.Facts(ctx); err == nil {
				facts = f
			}
		}
		capacity, err := d.Capacity(ctx)
		if err == nil {
			capacity = m.withoutStarting(capacity)
		}
		if err != nil {
			log.Warn("the driver reported no capacity", "error", err)
			sleep(ctx, m.cfg.PollInterval)
			continue
		}
		if r := newReport(facts, capacity); !reportEqual(r, reported) || m.cfg.Now().Sub(reportedAt) >= reportEvery {
			if err := m.report(ctx, r); err != nil {
				if ctx.Err() == nil {
					log.Warn("could not report facts and slots", "error", err)
				}
			} else {
				reported, reportedAt = r, m.cfg.Now()
			}
		}
		m.scale(ctx, log, capacity)
		if len(capacity.Ready) == 0 {
			sleep(ctx, m.cfg.PollInterval)
			continue
		}
		c, err := m.Claim(ctx)
		if err != nil || c == nil {
			if err != nil && ctx.Err() == nil {
				log.Warn("claim failed", "error", err)
			}
			sleep(ctx, m.cfg.PollInterval)
			continue
		}
		slot := capacity.Ready[0]
		log.Info("job claimed", "job", c.JobID, "attempt", c.Attempt, "slot", slot)
		m.track(c.JobID, 1)
		m.markStarting(slot, true)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer m.track(c.JobID, -1)
			// One span covers the executor's life; the executor's own spans
			// are its children when the driver can hand it the parent.
			jctx, span := telemetry.Start(jobCtx, "fleet.manager.job", telemetry.Internal)
			span.Int("oyzu.fleet.job", c.JobID)
			span.Int("oyzu.fleet.attempt", int64(c.Attempt))
			span.Int("oyzu.fleet.manager", m.st.ManagerID)
			span.Str("oyzu.fleet.pool", m.st.Pool)
			h, startErr := m.start(jctx, slot, *c)
			m.markStarting(slot, false)
			clean := m.watch(jctx, log, h, *c, startErr)
			if clean {
				span.End(telemetry.Success, "")
			} else {
				span.End(telemetry.Fault, "executor_failed")
			}
		}()
	}
}

// start starts a claimed job's executor under a deadline: the claim's
// startup expiry, after which its token is useless (at least a minute and at
// most defaultStartTimeout away), and the drain timeout through ctx.
func (m *Manager) start(ctx context.Context, slot SlotID, c runnerclient.Claim) (Handle, error) {
	ctx, cancel := context.WithTimeout(ctx, startTimeout(m.cfg.Now(), c))
	defer cancel()
	h, err := m.cfg.Driver.Start(ctx, slot, c)
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w (gave up after %s)", err, context.Cause(ctx))
	}
	return h, err
}

// startTimeout is how long starting c's executor may take. The expiry is on
// runs' clock, so it only shortens the wait, and never below a minute
// however far the clocks disagree.
func startTimeout(now time.Time, c runnerclient.Claim) time.Duration {
	if c.StartupExpires.IsZero() {
		return defaultStartTimeout
	}
	return min(defaultStartTimeout, max(time.Minute, c.StartupExpires.Sub(now)))
}

func (m *Manager) markStarting(slot SlotID, on bool) {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	if m.starting == nil {
		m.starting = map[SlotID]bool{}
	}
	if on {
		m.starting[slot] = true
	} else {
		delete(m.starting, slot)
	}
}

// withoutStarting counts slots whose Start is still running as running
// rather than ready.
func (m *Manager) withoutStarting(c Capacity) Capacity {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	if len(m.starting) == 0 {
		return c
	}
	ready := make([]SlotID, 0, len(c.Ready))
	for _, s := range c.Ready {
		if m.starting[s] {
			c.Running++
			continue
		}
		ready = append(ready, s)
	}
	c.Ready = ready
	return c
}

// watch waits for a started executor, hands its job back when it ended
// badly, and tears it down.
func (m *Manager) watch(ctx context.Context, log *slog.Logger, h Handle, c runnerclient.Claim, startErr error) (clean bool) {
	d := m.cfg.Driver
	log = log.With("job", c.JobID, "attempt", c.Attempt, "slot", h.Slot)
	var exit Exit
	if startErr != nil {
		exit = Exit{Reason: ExitLost, Code: -1, Detail: "the executor did not start: " + startErr.Error()}
	} else {
		var err error
		if exit, err = d.Wait(ctx, h); err != nil {
			exit = Exit{Reason: ExitLost, Code: -1, Detail: "stopped waiting for the executor: " + err.Error()}
		}
	}
	clean = exit.Clean()
	if clean {
		log.Info("job runner exited")
	} else {
		log.Warn("job runner ended badly", "exit", exit.String())
		// Released first so the job is offered again while teardown runs.
		m.release(ctx, log, c, exit)
	}
	if h.Ref == "" {
		return clean
	}
	tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cfg.TeardownTimeout)
	defer cancel()
	if err := d.Teardown(tctx, h); err != nil {
		log.Warn("teardown failed; the reaper will retry", "error", err)
	}
	return clean
}

// release hands a job back to runs. Runs requeues it without using an
// attempt only if its runner never started; otherwise the runner already
// reported, or its lease expiry deals with it.
func (m *Manager) release(ctx context.Context, log *slog.Logger, c runnerclient.Claim, exit Exit) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	tok, err := m.accessToken(ctx)
	if err != nil {
		log.Warn("could not hand the job back; its lease will expire", "error", err)
		return
	}
	released, err := m.cfg.Client.Release(ctx, tok, runnerclient.Release{JobID: c.JobID, Attempt: c.Attempt, Reason: exit.String()})
	switch {
	case errors.Is(err, runnerclient.ErrUnauthenticated):
		m.forget()
		log.Warn("could not hand the job back; its lease will expire", "error", err)
	case err != nil:
		log.Warn("could not hand the job back; its lease will expire", "error", err)
	case released:
		log.Info("handed the job back before its runner started; it is requeued without using an attempt")
	default:
		log.Info("the job's runner had started, so it was not handed back")
	}
}

// scale asks the driver for more slots when the pool's eligible demand is
// more than its ready and provisioning slots, up to the driver's maximum.
// A driver whose slots are always ready never has room, so it never asks.
func (m *Manager) scale(ctx context.Context, log *slog.Logger, c Capacity) {
	room := c.Room()
	if room == 0 {
		return
	}
	demand, err := m.demand(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("could not read the pool's demand", "error", err)
		}
		return
	}
	n := min(room, demand.Eligible-len(c.Ready)-c.Provisioning)
	if n <= 0 {
		return
	}
	if err := m.cfg.Driver.Provision(ctx, n); err != nil {
		log.Warn("provisioning failed", "slots", n, "error", err)
		return
	}
	log.Info("provisioning executors", "slots", n, "eligible", demand.Eligible, "ready", len(c.Ready),
		"provisioning", c.Provisioning, "running", c.Running, "max", c.Max)
}

// newReport is what the manager reports: its driver's oyzu.io/ facts and its
// slots.
func newReport(facts Facts, c Capacity) runnerclient.Report {
	r := runnerclient.Report{Facts: map[string]string{}, Slots: runnerclient.Slots{
		Max: c.Max, Running: c.Running, Ready: len(c.Ready), Provisioning: c.Provisioning,
	}}
	for k, v := range facts {
		if strings.HasPrefix(k, "oyzu.io/") && v != "" {
			r.Facts[k] = v
		}
	}
	return r
}

func reportEqual(a, b runnerclient.Report) bool {
	return a.Slots == b.Slots && maps.Equal(a.Facts, b.Facts)
}

func (m *Manager) report(ctx context.Context, r runnerclient.Report) error {
	tok, err := m.accessToken(ctx)
	if err != nil {
		return err
	}
	err = m.cfg.Client.Report(ctx, tok, r)
	if errors.Is(err, runnerclient.ErrUnauthenticated) {
		m.forget()
	}
	return err
}

func (m *Manager) demand(ctx context.Context) (runnerclient.Demand, error) {
	tok, err := m.accessToken(ctx)
	if err != nil {
		return runnerclient.Demand{}, err
	}
	d, err := m.cfg.Client.Demand(ctx, tok)
	if errors.Is(err, runnerclient.ErrUnauthenticated) {
		m.forget()
	}
	return d, err
}

// track counts a job in or out of the live set Reap is given.
func (m *Manager) track(job JobID, delta int) {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	if m.live == nil {
		m.live = map[JobID]int{}
	}
	if m.live[job] += delta; m.live[job] <= 0 {
		delete(m.live, job)
	}
}

func (m *Manager) reap(ctx context.Context, log *slog.Logger) {
	m.liveMu.Lock()
	live := make([]JobID, 0, len(m.live))
	for j := range m.live {
		live = append(live, j)
	}
	m.liveMu.Unlock()
	if err := m.cfg.Driver.Reap(ctx, live); err != nil && ctx.Err() == nil {
		log.Warn("reaping failed", "error", err)
	}
}

// Claim asks runs for one job with the manager's credentials, logging in
// when needed. Run calls it in its loop; callers that drive a manager by
// hand, such as end-to-end tests, call it directly.
func (m *Manager) Claim(ctx context.Context) (c *runnerclient.Claim, err error) {
	ctx, span := telemetry.Start(ctx, "fleet.manager.claim", telemetry.Internal)
	span.Int("oyzu.fleet.manager", m.st.ManagerID)
	defer func() {
		if c != nil {
			span.Int("oyzu.fleet.job", c.JobID)
			span.Int("oyzu.fleet.attempt", int64(c.Attempt))
		}
		endSpan(span, ctx, err)
	}()
	tok, err := m.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	c, err = m.cfg.Client.Claim(ctx, tok)
	if errors.Is(err, runnerclient.ErrUnauthenticated) {
		m.forget()
	}
	return c, err
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
