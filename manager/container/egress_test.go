package container

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// fakeControl stands in for the gateway's control API.
type fakeControl struct {
	mu       sync.Mutex
	regs     map[string]egressgate.Registration
	history  []string
	denied   map[string][]egressgate.Denial
	healthy  error
	registry error
}

func newFakeControl() *fakeControl {
	return &fakeControl{regs: map[string]egressgate.Registration{}, denied: map[string][]egressgate.Denial{}}
}

func (f *fakeControl) Health(context.Context) error { return f.healthy }

func (f *fakeControl) Register(_ context.Context, r egressgate.Registration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registry != nil {
		return f.registry
	}
	f.regs[r.Job] = r
	f.history = append(f.history, "register "+r.Job)
	// The probe's denied destination is what the real gateway would record.
	if strings.Contains(r.Job, "-probe-") {
		f.denied[r.Job] = []egressgate.Denial{{Host: "probe.invalid", Port: 443, Method: "CONNECT"}}
	}
	return nil
}

func (f *fakeControl) Unregister(_ context.Context, job string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.regs, job)
	f.history = append(f.history, "unregister "+job)
	return nil
}

func (f *fakeControl) Denials(_ context.Context, job string, _ int) (egressgate.DenialsReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return egressgate.DenialsReply{Denials: f.denied[job]}, nil
}

func sandboxDriver(e *fakeEngine, mode EgressMode) (*Driver, *fakeControl) {
	d := newDriver(e)
	d.Egress = mode
	d.Pool = "linux"
	ctl := newFakeControl()
	d.Control = func(string, string) GatewayControl { return ctl }
	return d, ctl
}

// settle waits for the pull and the self-test to finish.
func settle(t *testing.T, d *Driver) manager.Capacity {
	t.Helper()
	return ready(t, d)
}

func TestCheckEgressRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Driver)
		ok   bool
	}{
		{"enforce alone", func(d *Driver) { d.Egress = EgressEnforce }, true},
		{"report alone", func(d *Driver) { d.Egress = EgressReport }, true},
		{"open with a network", func(d *Driver) { d.Egress, d.Network = EgressOpen, "builders" }, true},
		{"default mode with a network", func(d *Driver) { d.Network = "builders" }, true},
		{"enforce with a network", func(d *Driver) { d.Egress, d.Network = EgressEnforce, "builders" }, false},
		{"report with a network", func(d *Driver) { d.Egress, d.Network = EgressReport, "bridge" }, false},
		{"unknown mode", func(d *Driver) { d.Egress = "strict" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(newFakeEngine())
			tc.edit(d)
			if err := d.Check(); (err == nil) != tc.ok {
				t.Fatalf("Check = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestFactsReportEgressAndOnlyAnEnforcedPoolTakesUntrustedWork(t *testing.T) {
	ctx := context.Background()
	facts := func(d *Driver) manager.Facts {
		f, err := d.Facts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	// Open, the default: no untrusted work.
	f := facts(newDriver(newFakeEngine()))
	if f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
		t.Fatalf("open facts = %v", f)
	}
	// Report: never untrusted.
	e := newFakeEngine()
	e.present = true
	d, _ := sandboxDriver(e, EgressReport)
	settle(t, d)
	if f := facts(d); f[manager.FactEgress] != "report" || f[manager.FactUntrusted] != "" {
		t.Fatalf("report facts = %v", f)
	}
	// Enforce, before the self-test has passed, is still open.
	e2 := newFakeEngine()
	e2.present = true
	d2, _ := sandboxDriver(e2, EgressEnforce)
	if f := facts(d2); f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
		t.Fatalf("enforce before the self-test = %v", f)
	}
	settle(t, d2)
	f = facts(d2)
	if f[manager.FactEgress] != "enforced" || f[manager.FactUntrusted] != "accepted" || f[manager.FactIsolation] != "container" {
		t.Fatalf("enforce after the self-test = %v", f)
	}
	if !d2.FactsChanged() || d2.FactsChanged() {
		t.Fatal("FactsChanged must report the self-test's result once")
	}
}

func TestAFailedSelfTestReportsOpenAndTakesNoUntrustedWork(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	e.probeExit = 1
	d, ctl := sandboxDriver(e, EgressEnforce)
	c := settle(t, d)
	if len(c.Ready) == 0 {
		t.Fatalf("a pool that failed its self-test must still run trusted work: %+v", c)
	}
	f, _ := d.Facts(context.Background())
	if f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
		t.Fatalf("facts after a failed self-test = %v", f)
	}
	// The probe's network and container are gone either way.
	if len(e.networks) != 0 {
		t.Fatalf("networks left behind: %v", e.networks)
	}
	if len(ctl.regs) != 0 {
		t.Fatalf("registrations left behind: %v", ctl.regs)
	}
	// It is tried again after pullRetry, and passes once the cause is fixed.
	e.mu.Lock()
	e.probeExit = 0
	e.mu.Unlock()
	d.Now = func() time.Time { return time.Now().Add(2 * pullRetry) }
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.Capacity(context.Background())
		if f, _ := d.Facts(context.Background()); f[manager.FactEgress] == "enforced" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the pool never recovered after the self-test passed")
}

func TestSelfTestNeedsTheGatewayToSeeTheDenial(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, ctl := sandboxDriver(e, EgressEnforce)
	// A gateway that recorded nothing for the probe did not do the refusing.
	d.Control = func(string, string) GatewayControl { return silentControl{ctl} }
	settle(t, d)
	if f, _ := d.Facts(context.Background()); f[manager.FactEgress] != "open" {
		t.Fatalf("facts = %v", f)
	}
}

type silentControl struct{ *fakeControl }

func (silentControl) Denials(context.Context, string, int) (egressgate.DenialsReply, error) {
	return egressgate.DenialsReply{}, nil
}

func TestGatewayFailureFailsTheSelfTestAndTheStart(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, ctl := sandboxDriver(e, EgressEnforce)
	ctl.registry = errors.New("control refused")
	settle(t, d)
	if f, _ := d.Facts(context.Background()); f[manager.FactEgress] != "open" {
		t.Fatalf("facts = %v", f)
	}
	_, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 5, Attempt: 1})
	if err == nil || !strings.Contains(err.Error(), "register the job") {
		t.Fatalf("Start = %v", err)
	}
}

func startJob(t *testing.T, d *Driver, slot manager.SlotID, id int64, allow ...runnerclient.EgressAllow) manager.Handle {
	t.Helper()
	h, err := d.Start(context.Background(), slot, runnerclient.Claim{
		JobID: id, Attempt: 1, StartupToken: "st_secret", Egress: runnerclient.ClaimEgress{Allow: allow},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *fakeEngine) byName(prefix string) *fakeContainer {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.containers {
		if strings.HasPrefix(c.name, prefix) {
			return c
		}
	}
	return nil
}

func TestEnforcedJobsGetTheirOwnInternalNetworkBehindTheGateway(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, ctl := sandboxDriver(e, EgressEnforce)
	settle(t, d)
	h := startJob(t, d, "0", 42, runnerclient.EgressAllow{Host: "registry.npmjs.org", Port: 0})
	h2 := startJob(t, d, "1", 43)

	// One gateway for the host, from the pinned image, with the control port
	// on loopback and the DNS port bindable without root.
	gw := e.byName("oyzu-7-gateway")
	if gw == nil {
		t.Fatal("no gateway container")
	}
	if n := countPrefix(e, "oyzu-7-gateway"); n != 1 {
		t.Fatalf("%d gateways", n)
	}
	if gw.spec.Image != d.Image || !slices.Equal(gw.spec.Cmd[:3], []string{"oyzu-executor", "gateway", "--mode"}) || gw.spec.Cmd[3] != "enforce" ||
		!slices.Equal(gw.spec.Publish, []int{9091}) || gw.spec.Sysctls["net.ipv4.ip_unprivileged_port_start"] != "53" ||
		!gw.spec.ReadOnly || gw.spec.Network != "bridge" || gw.spec.Labels[LabelRole] != "gateway" || gw.spec.Labels[LabelJob] != "" {
		t.Fatalf("gateway spec = %+v", gw.spec)
	}
	if !slices.ContainsFunc(gw.spec.Env, func(s string) bool { return strings.HasPrefix(s, "OYZU_GATEWAY_TOKEN=") && len(s) > 30 }) {
		t.Fatalf("gateway env = %v", gw.spec.Env)
	}

	// The job's network is internal, labelled, and the job lives on it.
	if len(e.networks) != 2 {
		t.Fatalf("networks = %v", e.networks)
	}
	n := e.networks[h.Ref]
	if n == nil || !n.spec.Internal || n.spec.Labels[LabelJob] != "42" || n.spec.Labels[LabelManager] != "7" || n.spec.Labels[LabelPool] != "linux" {
		t.Fatalf("job network = %+v", n)
	}
	if len(n.connected) != 1 {
		t.Fatalf("connected = %v", n.connected)
	}
	job := e.byName(h.Ref)
	gwIP := n.connected["c1"]
	if gwIP == "" {
		t.Fatalf("the gateway is not on the job's network: %v", n.connected)
	}
	s := job.spec
	if s.Network != h.Ref || !slices.Equal(s.DNS, []string{gwIP}) {
		t.Fatalf("job spec network %q dns %v, want %q %v", s.Network, s.DNS, h.Ref, gwIP)
	}
	for _, want := range []string{
		"HTTPS_PROXY=http://" + gwIP + ":3128", "HTTP_PROXY=http://" + gwIP + ":3128",
		"https_proxy=http://" + gwIP + ":3128", "OYZU_EGRESS_GATEWAY=http://" + gwIP + ":3128",
	} {
		if !slices.Contains(s.Env, want) {
			t.Errorf("job env lacks %s: %v", want, s.Env)
		}
	}
	// The gateway was told who the job is and what it may reach: the runs
	// server, always, and what runs sent.
	reg := ctl.regs[h.Ref]
	if !slices.Equal(reg.Sources, []string{n.subnet}) || !slices.Equal(reg.Allow, []egressgate.Allow{
		{Host: "runs.example", Port: 443}, {Host: "registry.npmjs.org", Port: 0},
	}) {
		t.Fatalf("registration = %+v", reg)
	}
	if reg2 := ctl.regs[h2.Ref]; slices.Equal(reg2.Sources, reg.Sources) || len(reg2.Allow) != 1 {
		t.Fatalf("second registration = %+v", reg2)
	}

	// Teardown undoes all of it, and the other job is untouched.
	if err := d.Teardown(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if e.networks[h.Ref] != nil || e.byName(h.Ref) != nil {
		t.Fatalf("job network or container left: %v", e.networks)
	}
	if _, ok := ctl.regs[h.Ref]; ok {
		t.Fatal("the job is still registered with the gateway")
	}
	if e.networks[h2.Ref] == nil || e.byName("oyzu-7-gateway") == nil || ctl.regs[h2.Ref].Job == "" {
		t.Fatal("tearing one job down touched another")
	}
	if err := d.Teardown(context.Background(), h2); err != nil {
		t.Fatal(err)
	}
	if len(e.networks) != 0 {
		t.Fatalf("networks left: %v", e.networks)
	}
}

func countPrefix(e *fakeEngine, prefix string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, c := range e.containers {
		if strings.HasPrefix(c.name, prefix) {
			n++
		}
	}
	return n
}

func TestReportModeKeepsARouteOutAndTheEngineDNS(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, ctl := sandboxDriver(e, EgressReport)
	settle(t, d)
	h := startJob(t, d, "0", 1)
	n := e.networks[h.Ref]
	if n == nil || n.spec.Internal {
		t.Fatalf("report mode network = %+v", n)
	}
	job := e.byName(h.Ref)
	if len(job.spec.DNS) != 0 || !slices.ContainsFunc(job.spec.Env, func(s string) bool { return strings.HasPrefix(s, "HTTPS_PROXY=") }) {
		t.Fatalf("job spec = %+v", job.spec)
	}
	if !slices.Contains(e.byName("oyzu-7-gateway").spec.Cmd, "report") {
		t.Fatalf("gateway cmd = %v", e.byName("oyzu-7-gateway").spec.Cmd)
	}
	if _, ok := ctl.regs[h.Ref]; !ok {
		t.Fatal("not registered")
	}
	// No self-test runs in report mode, and nothing is probed.
	if e.byName("oyzu-7-probe") != nil {
		t.Fatal("a probe ran in report mode")
	}
}

func TestOpenModeCreatesNoNetworkOrGateway(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.networks) != 0 || e.byName("oyzu-7-gateway") != nil {
		t.Fatalf("open mode made %v", e.networks)
	}
	if s := e.byName(h.Ref).spec; s.Network != "bridge" || len(s.Env) != 0 || len(s.DNS) != 0 {
		t.Fatalf("spec = %+v", s)
	}
}

func TestStartFailureAfterTheNetworkStillTearsDown(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, ctl := sandboxDriver(e, EgressEnforce)
	settle(t, d)
	ctl.mu.Lock()
	ctl.registry = errors.New("control refused")
	ctl.mu.Unlock()
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 9, Attempt: 1})
	if err == nil || h.Ref == "" {
		t.Fatalf("Start = %+v, %v", h, err)
	}
	if e.networks[h.Ref] == nil {
		t.Fatal("the network should exist for Teardown to remove")
	}
	if err := d.Teardown(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if len(e.networks) != 0 {
		t.Fatalf("networks left: %v", e.networks)
	}
}

func TestReapRemovesOrphanNetworksAndStaleGateways(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, _ := sandboxDriver(e, EgressEnforce)
	settle(t, d)
	live := startJob(t, d, "0", 1)
	other := map[string]string{LabelManager: "8", LabelJob: "3"}
	e.networks["oyzu-7-job-2-1-dead"] = &fakeNetwork{id: "nx", spec: NetworkSpec{Labels: map[string]string{LabelManager: "7", LabelJob: "2"}}, connected: map[string]string{}}
	e.networks["oyzu-7-job-3-1-live"] = &fakeNetwork{id: "ny", spec: NetworkSpec{Labels: map[string]string{LabelManager: "7", LabelJob: "3"}}, connected: map[string]string{}}
	e.networks["oyzu-8-job-3-1"] = &fakeNetwork{id: "nz", spec: NetworkSpec{Labels: other}, connected: map[string]string{}}
	if err := d.Reap(context.Background(), []manager.JobID{3}); err != nil {
		t.Fatal(err)
	}
	got := slices.Sorted(maps.Keys(e.networks))
	want := []string{live.Ref, "oyzu-7-job-3-1-live", "oyzu-8-job-3-1"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("networks after Reap = %v, want %v", got, want)
	}
	if e.byName("oyzu-7-gateway") == nil {
		t.Fatal("Reap removed the running gateway")
	}

	// A new manager process has no gateway of its own yet, so the one its
	// predecessor left, whose token nobody holds, is removed.
	d2, _ := sandboxDriver(e, EgressEnforce)
	if err := d2.Reap(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if e.byName("oyzu-7-gateway") != nil {
		t.Fatal("a stale gateway survived the restart")
	}
	if len(e.networks) != 1 || e.networks["oyzu-8-job-3-1"] == nil {
		t.Fatalf("networks after restart reap = %v", e.networks)
	}
}

func TestGatewayIsRestartedWhenItDies(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d, _ := sandboxDriver(e, EgressEnforce)
	settle(t, d)
	first := startJob(t, d, "0", 1)
	e.mu.Lock()
	for _, c := range e.containers {
		if c.spec.Labels[LabelRole] == "gateway" {
			c.stopped = true
		}
	}
	e.mu.Unlock()
	startJob(t, d, "1", 2)
	if n := countPrefix(e, "oyzu-7-gateway"); n != 1 {
		t.Fatalf("%d gateway containers after a restart", n)
	}
	if err := d.Teardown(context.Background(), first); err != nil {
		t.Fatal(err)
	}
}
