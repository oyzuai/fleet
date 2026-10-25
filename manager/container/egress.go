package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/runnerclient"
)

// EgressMode is how a pool controls its jobs' network.
//
// Enforce gives each job its own internal network, with no route out, and
// connects the manager's gateway to it: the gateway is the only way out, and
// it holds each job to the allow list runs sent with its claim. Report runs
// the same gateway but leaves the job a route out, and logs what enforcing
// would block. Open, the default for a Driver, is the earlier behaviour: the
// jobs share the --network and nothing watches them.
type EgressMode string

const (
	EgressOpen    EgressMode = "open"
	EgressReport  EgressMode = "report"
	EgressEnforce EgressMode = "enforce"
)

// Valid reports whether m names a mode. The empty mode is open.
func (m EgressMode) Valid() bool {
	return m == "" || m == EgressOpen || m == EgressReport || m == EgressEnforce
}

// LabelRole marks the manager's gateway container, which no job owns.
const (
	LabelRole   = "oyzu.io/role"
	roleGateway = "gateway"
)

const (
	gatewayProxyPort   = egressgate.DefaultProxyPort
	gatewayControlPort = egressgate.DefaultControlPort
	gatewayDNSPort     = egressgate.DefaultDNSPort
	gatewayReadyWait   = 30 * time.Second
	// probeTimeout bounds the startup self-test's probe job.
	probeTimeout = 2 * time.Minute
)

// GatewayControl is the manager's side of the gateway's control API.
type GatewayControl interface {
	Health(ctx context.Context) error
	Register(ctx context.Context, r egressgate.Registration) error
	Unregister(ctx context.Context, job string) error
	Denials(ctx context.Context, job string, after int) (egressgate.DenialsReply, error)
}

// sandboxed reports whether jobs go through the gateway.
func (d *Driver) sandboxed() bool { return d.mode() == EgressEnforce || d.mode() == EgressReport }

// gateway is the manager's running gateway container.
type gateway struct {
	id      string
	name    string
	token   string
	control GatewayControl
}

func (d *Driver) controlClient(base, token string) GatewayControl {
	if d.Control != nil {
		return d.Control(base, token)
	}
	return egressgate.NewClient(base, token)
}

func (d *Driver) gatewayName() string { return fmt.Sprintf("oyzu-%d-gateway", d.Manager) }

// gatewayCmd starts the gateway from the executor image.
func (d *Driver) gatewayCmd() []string {
	mode := egressgate.ModeEnforce
	if d.mode() == EgressReport {
		mode = egressgate.ModeReport
	}
	return []string{d.Command[0], "gateway", "--mode", string(mode), "--pool", d.Pool,
		"--proxy", fmt.Sprintf(":%d", gatewayProxyPort), "--dns", fmt.Sprintf(":%d", gatewayDNSPort),
		"--control", fmt.Sprintf(":%d", gatewayControlPort), "--control-interface", "eth0"}
}

// ensureGateway returns the manager's gateway, starting it if it is not
// running. One gateway serves every job on the host.
func (d *Driver) ensureGateway(ctx context.Context) (*gateway, error) {
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	return d.ensureGatewayLocked(ctx)
}
func (d *Driver) ensureGatewayLocked(ctx context.Context) (*gateway, error) {
	if err := d.checkAnchorLocked(ctx); err != nil {
		return nil, err
	}
	if gw := d.gw; gw != nil {
		if st, err := d.Engine.InspectContainer(ctx, gw.id); err == nil && st.Running {
			return gw, nil
		}
		if d.anchor != nil {
			return nil, d.pairFailure(errors.New("gateway is no longer running"))
		}
		d.log().Warn("the egress gateway is not running; starting another", "gateway", gw.name)
		_ = d.Engine.RemoveContainer(ctx, gw.id)
		d.gw = nil
	}
	// A gateway a predecessor left behind has a token nobody knows.
	if old, err := d.Engine.ListContainers(ctx, map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelRole: roleGateway}); err == nil {
		for _, c := range old {
			if c.Name != d.gatewayName() {
				return nil, errors.New("unrecognized stale gateway")
			}
			if err := d.removeConfirmed(ctx, c.ID); err != nil {
				return nil, err
			}
		}
	} else {
		return nil, err
	}
	if d.anchor == nil {
		old, err := d.Engine.ListContainers(ctx, map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelRole: roleAnchor})
		if err != nil {
			return nil, err
		}
		for _, c := range old {
			if c.Name != d.anchorName() {
				return nil, errors.New("unrecognized stale namespace anchor")
			}
			if err := d.removeConfirmed(ctx, c.ID); err != nil {
				return nil, err
			}
		}
	}
	// The bridge namespace must have two live members before any probe/job
	// detaches the gateway. Podman4.9 otherwise retires its shared rootless
	// namespace when the gateway is the last bridge container.
	if err := d.createAnchorLocked(ctx); err != nil {
		clean, cancel := pairCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, d.retirePairLocked(clean))
	}
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	spec := Spec{
		Image: d.Image, Cmd: d.gatewayCmd(), User: d.user(), Network: defaultNetwork, PidsLimit: 1024, ReadOnly: true,
		Labels:  map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelRole: roleGateway},
		Env:     []string{egressgate.TokenEnv + "=" + token},
		Publish: []int{gatewayControlPort},
		// The DNS sinkhole listens on port 53 without being root.
		Sysctls: map[string]string{"net.ipv4.ip_unprivileged_port_start": strconv.Itoa(gatewayDNSPort)},
	}
	name := d.gatewayName()
	id, err := d.Engine.CreateContainer(ctx, name, spec)
	if err != nil {
		clean, cancel := pairCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("create the egress gateway: %w", err), d.retirePairLocked(clean))
	}
	d.gw = &gateway{id: id, name: name}
	fail := func(err error) (*gateway, error) {
		clean, cancel := pairCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, d.retirePairLocked(clean))
	}
	if err := d.Engine.StartContainer(ctx, id); err != nil {
		return fail(fmt.Errorf("start the egress gateway: %w", err))
	}
	port, err := d.Engine.PublishedPort(ctx, id, gatewayControlPort)
	if err != nil {
		return fail(fmt.Errorf("find the egress gateway's control port: %w", err))
	}
	gw := &gateway{id: id, name: name, token: token,
		control: d.controlClient("http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), token)}
	deadline := time.Now().Add(gatewayReadyWait)
	for {
		err := gw.control.Health(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return fail(fmt.Errorf("the egress gateway did not answer: %w", err))
		}
		time.Sleep(200 * time.Millisecond)
	}
	d.gw = gw
	d.log().Info("started the egress gateway", "gateway", name, "mode", d.mode())
	return gw, nil
}

// allowFor is the job's allow list: what runs sent, and always the runs
// server, which the runner cannot start without.
func (d *Driver) allowFor(c runnerclient.Claim) []egressgate.Allow {
	var out []egressgate.Allow
	if u, err := url.Parse(d.Server); err == nil && u.Hostname() != "" {
		port := 443
		if u.Scheme == "http" {
			port = 80
		}
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		}
		out = append(out, egressgate.Allow{Host: u.Hostname(), Port: port})
	}
	for _, a := range c.Egress.Allow {
		out = append(out, egressgate.Allow{Host: a.Host, Port: a.Port})
	}
	return out
}

// proxyEnv is what points a job at the gateway on its network.
func proxyEnv(gwIP string) []string {
	u := "http://" + net.JoinHostPort(gwIP, strconv.Itoa(gatewayProxyPort))
	env := []string{egressEnvGateway + "=" + u}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		env = append(env, k+"="+u)
	}
	return env
}

// egressEnvGateway is executor.EnvEgressGateway; the executor package is
// not imported here.
const egressEnvGateway = "OYZU_EGRESS_GATEWAY"

// openSandbox gives j its own network, joins the gateway to it and tells the
// gateway who the job is. It records what it made in j as it goes, so
// Teardown can undo a half-made sandbox. It returns the job container's
// environment and DNS servers.
func (d *Driver) openSandbox(ctx context.Context, j *job, labels map[string]string, jobID int64, allow []egressgate.Allow) (env, dns []string, err error) {
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	gw, err := d.ensureGatewayLocked(ctx)
	if err != nil {
		return nil, nil, err
	}
	n, err := d.Engine.CreateNetwork(ctx, j.name, NetworkSpec{Labels: labels, Internal: d.mode() == EgressEnforce})
	if err != nil {
		return nil, nil, fmt.Errorf("create the job network: %w", err)
	}
	d.mu.Lock()
	j.network = j.name
	j.networkID = n.ID
	managed := d.managedReadiness
	mode := d.modeLocked()
	d.mu.Unlock()
	if managed && mode == EgressEnforce && (n.ID == "" || !n.Internal || n.IPv6 || n.Driver != "bridge") {
		return nil, nil, fmt.Errorf("%w: engine did not apply the qualified internal IPv4 bridge", readiness.ErrBoundaryChanged)
	}
	if n.Subnet == "" {
		return nil, nil, fmt.Errorf("the engine gave network %s no subnet", n.Name)
	}
	ip, err := d.Engine.ConnectNetwork(ctx, j.network, gw.id)
	if err != nil {
		return nil, nil, fmt.Errorf("join the egress gateway to the job network: %w", err)
	}
	d.mu.Lock()
	j.gateway = gw
	d.mu.Unlock()
	if err := gw.control.Register(ctx, egressgate.Registration{Job: j.name, Sources: []string{n.Subnet}, Allow: allow}); err != nil {
		return nil, nil, fmt.Errorf("register the job with the egress gateway: %w", err)
	}
	d.mu.Lock()
	j.registered = true
	d.mu.Unlock()
	if d.mode() == EgressEnforce {
		dns = []string{ip}
	}
	return proxyEnv(ip), dns, nil
}

// closeSandbox undoes openSandbox: unregister the job, detach the gateway
// and remove the network.
func (d *Driver) closeSandbox(ctx context.Context, j *job) error {
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	d.mu.Lock()
	network, gw, registered := j.network, j.gateway, j.registered
	d.mu.Unlock()
	if network == "" {
		return nil
	}
	var errs []error
	if registered && gw != nil {
		if err := gw.control.Unregister(ctx, j.name); err != nil {
			errs = append(errs, fmt.Errorf("unregister the job from the egress gateway: %w", err))
		}
	}
	if err := d.removeNetworkLocked(ctx, network, true); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// removeNetwork detaches the gateway, which the engine would otherwise
// refuse to leave behind, and removes the network.
func (d *Driver) removeNetwork(ctx context.Context, name string) error {
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	return d.removeNetworkLocked(ctx, name, true)
}
func (d *Driver) removeNetworkLocked(ctx context.Context, name string, requireHealthy bool) error {
	if requireHealthy {
		if err := d.checkAnchorLocked(ctx); err != nil {
			return err
		}
	}
	gw := d.gw
	if gw != nil {
		if err := d.Engine.DisconnectNetwork(ctx, name, gw.id); err != nil {
			return fmt.Errorf("detach the egress gateway from %s: %w", name, err)
		}
	}
	if err := d.Engine.RemoveNetwork(ctx, name); err != nil {
		return fmt.Errorf("remove network %s: %w", name, err)
	}
	return nil
}

// egressFacts adds the pool's egress facts.
func (d *Driver) egressFacts(f manager.Facts) {
	d.mu.Lock()
	ok := d.egressOK
	if d.managedReadiness {
		// Facts describe accepted current authority, not the latest probe's
		// outcome. An inconclusive refresh neither revokes nor extends an
		// earlier success; failed probes clear/poison that binding immediately.
		ok = d.localBinding != nil && !d.readinessPoisoned && d.now().Before(d.localBinding.ValidUntil)
	}
	d.mu.Unlock()
	switch d.mode() {
	case EgressEnforce:
		if ok {
			f[manager.FactEgress] = manager.EgressEnforced
			// Containers are never the process isolation; only an enforced,
			// self-tested pool takes untrusted work.
			f[manager.FactUntrusted] = manager.UntrustedAccepted
			return
		}
		f[manager.FactEgress] = manager.EgressOpen
	case EgressReport:
		f[manager.FactEgress] = manager.EgressReport
	default:
		f[manager.FactEgress] = manager.EgressOpen
	}
}

// FactsChanged implements manager.FactsChanger: the self-test finished since
// the facts were last read.
func (d *Driver) FactsChanged() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ch := d.factsDirty
	d.factsDirty = false
	return ch
}

var _ manager.FactsChanger = (*Driver)(nil)

// selfTest checks, before the pool says it enforces anything, that a job on
// a sandbox network cannot get out: it runs a probe container through the
// same path a job takes, and the probe must find the gateway refusing a
// destination that is not allowed, a lookup that gets no answer and no
// direct route to the outside. If it does not, or the gateway cannot be
// started, the pool reports egress=open and takes no untrusted work, and
// the reason is logged. The test is repeated until it passes.
func (d *Driver) selfTest(ctx context.Context) {
	err := d.probe(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.testing, d.tested = false, true
	if (err == nil) != d.egressOK {
		d.factsDirty = true
	}
	d.egressOK = err == nil && !d.anchorInvalid && !d.closing
	if err != nil {
		d.log().Warn("the egress self-test failed: this pool reports egress=open and takes no untrusted work", "error", err)
		return
	}
	d.log().Info("the egress self-test passed: this pool enforces egress")
}

func (d *Driver) probe(ctx context.Context) (err error) {
	ctx, release, err := d.beginProbe(ctx)
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("oyzu-%d-probe-%s", d.Manager, hex.EncodeToString(suffix))
	labels := map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelJob: "probe-" + hex.EncodeToString(suffix)}
	j := &job{name: name}
	cleanup := context.WithoutCancel(ctx)
	defer func() {
		cctx, stop := context.WithTimeout(cleanup, 30*time.Second)
		defer stop()
		if j.id != "" {
			_ = d.Engine.StopContainer(cctx, j.id, time.Second)
			_ = d.Engine.RemoveContainer(cctx, j.id)
		}
		if cerr := d.closeSandbox(cctx, j); cerr != nil && err == nil {
			err = cerr
		}
	}()
	env, dns, err := d.openSandbox(ctx, j, labels, 0, nil)
	if err != nil {
		return err
	}
	proxy := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, egressEnvGateway+"="); ok {
			proxy = v
		}
	}
	// 192.0.2.1 is TEST-NET-1, which routes nowhere; 1.1.1.1 is a real
	// address a job with a route out would reach.
	cmd := []string{d.Command[0], "gateway", "probe", "--proxy", proxy, "--deny", "probe.invalid:443", "--direct", "192.0.2.1:443,1.1.1.1:443"}
	id, err := d.Engine.CreateContainer(ctx, name, Spec{
		Image: d.Image, Cmd: cmd, User: d.user(), Labels: labels, Network: j.network, Env: env, DNS: dns,
		PidsLimit: 256, ReadOnly: true,
	})
	if err != nil {
		return fmt.Errorf("create the probe: %w", err)
	}
	j.id = id
	if err := d.Engine.StartContainer(ctx, id); err != nil {
		return fmt.Errorf("start the probe: %w", err)
	}
	code, err := d.Engine.WaitContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("wait for the probe: %w", err)
	}
	if code != 0 {
		out, _ := d.Engine.ContainerLogs(ctx, id, 10)
		return fmt.Errorf("the probe job got out or could not reach the gateway (exit %d): %s", code, strings.TrimSpace(string(out)))
	}
	// The gateway must have seen the refusal itself.
	reply, err := j.gateway.control.Denials(ctx, name, 0)
	if err != nil {
		return fmt.Errorf("read the probe's denials from the gateway: %w", err)
	}
	for _, dn := range reply.Denials {
		if dn.Host == "probe.invalid" && !dn.WouldBlock {
			return nil
		}
	}
	return errors.New("the gateway recorded no refusal for the probe's denied destination")
}
