package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/readiness"
)

func (d *Driver) modeLocked() EgressMode {
	if d.activeMode != "" {
		return d.activeMode
	}
	return d.Egress
}
func (d *Driver) mode() EgressMode { d.mu.Lock(); defer d.mu.Unlock(); return d.modeLocked() }
func (d *Driver) EnableReadiness() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.managedReadiness = true
	d.egressOK = false
	d.factsDirty = true
}

// ApplyReadinessMode drains the old boundary before replacing its gateway.
// Exported configuration remains immutable while job goroutines run.
func (d *Driver) ApplyReadinessMode(ctx context.Context, mode string) (bool, error) {
	if mode == "" {
		return false, nil
	}
	if mode != "open" && mode != "report" && mode != "enforce" {
		return false, errors.New("unsupported readiness mode")
	}
	d.mu.Lock()
	if string(d.modeLocked()) == mode {
		d.mu.Unlock()
		return true, nil
	}
	d.localBinding = nil
	if len(d.inUse) > 0 || d.testing {
		d.mu.Unlock()
		return false, nil
	}
	d.activeMode = EgressMode(mode)
	d.egressOK = false
	d.tested = false
	d.factsDirty = true
	d.mu.Unlock()
	d.gwMu.Lock()
	defer d.gwMu.Unlock()
	if d.gw != nil {
		if err := d.Engine.RemoveContainer(ctx, d.gw.id); err != nil {
			return false, err
		}
		d.gw = nil
	}
	return true, nil
}
func (d *Driver) SetReadiness(b *readiness.Binding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if (d.localBinding == nil) != (b == nil) || (d.localBinding != nil && b != nil && *d.localBinding != *b) {
		d.factsDirty = true
	}
	if b == nil {
		d.localBinding = nil
		return
	}
	if d.readinessPoisoned {
		if d.readinessPassedChallenge == "" || b.Challenge != d.readinessPassedChallenge {
			d.localBinding = nil
			return
		}
		d.readinessPoisoned = false
	}
	copy := *b
	d.localBinding = &copy
}
func (d *Driver) ReadinessBoundary(ctx context.Context) (readiness.Boundary, error) {
	info, err := d.Engine.Info(ctx)
	if err != nil {
		return readiness.Boundary{}, err
	}
	if info.OSType != "linux" || info.ID == "" || info.ServerVersion == "" {
		return readiness.Boundary{}, errors.New("unqualified container host identity")
	}
	d.mu.Lock()
	pulled := d.pulled
	d.mu.Unlock()
	if !pulled {
		return readiness.Boundary{}, errors.New("executor image is not present")
	}
	mode := d.mode()
	if mode == "" {
		mode = EgressOpen
	}
	// A kernel without IPv6 runs containers without the disable_ipv6
	// sysctls; measurements made either way are not interchangeable.
	ipv6 := "disable-sysctls"
	if p, ok := d.Engine.(ipv6Prober); ok {
		absent, err := p.ipv6SysctlsAbsent(ctx, d.Image, map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel()})
		if err != nil {
			return readiness.Boundary{}, err
		}
		if absent {
			ipv6 = "kernel-without-ipv6"
		}
	}
	command, _ := json.Marshal(struct {
		Command      []string
		User         string
		CPUs         float64
		Memory       int64
		Pids         int64
		Sandbox      string
		HostSecurity []string
		IPv6         string
	}{slices.Clone(d.Command), d.user(), d.CPUs, d.MemoryBytes, d.PidsLimit, sandboxPolicyFingerprint(), slices.Clone(info.SecurityOptions), ipv6})
	runtime := sha256.Sum256(append([]byte(info.ServerVersion), command...))
	b := readiness.Boundary{Support: "supported", Driver: "container", Host: info.ID, Image: d.Image, Runtime: hex.EncodeToString(runtime[:]), Network: "internal-bridge-ipv4-gateway-dns-v1", Mode: string(mode)}
	if mode != EgressOpen {
		gw, err := d.ensureGateway(ctx)
		if err != nil {
			return b, err
		}
		b.Gateway = gw.id
	} else {
		b.Network = d.Network
		if b.Network == "" {
			b.Network = defaultNetwork
		}
	}
	if !b.Valid() {
		return b, errors.New("invalid container readiness boundary")
	}
	return b, nil
}
func (d *Driver) CheckReadiness(ctx context.Context, binding *readiness.Binding) error {
	d.mu.Lock()
	managed := d.managedReadiness
	local := d.localBinding
	mode := d.modeLocked()
	d.mu.Unlock()
	if !managed && binding == nil {
		return nil
	}
	if binding == nil {
		if mode == EgressEnforce {
			return errors.New("enforced execution requires typed readiness")
		}
		return nil
	}
	if local == nil || binding.Session != local.Session || binding.Generation != local.Generation || binding.Fingerprint != local.Fingerprint || !d.now().Before(local.ValidUntil) {
		return errors.New("readiness assignment is no longer current")
	}
	b, err := d.ReadinessBoundary(ctx)
	if err != nil {
		return err
	}
	if b.Fingerprint() != binding.Fingerprint {
		d.SetReadiness(nil)
		return readiness.ErrBoundaryChanged
	}
	return nil
}

// allocationInspector reads the actual engine allocation, independently of the
// requested template. Engines without this observation cannot qualify.
// ipv6Prober is an engine that can tell whether its own kernel lacks IPv6.
type ipv6Prober interface {
	ipv6SysctlsAbsent(ctx context.Context, image string, labels map[string]string) (bool, error)
}

type allocationInspector interface {
	InspectReadinessAllocation(context.Context, string) (allocation, error)
}
type allocation struct {
	NetworkIDs     []string
	ImageReference string
	ExpectedImage  string
	DNS            []string
	Image          string
	Networks       int
	IPv6           bool
	Privileged     bool
	HostNetwork    bool
	ExtraMount     bool
	User           string
	SandboxApplied bool
}

func (d *Driver) checkAllocation(ctx context.Context, id string, expectedDNS []string, expectedNetwork string) error {
	inspector, ok := d.Engine.(allocationInspector)
	if !ok {
		return errors.New("engine cannot observe actual network allocation")
	}
	a, err := inspector.InspectReadinessAllocation(ctx, id)
	if err != nil {
		return err
	}
	if a.ImageReference != d.Image || a.ExpectedImage == "" || a.Image != a.ExpectedImage {
		return fmt.Errorf("%w: actual allocation image differs from its pinned image", readiness.ErrBoundaryChanged)
	}
	if !slices.Equal(a.DNS, expectedDNS) {
		return fmt.Errorf("%w: actual DNS upstream differs from the qualified gateway", readiness.ErrBoundaryChanged)
	}
	if expectedNetwork == "" || len(a.NetworkIDs) != 1 || a.NetworkIDs[0] != expectedNetwork {
		return fmt.Errorf("%w: actual job network identity changed", readiness.ErrBoundaryChanged)
	}
	if a.Networks != 1 || a.IPv6 || a.Privileged || a.HostNetwork || a.ExtraMount {
		return fmt.Errorf("%w: actual allocation exceeds the qualified container boundary", readiness.ErrBoundaryChanged)
	}
	if a.User != d.user() || !a.SandboxApplied {
		return fmt.Errorf("%w: actual syscall/proc or non-root policy differs from the measured runtime", readiness.ErrBoundaryChanged)
	}
	return nil
}

// ProbeReadiness uses the ordinary sandbox constructor and pinned image. Fixed
// positive controls run outside it on the gateway's management bridge, before
// and after the negative checks. No job, manager or production credential enters
// any of these containers.
func (d *Driver) ProbeReadiness(ctx context.Context, c readiness.Challenge) (result readiness.Result) {
	result = readiness.Result{Challenge: c.ID, Session: c.Session, Generation: c.Generation, Fingerprint: c.Fingerprint, Suite: c.Suite}
	add := func(name, outcome, reason string) {
		for i := range result.Checks {
			if result.Checks[i].Name == name {
				result.Checks[i] = readiness.Subcheck{Name: name, Outcome: outcome, Reason: reason}
				return
			}
		}
		result.Checks = append(result.Checks, readiness.Subcheck{Name: name, Outcome: outcome, Reason: reason})
	}
	d.mu.Lock()
	if d.testing {
		d.mu.Unlock()
		add("control-reachability", "inconclusive", "PROBE_ALREADY_ACTIVE")
		result.Aggregate()
		return
	}
	d.testing = true
	d.mu.Unlock()
	ctx, cancel := context.WithDeadline(ctx, c.Deadline)
	defer cancel()
	name := fmt.Sprintf("oyzu-%d-probe-%s", d.Manager, c.ID)
	labels := map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelJob: "probe-" + c.ID}
	j := &job{name: name}
	clean := true
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		if j.id != "" {
			if err := d.Engine.RemoveContainer(cleanup, j.id); err != nil {
				clean = false
			}
		}
		if err := d.closeSandbox(cleanup, j); err != nil {
			clean = false
		}
		if clean {
			add("cleanup", "passed", "RESOURCES_REMOVED")
		} else {
			add("cleanup", "inconclusive", "CLEANUP_FAILED")
		}
		for _, name := range readiness.CheckNames() {
			found := false
			for _, v := range result.Checks {
				found = found || v.Name == name
			}
			if !found {
				add(name, "inconclusive", "PREREQUISITE_UNAVAILABLE")
			}
		}
		result.Aggregate()
		d.mu.Lock()
		d.testing = false
		d.tested = true
		d.egressOK = result.Outcome == "passed"
		if result.Outcome == "failed" {
			d.localBinding = nil
			d.readinessPoisoned = true
			d.readinessPassedChallenge = ""
		}
		if result.Outcome == "passed" {
			d.readinessPassedChallenge = c.ID
		}
		d.factsDirty = true
		d.lastTest = d.now()
		d.mu.Unlock()
	}()
	b, err := d.ReadinessBoundary(ctx)
	if err != nil || b.Fingerprint() != c.Fingerprint || b.Mode != "enforce" || c.Suite != readiness.Suite || c.Descriptor.Validate() != nil {
		return
	}
	raw, _ := json.Marshal(c)
	control := func(suffix string) bool {
		id, err := d.Engine.CreateContainer(ctx, name+suffix, Spec{Image: d.Image, Cmd: []string{d.Command[0], "gateway", "probe-control", "--challenge", string(raw)}, User: d.user(), Network: defaultNetwork, Labels: labels, ReadOnly: true, PidsLimit: 64})
		if err != nil {
			return false
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer stop()
			if d.Engine.RemoveContainer(cleanup, id) != nil {
				clean = false
			}
		}()
		if err = d.Engine.StartContainer(ctx, id); err != nil {
			return false
		}
		code, err := d.Engine.WaitContainer(ctx, id)
		return err == nil && code == 0
	}
	before := control("-before")
	target, _ := url.Parse(c.Descriptor.URL)
	port := 80
	if target.Scheme == "https" {
		port = 443
	}
	if target.Port() != "" {
		_, _ = fmt.Sscan(target.Port(), &port)
	}
	env, dns, err := d.openSandbox(ctx, j, labels, 0, []egressgate.Allow{{Host: target.Hostname(), Port: port}})
	if err != nil {
		if errors.Is(err, readiness.ErrBoundaryChanged) {
			add("direct-egress", "failed", "UNQUALIFIED_NETWORK_TEMPLATE")
		}
		return
	}
	proxy := ""
	for _, v := range env {
		if value, ok := strings.CutPrefix(v, egressEnvGateway+"="); ok {
			proxy = value
		}
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return
	}
	cmd := []string{d.Command[0], "gateway", "probe-readiness", "--challenge", string(raw), "--proxy", proxy, "--control", net.JoinHostPort(u.Hostname(), fmt.Sprint(gatewayControlPort))}
	j.id, err = d.Engine.CreateContainer(ctx, name, Spec{Image: d.Image, Cmd: cmd, User: d.user(), Network: j.network, Env: env, DNS: dns, Labels: labels, ReadOnly: true, PidsLimit: 256, Sysctls: map[string]string{"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}})
	if err != nil {
		return
	}
	if err = d.Engine.StartContainer(ctx, j.id); err != nil {
		return
	}
	if err = d.checkAllocation(ctx, j.id, dns, j.networkID); err != nil {
		outcome := "inconclusive"
		if errors.Is(err, readiness.ErrBoundaryChanged) {
			outcome = "failed"
		}
		add("direct-egress", outcome, "UNQUALIFIED_ALLOCATION")
		return
	}

	code, err := d.Engine.WaitContainer(ctx, j.id)
	if err != nil || code != 0 {
		return
	}
	output, err := d.Engine.ContainerLogs(ctx, j.id, 1)
	if err != nil || len(output) > 64<<10 {
		return
	}
	var child readiness.Result
	if json.Unmarshal(output, &child) != nil || child.Validate() != nil || child.Challenge != c.ID || child.Session != c.Session || child.Generation != c.Generation || child.Fingerprint != c.Fingerprint {
		return
	}
	result.Checks = child.Checks
	// Refusal must also be observed by the actual gateway registration.
	denials, err := j.gateway.control.Denials(ctx, j.name, 0)
	observed := false
	if err == nil {
		for _, dn := range denials.Denials {
			observed = observed || (dn.Host == "probe.invalid" && !dn.WouldBlock)
		}
	}
	if !observed {
		add("proxy-refusal", "inconclusive", "GATEWAY_REFUSAL_UNAVAILABLE")
	}
	after := control("-after")
	if before && after {
		add("control-reachability", "passed", "FIXED_CONTROLS_REACHABLE")
	} else {
		add("control-reachability", "inconclusive", "FIXED_CONTROLS_UNAVAILABLE")
	}
	return
}

func (d *Driver) CheckReadinessAllocation(ctx context.Context, h manager.Handle, b *readiness.Binding) error {
	if err := d.CheckReadiness(ctx, b); err != nil {
		return err
	}
	j, err := d.job(h)
	if err != nil {
		return err
	}
	d.mu.Lock()
	id := j.id
	dns := slices.Clone(j.dns)
	d.mu.Unlock()
	if err = d.checkAllocation(ctx, id, dns, j.networkID); err != nil && errors.Is(err, readiness.ErrBoundaryChanged) {
		d.mu.Lock()
		d.localBinding = nil
		d.readinessPoisoned = true
		d.readinessPassedChallenge = ""
		d.mu.Unlock()
	}
	return err
}

// ReadinessInvalidated keeps a known local failure latched until a newly
// accepted challenge replaces it, including while invalidation delivery retries.
func (d *Driver) ReadinessInvalidated() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readinessPoisoned
}
