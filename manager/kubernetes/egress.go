package kubernetes

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
	"github.com/oyzuai/fleet/runnerclient"
)

// EgressMode is how a pool controls its jobs' network.
//
// Enforce runs the gateway as a Deployment in the jobs namespace, denies
// every job pod all traffic by default and lets each one reach only the
// gateway's proxy and DNS ports, and tells the gateway which pod IP is which
// job. Report runs the same gateway and sets the same proxy for jobs, but
// adds no policy: jobs can still go out directly, and the gateway logs what
// enforcing would block. Open is the earlier behaviour.
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

// Labels on the gateway's objects. They use their own manager label, not
// LabelManager, so Reap never mistakes them for a job's.
const (
	LabelRole    = "oyzu.io/role"
	LabelGateway = "oyzu.io/gateway"
	roleGateway  = "gateway"
	rolePolicy   = "jobs-policy"
)

const (
	gatewayProxyPort   = egressgate.DefaultProxyPort
	gatewayControlPort = egressgate.DefaultControlPort
	gatewayDNSPort     = egressgate.DefaultDNSPort
	gatewayReadyWait   = 5 * time.Minute
	setupRetry         = time.Minute
	probeTimeout       = 3 * time.Minute
	// egressEnvGateway is executor.EnvEgressGateway; the executor package is
	// not imported here.
	egressEnvGateway = "OYZU_EGRESS_GATEWAY"
)

// GatewayControl is the manager's side of the gateway's control API.
type GatewayControl interface {
	Health(ctx context.Context) error
	Register(ctx context.Context, r egressgate.Registration) error
	Unregister(ctx context.Context, job string) error
	Denials(ctx context.Context, job string, after int) (egressgate.DenialsReply, error)
}

func (d *Driver) sandboxed() bool { return d.Egress == EgressEnforce || d.Egress == EgressReport }

// GatewayName is the name of the manager's gateway Deployment and Service.
func (d *Driver) GatewayName() string { return fmt.Sprintf("oyzu-gateway-%d", d.Manager) }

func (d *Driver) gatewayLabels() map[string]string {
	return map[string]string{LabelGateway: d.managerLabel()}
}

// gatewayPodLabels are what the Service and every job's policy select.
func (d *Driver) gatewayPodLabels() map[string]string {
	return map[string]string{LabelRole: roleGateway, LabelGateway: d.managerLabel()}
}

func (d *Driver) egressAPI() (EgressAPI, error) {
	api, ok := d.API.(EgressAPI)
	if !ok {
		return nil, errors.New("kubernetes: the API client cannot manage deployments and network policies")
	}
	return api, nil
}

// defaultDenyName is the policy that leaves job pods no traffic but what a
// per-job policy adds.
func (d *Driver) defaultDenyName() string { return fmt.Sprintf("oyzu-%d-jobs-default-deny", d.Manager) }

// defaultDeny denies every job pod of this manager all traffic. Job pods
// are those carrying the job label.
func (d *Driver) defaultDeny() NetworkPolicy {
	return NetworkPolicy{
		Metadata: ObjectMeta{Name: d.defaultDenyName(), Labels: map[string]string{LabelRole: rolePolicy, LabelGateway: d.managerLabel()}},
		Spec: NetworkPolicySpec{
			PodSelector: LabelSelector{
				MatchLabels:      map[string]string{LabelManager: d.managerLabel()},
				MatchExpressions: []LabelSelectorRequirement{{Key: LabelJob, Operator: "Exists"}},
			},
			PolicyTypes: []string{"Ingress", "Egress"},
		},
	}
}

// jobPolicy lets one job's pod reach the gateway's proxy and DNS ports, and
// nothing else.
func (d *Driver) jobPolicy(name string, labels map[string]string, owner OwnerReference) NetworkPolicy {
	sel := map[string]string{LabelManager: labels[LabelManager], LabelJob: labels[LabelJob]}
	return NetworkPolicy{
		Metadata: ObjectMeta{Name: name, Labels: labels, OwnerReferences: []OwnerReference{owner}},
		Spec: NetworkPolicySpec{
			PodSelector: LabelSelector{MatchLabels: sel},
			PolicyTypes: []string{"Egress"},
			Egress: []NetworkPolicyRule{{
				To: []NetworkPolicyPeer{{PodSelector: &LabelSelector{MatchLabels: d.gatewayPodLabels()}}},
				Ports: []NetworkPolicyPort{
					{Protocol: "TCP", Port: gatewayProxyPort},
					{Protocol: "UDP", Port: gatewayDNSPort},
				},
			}},
		},
	}
}

// gatewayDeployment is the gateway: one replica of the executor image, under
// the same restricted profile as a job, with a read-only filesystem.
func (d *Driver) gatewayDeployment(secret string) Deployment {
	uid := d.user()
	mode := egressgate.ModeEnforce
	if d.Egress == EgressReport {
		mode = egressgate.ModeReport
	}
	labels := d.gatewayPodLabels()
	return Deployment{
		Metadata: ObjectMeta{Name: d.GatewayName(), Labels: d.gatewayLabels()},
		Spec: DeploymentSpec{
			Replicas: ptr(int32(1)),
			Selector: LabelSelector{MatchLabels: labels},
			Template: PodTemplate{
				Metadata: ObjectMeta{Labels: labels},
				Spec: PodSpec{
					AutomountServiceAccountToken: ptr(false),
					EnableServiceLinks:           ptr(false),
					NodeSelector:                 map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": d.arch()},
					PriorityClassName:            d.PriorityClass,
					Tolerations:                  append([]Toleration(nil), d.Tolerations...),
					SecurityContext: &PodSecurityContext{
						RunAsNonRoot: ptr(true), RunAsUser: ptr(uid), RunAsGroup: ptr(uid),
						SeccompProfile: &SeccompProfile{Type: "RuntimeDefault"},
						// The DNS sinkhole listens on port 53 without being root.
						Sysctls: []Sysctl{{Name: "net.ipv4.ip_unprivileged_port_start", Value: strconv.Itoa(gatewayDNSPort)}},
					},
					Containers: []Container{{
						Name: "gateway", Image: d.Image, ImagePullPolicy: "IfNotPresent",
						Command: d.Command[:1],
						Args: []string{"gateway", "--mode", string(mode), "--pool", d.Pool,
							"--proxy", fmt.Sprintf(":%d", gatewayProxyPort), "--dns", fmt.Sprintf(":%d", gatewayDNSPort),
							"--control", fmt.Sprintf(":%d", gatewayControlPort)},
						Env: []EnvVar{{Name: egressgate.TokenEnv, ValueFrom: &EnvVarSource{SecretKeyRef: &SecretKeySelector{Name: secret, Key: "token"}}}},
						Ports: []ContainerPort{
							{Name: "proxy", ContainerPort: gatewayProxyPort, Protocol: "TCP"},
							{Name: "dns", ContainerPort: gatewayDNSPort, Protocol: "UDP"},
							{Name: "control", ContainerPort: gatewayControlPort, Protocol: "TCP"},
						},
						SecurityContext: &ContainerSecurityContext{
							Privileged: ptr(false), AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true),
							Capabilities: &Capabilities{Drop: []string{"ALL"}},
						},
					}},
				},
			},
		},
	}
}

func (d *Driver) gatewayService() Service {
	return Service{
		Metadata: ObjectMeta{Name: d.GatewayName(), Labels: d.gatewayLabels()},
		Spec: ServiceSpec{
			Type: "ClusterIP", Selector: d.gatewayPodLabels(),
			Ports: []ServicePort{
				{Name: "proxy", Protocol: "TCP", Port: gatewayProxyPort, TargetPort: gatewayProxyPort},
				{Name: "dns", Protocol: "UDP", Port: gatewayDNSPort, TargetPort: gatewayDNSPort},
				{Name: "control", Protocol: "TCP", Port: gatewayControlPort, TargetPort: gatewayControlPort},
			},
		},
	}
}

// setup makes the gateway ready, then runs the self-test. It runs in the
// background; Capacity reports no ready slot until it has.
func (d *Driver) setup(ctx context.Context) {
	err := d.prepareGateway(ctx)
	if err != nil {
		d.log().Warn("the egress gateway is not ready; no job will be claimed", "error", err)
		d.mu.Lock()
		d.settingUp, d.setupErr = false, err
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.gwReady, d.setupErr = true, nil
	d.mu.Unlock()
	if d.Egress == EgressEnforce {
		d.selfTest(ctx)
	}
	d.mu.Lock()
	d.settingUp = false
	d.mu.Unlock()
}

// prepareGateway applies the gateway's secret, Service and Deployment, the
// namespace's default-deny policy, and waits for the gateway to answer.
func (d *Driver) prepareGateway(ctx context.Context) error {
	api, err := d.egressAPI()
	if err != nil {
		return err
	}
	if d.NewControl == nil {
		return errors.New("kubernetes: no way to reach the egress gateway's control API")
	}
	secret := d.GatewayName() + "-control"
	data, err := api.GetSecret(ctx, secret)
	if errors.Is(err, ErrNotFound) {
		raw := make([]byte, 24)
		_, _ = rand.Read(raw)
		err = d.API.CreateSecret(ctx, Secret{
			Metadata: ObjectMeta{Name: secret, Labels: d.gatewayLabels()}, Type: "Opaque",
			Data: map[string][]byte{"token": []byte(hex.EncodeToString(raw))}, Immutable: true,
		})
		if err == nil {
			data, err = api.GetSecret(ctx, secret)
		}
	}
	if err != nil {
		return fmt.Errorf("the gateway's control token: %w", err)
	}
	token := string(data["token"])
	if token == "" {
		return fmt.Errorf("secret %s holds no token", secret)
	}
	ip, err := api.ApplyService(ctx, d.gatewayService())
	if err != nil {
		return fmt.Errorf("apply the gateway's service: %w", err)
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return fmt.Errorf("the gateway's service has no cluster IP (%q)", ip)
	}
	if err := api.ApplyDeployment(ctx, d.gatewayDeployment(secret)); err != nil {
		return fmt.Errorf("apply the gateway's deployment: %w", err)
	}
	if d.Egress == EgressEnforce {
		if err := api.ApplyNetworkPolicy(ctx, d.defaultDeny()); err != nil {
			return fmt.Errorf("apply the default-deny policy: %w", err)
		}
	}
	ctl := d.NewControl(token)
	deadline := time.Now().Add(orDefault(d.GatewayWait, gatewayReadyWait))
	for {
		herr := ctl.Health(ctx)
		if herr == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return fmt.Errorf("the egress gateway did not answer: %w", herr)
		}
		time.Sleep(orDefault(d.PollInterval, defaultPoll))
	}
	d.mu.Lock()
	d.gwIP, d.control = ip, ctl
	d.mu.Unlock()
	return nil
}

func (d *Driver) proxyURL() string {
	return "http://" + net.JoinHostPort(d.gwIP, strconv.Itoa(gatewayProxyPort))
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

// sandboxPod points a job pod at the gateway: the proxy variables and, when
// egress is enforced, the gateway's DNS in place of the cluster's.
func (d *Driver) sandboxPod(p *Pod) {
	proxy := d.proxyURL()
	c := &p.Spec.Containers[0]
	c.Env = append(c.Env, EnvVar{Name: egressEnvGateway, Value: proxy})
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		c.Env = append(c.Env, EnvVar{Name: k, Value: proxy})
	}
	if d.Egress == EgressEnforce {
		p.Spec.DNSPolicy = "None"
		p.Spec.DNSConfig = &DNSConfig{Nameservers: []string{d.gwIP}}
	}
}

// openSandbox gives a created pod its policy, waits for the cluster to
// give it an address and tells the gateway who it is. The pod is already
// denied everything by the default-deny policy until its own policy lets it
// reach the gateway. j records what was made, for Teardown.
func (d *Driver) openSandbox(ctx context.Context, j *job, labels map[string]string, owner OwnerReference, allow []egressgate.Allow) error {
	api, err := d.egressAPI()
	if err != nil {
		return err
	}
	if d.Egress == EgressEnforce {
		if err := api.ApplyNetworkPolicy(ctx, d.jobPolicy(j.name, labels, owner)); err != nil {
			return fmt.Errorf("apply the job's network policy: %w", err)
		}
		d.mu.Lock()
		j.policy = j.name
		d.mu.Unlock()
	}
	ip, err := d.waitPodIP(ctx, j.name)
	if err != nil {
		return err
	}
	d.mu.Lock()
	ctl := d.control
	d.mu.Unlock()
	if err := ctl.Register(ctx, egressgate.Registration{Job: j.name, Sources: []string{ip}, Allow: allow}); err != nil {
		return fmt.Errorf("register the job with the egress gateway: %w", err)
	}
	d.mu.Lock()
	j.registered = true
	d.mu.Unlock()
	return nil
}

// waitPodIP waits for the pod's address, which the cluster assigns when the
// pod's sandbox is made, before its container starts.
func (d *Driver) waitPodIP(ctx context.Context, pod string) (string, error) {
	for {
		st, err := d.API.GetPod(ctx, pod)
		switch {
		case err == nil && st.PodIP != "":
			return st.PodIP, nil
		case err != nil && !errors.Is(err, ErrNotFound):
			d.log().Warn("could not read the pod's status", "pod", pod, "error", err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("the pod %s was given no address: %w", pod, ctx.Err())
		case <-time.After(orDefault(d.PollInterval, defaultPoll)):
		}
	}
}

// closeSandbox undoes openSandbox: unregister the job and delete its
// policy.
func (d *Driver) closeSandbox(ctx context.Context, j *job) error {
	d.mu.Lock()
	policy, registered, ctl := j.policy, j.registered, d.control
	d.mu.Unlock()
	var errs []error
	if registered && ctl != nil {
		if err := ctl.Unregister(ctx, j.name); err != nil {
			errs = append(errs, fmt.Errorf("unregister the job from the egress gateway: %w", err))
		}
	}
	if policy != "" {
		if api, err := d.egressAPI(); err == nil {
			if err := api.DeleteNetworkPolicy(ctx, policy); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// egressFacts adds the pool's egress facts.
func (d *Driver) egressFacts(f manager.Facts) {
	d.mu.Lock()
	ok := d.egressOK
	d.mu.Unlock()
	switch d.Egress {
	case EgressEnforce:
		if ok {
			f[manager.FactEgress] = manager.EgressEnforced
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

// FactsChanged implements manager.FactsChanger.
func (d *Driver) FactsChanged() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ch := d.factsDirty
	d.factsDirty = false
	return ch
}

var _ manager.FactsChanger = (*Driver)(nil)

// selfTest runs a probe pod the way a job runs, and the pool reports
// egress=enforced only if the gateway refused its denied destination and
// the cluster kept it from reaching the gateway's control port, which no
// policy lets a job reach. A cluster whose network plugin ignores
// NetworkPolicy fails that, and the pool then reports egress=open and takes
// no untrusted work. It is repeated until it passes.
func (d *Driver) selfTest(ctx context.Context) {
	err := d.probe(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tested = true
	if (err == nil) != d.egressOK {
		d.factsDirty = true
	}
	d.egressOK = err == nil
	if err != nil {
		d.log().Warn("the egress self-test failed: this pool reports egress=open and takes no untrusted work", "error", err)
		return
	}
	d.log().Info("the egress self-test passed: this pool enforces egress")
}

func (d *Driver) probe(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("oyzu-%d-probe-%s", d.Manager, hex.EncodeToString(suffix))
	labels := d.labels(0)
	labels[LabelJob] = "probe-" + hex.EncodeToString(suffix)
	j := &job{name: name}
	defer func() {
		cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer stop()
		if cerr := d.closeSandbox(cctx, j); cerr != nil && err == nil {
			err = cerr
		}
		if derr := d.API.DeletePod(cctx, name, time.Second); derr != nil && err == nil {
			err = derr
		}
	}()
	p := d.pod(name, "", labels)
	c := &p.Spec.Containers[0]
	c.Args = []string{"gateway", "probe", "--proxy", d.proxyURL(), "--deny", "probe.invalid:443",
		"--direct", fmt.Sprintf("1.1.1.1:443,%s", net.JoinHostPort(d.gwIP, strconv.Itoa(gatewayControlPort)))}
	c.Env = c.Env[:1] // HOME only: no startup token
	d.sandboxPod(&p)
	uid, err := d.API.CreatePod(ctx, p)
	if err != nil {
		return fmt.Errorf("create the probe pod: %w", err)
	}
	if err := d.openSandbox(ctx, j, labels, OwnerReference{APIVersion: "v1", Kind: "Pod", Name: name, UID: uid}, nil); err != nil {
		return err
	}
	for {
		st, err := d.API.GetPod(ctx, name)
		if err == nil {
			if exit, done := ended(name, st); done {
				if !exit.Clean() {
					out, _ := d.API.PodLog(ctx, name, 10)
					return fmt.Errorf("the probe job got out or could not reach the gateway (%s): %s", exit, strings.TrimSpace(string(out)))
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the probe pod did not finish: %w", ctx.Err())
		case <-time.After(orDefault(d.PollInterval, defaultPoll)):
		}
	}
	d.mu.Lock()
	ctl := d.control
	d.mu.Unlock()
	reply, err := ctl.Denials(ctx, name, 0)
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

// forget tells the gateway a reaped pod's job is gone.
func (d *Driver) forget(ctx context.Context, pod string) {
	d.mu.Lock()
	ctl := d.control
	d.mu.Unlock()
	if ctl != nil && d.sandboxed() {
		if err := ctl.Unregister(ctx, pod); err != nil {
			d.log().Warn("could not unregister a reaped pod from the egress gateway", "pod", pod, "error", err)
		}
	}
}

// reapPolicies deletes the job policies of pods that are gone. A policy has
// the pod as its owner, so the cluster normally does it; this catches the
// rest.
func (d *Driver) reapPolicies(ctx context.Context, keep map[string]bool, isLive func(string) bool) error {
	api, err := d.egressAPI()
	if err != nil {
		return err
	}
	policies, err := api.ListNetworkPolicies(ctx, d.selector())
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range policies {
		if keep[p.Name] || isLive(p.Labels[LabelJob]) {
			continue
		}
		if err := api.DeleteNetworkPolicy(ctx, p.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		d.log().Info("reaped a network policy", "policy", p.Name, "job", p.Labels[LabelJob])
	}
	return errors.Join(errs...)
}
