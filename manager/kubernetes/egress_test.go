package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// fakeEgressAPI adds the gateway's and policies' objects to the fake API. A
// pod gets an address when it is created, and a probe pod ends at once, as
// probeExit says.
type fakeEgressAPI struct {
	*fakeAPI
	policies    map[string]NetworkPolicy
	deployments map[string]Deployment
	services    map[string]Service
	probeExit   int
	podIPs      int
}

func newFakeEgressAPI() *fakeEgressAPI {
	return &fakeEgressAPI{fakeAPI: newFakeAPI(), policies: map[string]NetworkPolicy{}, deployments: map[string]Deployment{}, services: map[string]Service{}}
}

func (f *fakeEgressAPI) CreatePod(ctx context.Context, p Pod) (string, error) {
	uid, err := f.fakeAPI.CreatePod(ctx, p)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.podIPs++
	st := PodStatus{Phase: "Pending", PodIP: fmt.Sprintf("10.1.0.%d", f.podIPs)}
	if len(p.Spec.Containers) > 0 && slices.Contains(p.Spec.Containers[0].Args, "probe") {
		st.Phase = "Succeeded"
		code := f.probeExit
		if code != 0 {
			st.Phase = "Failed"
		}
		st.ContainerStatuses = []ContainerStatus{{Name: container, State: ContainerState{Terminated: &ContainerStateTerminated{ExitCode: code}}}}
	}
	f.pods[p.Metadata.Name].status = st
	return uid, err
}

func (f *fakeEgressAPI) GetSecret(_ context.Context, name string) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[name]
	if !ok {
		return nil, ErrNotFound
	}
	return s.Data, nil
}

func (f *fakeEgressAPI) ApplyDeployment(_ context.Context, d Deployment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deployments[d.Metadata.Name] = d
	return nil
}

func (f *fakeEgressAPI) DeploymentAvailable(context.Context, string) (bool, error) { return true, nil }

func (f *fakeEgressAPI) ApplyService(_ context.Context, s Service) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.services[s.Metadata.Name] = s
	return "10.96.0.10", nil
}

func (f *fakeEgressAPI) ApplyNetworkPolicy(_ context.Context, p NetworkPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[p.Metadata.Name] = p
	return nil
}

func (f *fakeEgressAPI) DeleteNetworkPolicy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, name)
	return nil
}

func (f *fakeEgressAPI) ListNetworkPolicies(_ context.Context, selector string) ([]ObjectMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ObjectMeta
	for _, p := range f.policies {
		if selects(selector, p.Metadata.Labels) {
			out = append(out, p.Metadata)
		}
	}
	return out, nil
}

type fakeControl struct {
	mu       sync.Mutex
	regs     map[string]egressgate.Registration
	token    string
	silent   bool
	registry error
}

func (f *fakeControl) Health(context.Context) error { return nil }

func (f *fakeControl) Register(_ context.Context, r egressgate.Registration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registry != nil {
		return f.registry
	}
	f.regs[r.Job] = r
	return nil
}

func (f *fakeControl) Unregister(_ context.Context, job string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.regs, job)
	return nil
}

func (f *fakeControl) Denials(_ context.Context, job string, _ int) (egressgate.DenialsReply, error) {
	if f.silent || !strings.Contains(job, "-probe-") {
		return egressgate.DenialsReply{}, nil
	}
	return egressgate.DenialsReply{Denials: []egressgate.Denial{{Host: "probe.invalid", Port: 443, Method: "CONNECT"}}}, nil
}

func sandboxDriver(mode EgressMode) (*Driver, *fakeEgressAPI, *fakeControl) {
	api := newFakeEgressAPI()
	ctl := &fakeControl{regs: map[string]egressgate.Registration{}}
	d := newDriver(api.fakeAPI)
	d.API = api
	d.Egress = mode
	d.NewControl = func(token string) GatewayControl { ctl.token = token; return ctl }
	return d, api, ctl
}

// ready waits for the gateway to be set up and the self-test to finish.
func ready(t *testing.T, d *Driver) manager.Capacity {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, _ := d.Capacity(context.Background())
		if len(c.Ready) > 0 {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no slot became ready")
	return manager.Capacity{}
}

func TestCheckEgressNeedsAnEgressAPIAndControl(t *testing.T) {
	d, _, _ := sandboxDriver(EgressEnforce)
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	d.NewControl = nil
	if err := d.Check(); err == nil {
		t.Fatal("Check accepted egress without a way to reach the gateway")
	}
	d2 := newDriver(newFakeAPI())
	d2.Egress = EgressReport
	d2.NewControl = func(string) GatewayControl { return nil }
	if err := d2.Check(); err == nil {
		t.Fatal("Check accepted an API that cannot manage policies")
	}
	d3 := newDriver(newFakeAPI())
	d3.Egress = "strict"
	if err := d3.Check(); err == nil {
		t.Fatal("Check accepted an unknown mode")
	}
}

func TestGatewayObjects(t *testing.T) {
	d, api, ctl := sandboxDriver(EgressEnforce)
	ready(t, d)
	dep := api.deployments["oyzu-gateway-7"]
	pod := dep.Spec.Template.Spec
	c := pod.Containers[0]
	if c.Image != d.Image || !slices.Equal(c.Command, []string{"oyzu-executor"}) || c.Args[0] != "gateway" || !slices.Contains(c.Args, "enforce") ||
		*pod.SecurityContext.RunAsUser != 1000 || !*pod.SecurityContext.RunAsNonRoot || !*c.SecurityContext.ReadOnlyRootFilesystem ||
		!slices.Equal(c.SecurityContext.Capabilities.Drop, []string{"ALL"}) || *c.SecurityContext.AllowPrivilegeEscalation ||
		*pod.AutomountServiceAccountToken || pod.SecurityContext.Sysctls[0].Value != "53" {
		t.Fatalf("gateway pod = %+v", dep)
	}
	if ref := c.Env[0].ValueFrom.SecretKeyRef; ref.Name != "oyzu-gateway-7-control" || c.Env[0].Name != "OYZU_GATEWAY_TOKEN" {
		t.Fatalf("gateway token = %+v", c.Env)
	}
	// The token is in a secret the manager created, and the control client got it.
	if tok := string(api.secrets["oyzu-gateway-7-control"].Data["token"]); len(tok) < 32 || tok != ctl.token {
		t.Fatalf("token %q, control got %q", tok, ctl.token)
	}
	svc := api.services["oyzu-gateway-7"]
	if !maps.Equal(svc.Spec.Selector, dep.Spec.Selector.MatchLabels) || len(svc.Spec.Ports) != 3 {
		t.Fatalf("service = %+v", svc)
	}
	// Gateway objects carry no manager label, so Reap leaves them alone.
	if _, ok := dep.Metadata.Labels[LabelManager]; ok {
		t.Fatalf("labels = %v", dep.Metadata.Labels)
	}
	dd := api.policies["oyzu-7-jobs-default-deny"]
	raw, _ := json.Marshal(dd.Spec)
	if !slices.Equal(dd.Spec.PolicyTypes, []string{"Ingress", "Egress"}) || len(dd.Spec.Egress) != 0 || len(dd.Spec.Ingress) != 0 ||
		dd.Spec.PodSelector.MatchExpressions[0].Key != LabelJob || dd.Spec.PodSelector.MatchExpressions[0].Operator != "Exists" ||
		dd.Spec.PodSelector.MatchLabels[LabelManager] != "7" {
		t.Fatalf("default deny = %s", raw)
	}
	// Preparing twice reuses the token.
	before := api.secrets["oyzu-gateway-7-control"].Data["token"]
	if err := d.prepareGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if string(api.secrets["oyzu-gateway-7-control"].Data["token"]) != string(before) {
		t.Fatal("a second setup replaced the control token")
	}
}

func TestEnforcedJobPodReachesOnlyTheGateway(t *testing.T) {
	d, api, ctl := sandboxDriver(EgressEnforce)
	ready(t, d)
	ctx := context.Background()
	h, err := d.Start(ctx, "0", runnerclient.Claim{JobID: 42, Attempt: 1, StartupToken: "st_secret",
		Egress: runnerclient.ClaimEgress{Allow: []runnerclient.EgressAllow{{Host: "registry.npmjs.org"}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := api.pods[h.Ref].pod
	envs := map[string]string{}
	for _, e := range p.Spec.Containers[0].Env {
		envs[e.Name] = e.Value
	}
	const gw = "http://10.96.0.10:3128"
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "OYZU_EGRESS_GATEWAY"} {
		if envs[k] != gw {
			t.Errorf("%s = %q, want %s", k, envs[k], gw)
		}
	}
	// DNS goes to the sinkhole, by address, since the policy leaves no route to the cluster's.
	if p.Spec.DNSPolicy != "None" || !slices.Equal(p.Spec.DNSConfig.Nameservers, []string{"10.96.0.10"}) {
		t.Fatalf("dns = %q %+v", p.Spec.DNSPolicy, p.Spec.DNSConfig)
	}
	// The pod's labels are unchanged: they are what the policies select.
	if !maps.Equal(p.Metadata.Labels, map[string]string{LabelPool: "k8s-prod", LabelManager: "7", LabelJob: "42"}) {
		t.Fatalf("labels = %v", p.Metadata.Labels)
	}
	pol := api.policies[h.Ref]
	raw, _ := json.Marshal(pol.Spec)
	if !slices.Equal(pol.Spec.PolicyTypes, []string{"Egress"}) || len(pol.Spec.Egress) != 1 || len(pol.Spec.Ingress) != 0 ||
		!maps.Equal(pol.Spec.PodSelector.MatchLabels, map[string]string{LabelManager: "7", LabelJob: "42"}) {
		t.Fatalf("job policy = %s", raw)
	}
	rule := pol.Spec.Egress[0]
	if !maps.Equal(rule.To[0].PodSelector.MatchLabels, d.gatewayPodLabels()) ||
		!slices.Equal(rule.Ports, []NetworkPolicyPort{{"TCP", 3128}, {"UDP", 53}}) {
		t.Fatalf("job policy rule = %s", raw)
	}
	if o := pol.Metadata.OwnerReferences; len(o) != 1 || o[0].Kind != "Pod" || o[0].Name != h.Ref || o[0].UID != "uid-"+h.Ref {
		t.Fatalf("policy owner = %+v", o)
	}
	// The pod's address is what the gateway was told, with the allow list.
	reg := ctl.regs[h.Ref]
	if !slices.Equal(reg.Sources, []string{api.pods[h.Ref].status.PodIP}) || !slices.Equal(reg.Allow, []egressgate.Allow{
		{Host: "runs.example", Port: 443}, {Host: "registry.npmjs.org", Port: 0},
	}) {
		t.Fatalf("registration = %+v", reg)
	}
	if err := d.Teardown(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.policies[h.Ref]; ok {
		t.Fatal("the job's policy is left after Teardown")
	}
	if _, ok := ctl.regs[h.Ref]; ok {
		t.Fatal("the job is still registered after Teardown")
	}
	if _, ok := api.policies["oyzu-7-jobs-default-deny"]; !ok {
		t.Fatal("Teardown removed the default-deny policy")
	}
}

func TestReportModeAddsNoPolicyAndKeepsClusterDNS(t *testing.T) {
	d, api, ctl := sandboxDriver(EgressReport)
	ready(t, d)
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	p := api.pods[h.Ref].pod
	if len(api.policies) != 0 || p.Spec.DNSPolicy != "" || p.Spec.DNSConfig != nil {
		t.Fatalf("report mode changed the pod's network: %v %+v", api.policies, p.Spec)
	}
	if !slices.ContainsFunc(p.Spec.Containers[0].Env, func(e EnvVar) bool { return e.Name == "HTTPS_PROXY" }) {
		t.Fatal("no proxy variable")
	}
	if _, ok := ctl.regs[h.Ref]; !ok {
		t.Fatal("not registered")
	}
	if !slices.Contains(api.deployments["oyzu-gateway-7"].Spec.Template.Spec.Containers[0].Args, "report") {
		t.Fatal("the gateway does not run in report mode")
	}
	f, _ := d.Facts(context.Background())
	if f[manager.FactEgress] != "report" || f[manager.FactUntrusted] != "" {
		t.Fatalf("facts = %v", f)
	}
}

func TestFactsAndTheSelfTest(t *testing.T) {
	ctx := context.Background()
	d, _, _ := sandboxDriver(EgressEnforce)
	if f, _ := d.Facts(ctx); f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" || f[manager.FactIsolation] != "pod" {
		t.Fatalf("facts before the self-test = %v", f)
	}
	ready(t, d)
	f, _ := d.Facts(ctx)
	if f[manager.FactEgress] != "enforced" || f[manager.FactUntrusted] != "accepted" {
		t.Fatalf("facts after a passed self-test = %v", f)
	}
	if !d.FactsChanged() || d.FactsChanged() {
		t.Fatal("FactsChanged must report the self-test once")
	}
	// The probe pod is gone.
	if len(d.API.(*fakeEgressAPI).pods) != 0 {
		t.Fatalf("pods left: %v", d.API.(*fakeEgressAPI).pods)
	}

	// A cluster whose policies are not enforced lets the probe out: it exits
	// non-zero, and the pool says it is open.
	bad, api, ctl := sandboxDriver(EgressEnforce)
	api.probeExit = 1
	if c := ready(t, bad); len(c.Ready) == 0 {
		t.Fatal("a pool that failed its self-test must still run trusted work")
	}
	f, _ = bad.Facts(ctx)
	if f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
		t.Fatalf("facts after a failed self-test = %v", f)
	}
	if len(ctl.regs) != 0 || len(api.policies) != 1 {
		t.Fatalf("the probe left registrations %v or policies %v", ctl.regs, api.policies)
	}

	// A probe that exits cleanly but whose denial the gateway never saw does not pass.
	quiet, _, qctl := sandboxDriver(EgressEnforce)
	qctl.silent = true
	ready(t, quiet)
	if f, _ := quiet.Facts(ctx); f[manager.FactEgress] != "open" {
		t.Fatalf("facts = %v", f)
	}
}

func TestStartRefusesUntilTheGatewayIsReady(t *testing.T) {
	d, _, ctl := sandboxDriver(EgressEnforce)
	if _, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1}); err == nil {
		t.Fatal("Start ran a job before the gateway was set up")
	}
	if c, _ := d.Capacity(context.Background()); len(c.Ready) != 0 {
		t.Fatalf("slots ready before setup: %+v", c)
	}
	ready(t, d)
	ctl.registry = errors.New("control refused")
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 2, Attempt: 1})
	if err == nil || h.Ref == "" {
		t.Fatalf("Start = %+v, %v", h, err)
	}
	// The failed job still has a Ref, so Teardown removes its pod and policy.
	if err := d.Teardown(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if a := d.API.(*fakeEgressAPI); len(a.pods) != 0 || len(a.policies) != 1 {
		t.Fatalf("pods %v policies %v", a.pods, a.policies)
	}
}

func TestReapDeletesOrphanPoliciesButNotTheGatewayOrDefaultDeny(t *testing.T) {
	d, api, ctl := sandboxDriver(EgressEnforce)
	ready(t, d)
	ctx := context.Background()
	h, _ := d.Start(ctx, "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	policy := func(name, job, mgr string) {
		_ = api.ApplyNetworkPolicy(ctx, NetworkPolicy{Metadata: ObjectMeta{Name: name, Labels: map[string]string{LabelManager: mgr, LabelJob: job}}})
	}
	policy("oyzu-7-job-2-1-x", "2", "7")
	policy("oyzu-7-job-3-1-x", "3", "7")
	policy("oyzu-8-job-4-1-x", "4", "8")
	_, _ = api.CreatePod(ctx, Pod{Metadata: ObjectMeta{Name: "oyzu-7-job-2-1-x", Labels: map[string]string{LabelManager: "7", LabelJob: "2"}}})
	ctl.regs["oyzu-7-job-2-1-x"] = egressgate.Registration{Job: "oyzu-7-job-2-1-x"}
	if err := d.Reap(ctx, []manager.JobID{3}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for n := range api.policies {
		got = append(got, n)
	}
	slices.Sort(got)
	want := []string{h.Ref, "oyzu-7-job-3-1-x", "oyzu-7-jobs-default-deny", "oyzu-8-job-4-1-x"}
	if !slices.Equal(got, want) {
		t.Fatalf("policies after Reap = %v, want %v", got, want)
	}
	if _, ok := ctl.regs["oyzu-7-job-2-1-x"]; ok {
		t.Fatal("a reaped pod is still registered with the gateway")
	}
	if _, ok := api.deployments["oyzu-gateway-7"]; !ok {
		t.Fatal("Reap removed the gateway")
	}
}

func TestOpenModeCreatesNothingExtra(t *testing.T) {
	api := newFakeEgressAPI()
	d := newDriver(api.fakeAPI)
	d.API = api
	if _, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1}); err != nil {
		t.Fatal(err)
	}
	if len(api.policies)+len(api.deployments)+len(api.services) != 0 {
		t.Fatal("open mode created egress objects")
	}
	f, _ := d.Facts(context.Background())
	if f[manager.FactEgress] != "open" || f[manager.FactUntrusted] != "" {
		t.Fatalf("facts = %v", f)
	}
}
