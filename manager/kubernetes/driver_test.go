package kubernetes

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// fakeAPI keeps pods and secrets in memory; a test sets a pod's status.
type fakeAPI struct {
	mu      sync.Mutex
	pods    map[string]*fakePod
	secrets map[string]Secret
	owners  map[string]OwnerReference
	deleted []string
}

type fakePod struct {
	pod    Pod
	status PodStatus
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{pods: map[string]*fakePod{}, secrets: map[string]Secret{}, owners: map[string]OwnerReference{}}
}

func (f *fakeAPI) CreateSecret(_ context.Context, s Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[s.Metadata.Name] = s
	return nil
}

func (f *fakeAPI) SetSecretOwner(_ context.Context, name string, o OwnerReference) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners[name] = o
	return nil
}

func (f *fakeAPI) DeleteSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, name)
	return nil
}

func (f *fakeAPI) ListSecrets(_ context.Context, selector string) ([]ObjectMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ObjectMeta
	for _, s := range f.secrets {
		if selects(selector, s.Metadata.Labels) {
			out = append(out, s.Metadata)
		}
	}
	return out, nil
}

func selects(selector string, labels map[string]string) bool {
	k, v, _ := strings.Cut(selector, "=")
	return labels[k] == v
}

func (f *fakeAPI) CreatePod(_ context.Context, p Pod) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pods[p.Metadata.Name] = &fakePod{pod: p, status: PodStatus{Phase: "Pending"}}
	return "uid-" + p.Metadata.Name, nil
}

func (f *fakeAPI) GetPod(_ context.Context, name string) (PodStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pods[name]
	if !ok {
		return PodStatus{}, ErrNotFound
	}
	return p.status, nil
}

func (f *fakeAPI) DeletePod(_ context.Context, name string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pods, name)
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeAPI) ListPods(_ context.Context, selector string) ([]ObjectMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ObjectMeta
	for _, p := range f.pods {
		if selects(selector, p.pod.Metadata.Labels) {
			out = append(out, p.pod.Metadata)
		}
	}
	return out, nil
}

func (f *fakeAPI) set(name string, st PodStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pods[name].status = st
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newDriver(api *fakeAPI) *Driver {
	return &Driver{API: api, Image: "ghcr.io/oyzuai/executor@sha256:" + strings.Repeat("a", 64), Command: []string{"oyzu-executor", "--oyzu", "oyzu"},
		Server: "https://runs.example", Pool: "k8s-prod", Manager: 7, MaxPods: 2, CPU: "2", Memory: "4Gi", Disk: "20Gi",
		NodeSelector: map[string]string{"workload": "builds"}, PollInterval: time.Millisecond, Log: quiet()}
}

func TestPodIsRestricted(t *testing.T) {
	api := newFakeAPI()
	d := newDriver(api)
	if err := d.Check(); err != nil {
		t.Fatal(err)
	}
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 42, Attempt: 2, StartupToken: "st_secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.Ref, "oyzu-7-job-42-2-") {
		t.Fatalf("handle = %+v", h)
	}
	p := api.pods[h.Ref].pod
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "st_secret") {
		t.Fatalf("the startup token is in the pod: %s", raw)
	}
	s := p.Spec
	if s.RestartPolicy != "Never" || *s.AutomountServiceAccountToken || *s.EnableServiceLinks {
		t.Fatalf("pod spec = %s", raw)
	}
	sc := s.SecurityContext
	if !*sc.RunAsNonRoot || *sc.RunAsUser != 1000 || *sc.RunAsGroup != 1000 || *sc.FSGroup != 1000 || sc.SeccompProfile.Type != "RuntimeDefault" {
		t.Fatalf("pod security = %s", raw)
	}
	if len(s.Containers) != 1 {
		t.Fatalf("containers = %d", len(s.Containers))
	}
	c := s.Containers[0]
	if *c.SecurityContext.Privileged || *c.SecurityContext.AllowPrivilegeEscalation ||
		!slices.Equal(c.SecurityContext.Capabilities.Drop, []string{"ALL"}) {
		t.Fatalf("container security = %s", raw)
	}
	wantArgs := []string{"--oyzu", "oyzu", "--server", "https://runs.example", "--startup-token-env", TokenEnv, "--work-dir", "/work"}
	if !slices.Equal(c.Command, []string{"oyzu-executor"}) || !slices.Equal(c.Args, wantArgs) {
		t.Fatalf("command %q args %q", c.Command, c.Args)
	}
	tokenVar := c.Env[slices.IndexFunc(c.Env, func(e EnvVar) bool { return e.Name == TokenEnv })]
	ref := tokenVar.ValueFrom.SecretKeyRef
	if tokenVar.Value != "" || ref.Name != h.Ref+"-token" || ref.Key != "startup-token" {
		t.Fatalf("token variable = %+v", tokenVar)
	}
	if c.Resources.Limits["cpu"] != "2" || c.Resources.Requests["memory"] != "4Gi" {
		t.Fatalf("resources = %+v", c.Resources)
	}
	if len(s.Volumes) != 1 || s.Volumes[0].EmptyDir == nil || s.Volumes[0].EmptyDir.SizeLimit != "20Gi" ||
		len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != "/work" {
		t.Fatalf("volumes = %s", raw)
	}
	wantNodes := map[string]string{"workload": "builds", "kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
	if !maps.Equal(s.NodeSelector, wantNodes) {
		t.Fatalf("node selector = %v", s.NodeSelector)
	}
	if d.NodeSelector["kubernetes.io/arch"] != "" {
		t.Fatal("the pool's node selector was changed")
	}
	wantLabels := map[string]string{LabelPool: "k8s-prod", LabelManager: "7", LabelJob: "42"}
	if !maps.Equal(p.Metadata.Labels, wantLabels) {
		t.Fatalf("labels = %v", p.Metadata.Labels)
	}
	sec := api.secrets[h.Ref+"-token"]
	if string(sec.Data["startup-token"]) != "st_secret" || !sec.Immutable || !maps.Equal(sec.Metadata.Labels, wantLabels) {
		t.Fatalf("secret = %+v", sec)
	}
	if o := api.owners[h.Ref+"-token"]; o.Kind != "Pod" || o.Name != h.Ref || o.UID != "uid-"+h.Ref {
		t.Fatalf("secret owner = %+v", o)
	}
	cp, _ := d.Capacity(context.Background())
	if cp.Running != 1 || !slices.Equal(cp.Ready, []manager.SlotID{"1"}) {
		t.Fatalf("Capacity = %+v", cp)
	}
}

func TestFacts(t *testing.T) {
	d := newDriver(newFakeAPI())
	f, _ := d.Facts(context.Background())
	if f[manager.FactIsolation] != "pod" || f[manager.FactDocker] != "false" || f[manager.FactCPU] != "2" ||
		f[manager.FactMemory] != "4Gi" || f[manager.FactArch] != "amd64" {
		t.Fatalf("Facts = %v", f)
	}
	d.RuntimeClass, d.Docker = "kata", true
	f, _ = d.Facts(context.Background())
	if f[manager.FactIsolation] != "sandboxed-pod" || f[manager.FactDocker] != "true" {
		t.Fatalf("Facts with kata = %v", f)
	}
}

func TestCheckRefuses(t *testing.T) {
	d := newDriver(newFakeAPI())
	d.Docker = true
	if d.Check() == nil {
		t.Fatal("accepted Docker without a sandboxed runtime class")
	}
	d = newDriver(newFakeAPI())
	d.User = -1
	if d.Check() == nil {
		t.Fatal("accepted a negative uid")
	}
}

func terminated(code int, reason string) PodStatus {
	phase := "Succeeded"
	if code != 0 {
		phase = "Failed"
	}
	return PodStatus{Phase: phase, ContainerStatuses: []ContainerStatus{{Name: "job",
		State: ContainerState{Terminated: &ContainerStateTerminated{ExitCode: code, Reason: reason}}}}}
}

func TestWaitOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status PodStatus
		gone   bool
		reason manager.ExitReason
		code   int
	}{
		{name: "succeeded", status: terminated(0, "Completed"), reason: manager.ExitExited},
		{name: "failed", status: terminated(3, "Error"), reason: manager.ExitExited, code: 3},
		{name: "out of memory", status: terminated(137, "OOMKilled"), reason: manager.ExitLost, code: -1},
		{name: "evicted", status: PodStatus{Phase: "Failed", Reason: "Evicted", Message: "low on ephemeral storage"},
			reason: manager.ExitLost, code: -1},
		{name: "deleted", gone: true, reason: manager.ExitLost, code: -1},
		{name: "bad image", status: PodStatus{Phase: "Pending", ContainerStatuses: []ContainerStatus{{Name: "job",
			State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "InvalidImageName"}}}}},
			reason: manager.ExitLost, code: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI()
			d := newDriver(api)
			h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1})
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.gone:
				_ = api.DeletePod(context.Background(), h.Ref, 0)
			case tc.status.Phase == "Pending":
				api.set(h.Ref, tc.status)
			default:
				api.set(h.Ref, PodStatus{Phase: "Running"})
				go func() {
					time.Sleep(10 * time.Millisecond)
					api.set(h.Ref, tc.status)
				}()
			}
			exit, err := d.Wait(context.Background(), h)
			if err != nil || exit.Reason != tc.reason || exit.Code != tc.code {
				t.Fatalf("Wait = %+v, %v", exit, err)
			}
		})
	}
}

func TestPodThatNeverStartsIsLost(t *testing.T) {
	api := newFakeAPI()
	d := newDriver(api)
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	d.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	api.set(h.Ref, PodStatus{Phase: "Pending", Conditions: []PodCondition{{Type: "PodScheduled", Status: "False",
		Reason: "Unschedulable", Message: "0/3 nodes are available"}}})
	go func() {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		now = now.Add(defaultStartTimeout)
		mu.Unlock()
	}()
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Reason != manager.ExitLost || !strings.Contains(exit.Detail, "0/3 nodes are available") {
		t.Fatalf("Wait = %+v, %v", exit, err)
	}
}

func TestWaitStopsWithItsContext(t *testing.T) {
	api := newFakeAPI()
	d := newDriver(api)
	h, _ := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	api.set(h.Ref, PodStatus{Phase: "Running"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.Wait(ctx, h); err == nil {
		t.Fatal("Wait returned without the pod ending")
	}
	if _, ok := api.pods[h.Ref]; !ok {
		t.Fatal("Wait returning early deleted the pod")
	}
}

func TestTeardownAndReap(t *testing.T) {
	api := newFakeAPI()
	d := newDriver(api)
	ctx := context.Background()
	h, _ := d.Start(ctx, "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	mine := func(job string) ObjectMeta {
		return ObjectMeta{Name: "oyzu-7-job-" + job + "-1-x", Labels: map[string]string{LabelManager: "7", LabelJob: job}}
	}
	other := ObjectMeta{Name: "oyzu-8-job-4-1-x", Labels: map[string]string{LabelManager: "8", LabelJob: "4"}}
	for _, m := range []ObjectMeta{mine("2"), mine("3"), other} {
		_, _ = api.CreatePod(ctx, Pod{Metadata: m})
		_ = api.CreateSecret(ctx, Secret{Metadata: ObjectMeta{Name: m.Name + "-token", Labels: m.Labels}})
	}
	if err := d.Reap(ctx, []manager.JobID{3}); err != nil {
		t.Fatal(err)
	}
	var pods, secrets []string
	for n := range api.pods {
		pods = append(pods, n)
	}
	for n := range api.secrets {
		secrets = append(secrets, n)
	}
	slices.Sort(pods)
	slices.Sort(secrets)
	if !slices.Equal(pods, []string{h.Ref, "oyzu-7-job-3-1-x", "oyzu-8-job-4-1-x"}) {
		t.Fatalf("pods after Reap = %v", pods)
	}
	if !slices.Equal(secrets, []string{h.Ref + "-token", "oyzu-7-job-3-1-x-token", "oyzu-8-job-4-1-x-token"}) {
		t.Fatalf("secrets after Reap = %v", secrets)
	}

	if err := d.Teardown(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.pods[h.Ref]; ok {
		t.Fatal("pod left after Teardown")
	}
	if _, ok := api.secrets[h.Ref+"-token"]; ok {
		t.Fatal("secret left after Teardown")
	}
	if cp, _ := d.Capacity(ctx); len(cp.Ready) != 2 {
		t.Fatalf("slot not freed: %+v", cp)
	}
}

func TestCheckImageDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name  string
		image string
		valid bool
	}{
		{"empty", "", false},
		{"bare name", "executor", false},
		{"latest tag", "executor:latest", false},
		{"version tag", "executor:1.2.3", false},
		{"missing digest", "executor@sha256:", false},
		{"short digest", "executor@sha256:abc", false},
		{"long digest", "executor@sha256:" + digest + "a", false},
		{"non hex digest", "executor@sha256:" + strings.Repeat("g", 64), false},
		{"uppercase digest", "executor@sha256:" + strings.Repeat("A", 64), false},
		{"wrong algorithm", "executor@sha512:" + digest, false},
		{"missing name", "@sha256:" + digest, false},
		{"trailing suffix", "executor@sha256:" + digest + ":tag", false},
		{"digest", "ghcr.io/oyzuai/executor@sha256:" + digest, true},
		{"tag and digest", "ghcr.io/oyzuai/executor:1.2.3@sha256:" + digest, true},
		{"registry port", "localhost:5000/executor@sha256:" + digest, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(newFakeAPI())
			d.Image = tc.image
			err := d.Check()
			if (err == nil) != tc.valid {
				t.Fatalf("Check() = %v, want valid = %v", err, tc.valid)
			}
			if !tc.valid && tc.image != "" && err != nil && !strings.Contains(err.Error(), "not pinned by digest") {
				t.Fatalf("Check() returned an unrelated error: %v", err)
			}
		})
	}
}
