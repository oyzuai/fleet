package container

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/runnerclient"
)

// fakeEngine keeps containers and volumes in memory. A container "runs" until
// exit is sent on its channel.
type fakeEngine struct {
	mu         sync.Mutex
	present    bool
	pullErr    error
	pulls      int
	volumes    map[string]map[string]string
	containers map[string]*fakeContainer
	next       int
	networks   map[string]*fakeNetwork
	// probeExit is the exit code the self-test's probe container ends with.
	probeExit int
	// ipv6Probe is what `gateway probe-ipv6` prints, "available" when empty,
	// and ipv6ProbeExit how it exits. ipv6Probes counts its containers.
	ipv6Probe     string
	ipv6ProbeExit int
	ipv6Probes    int
}

type fakeNetwork struct {
	id        string
	spec      NetworkSpec
	subnet    string
	connected map[string]string
}

type fakeContainer struct {
	name    string
	spec    Spec
	files   map[string]*tar.Header
	content map[string]string
	started bool
	stopped bool
	exit    chan int
	oom     bool
	logs    string
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{volumes: map[string]map[string]string{}, containers: map[string]*fakeContainer{}, networks: map[string]*fakeNetwork{}}
}

func (e *fakeEngine) Info(context.Context) (Info, error) {
	return Info{OSType: "linux", Architecture: "x86_64", NCPU: 8, MemTotal: 16 << 30}, nil
}

func (e *fakeEngine) ImagePresent(context.Context, string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.present, nil
}

func (e *fakeEngine) PullImage(context.Context, string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pulls++
	if e.pullErr != nil {
		return e.pullErr
	}
	e.present = true
	return nil
}

func (e *fakeEngine) CreateVolume(_ context.Context, name string, labels map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.volumes[name] = maps.Clone(labels)
	return nil
}

func (e *fakeEngine) RemoveVolume(_ context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.volumes, name)
	return nil
}

func (e *fakeEngine) ListVolumes(_ context.Context, labels map[string]string) ([]Volume, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Volume
	for n, l := range e.volumes {
		if matches(l, labels) {
			out = append(out, Volume{Name: n, Labels: l})
		}
	}
	return out, nil
}

func matches(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func (e *fakeEngine) CreateContainer(_ context.Context, name string, spec Spec) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var id string
	if len(spec.Cmd) > 2 && spec.Cmd[2] == "probe-ipv6" {
		// Kept out of the c1, c2, ... numbering the other tests rely on.
		id = fmt.Sprintf("ipv6-%d", e.ipv6Probes)
	} else {
		e.next++
		id = fmt.Sprintf("c%d", e.next)
	}
	e.containers[id] = &fakeContainer{name: name, spec: spec, files: map[string]*tar.Header{},
		content: map[string]string{}, exit: make(chan int, 1)}
	return id, nil
}

func (e *fakeEngine) container(id string) (*fakeContainer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.containers[id]
	if !ok {
		return nil, errors.New("no such container")
	}
	return c, nil
}

func (e *fakeEngine) CopyFiles(_ context.Context, id, _ string, archive []byte) error {
	c, err := e.container(id)
	if err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(tr)
		e.mu.Lock()
		c.files[h.Name], c.content[h.Name] = h, string(b)
		e.mu.Unlock()
	}
}

func (e *fakeEngine) StartContainer(_ context.Context, id string) error {
	c, err := e.container(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	c.started = true
	if len(c.spec.Cmd) > 2 && c.spec.Cmd[1] == "gateway" && c.spec.Cmd[2] == "probe" {
		c.exit <- e.probeExit
	}
	if len(c.spec.Cmd) > 2 && c.spec.Cmd[1] == "gateway" && c.spec.Cmd[2] == "probe-ipv6" {
		e.ipv6Probes++
		c.logs = e.ipv6Probe
		if c.logs == "" {
			c.logs = "available"
		}
		c.logs += "\n"
		c.exit <- e.ipv6ProbeExit
	}
	e.mu.Unlock()
	return nil
}

func (e *fakeEngine) WaitContainer(ctx context.Context, id string) (int, error) {
	c, err := e.container(id)
	if err != nil {
		return 0, err
	}
	select {
	case code := <-c.exit:
		return code, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (e *fakeEngine) InspectContainer(_ context.Context, id string) (State, error) {
	c, err := e.container(id)
	if err != nil {
		return State{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return State{Running: c.started && !c.stopped, OOMKilled: c.oom}, nil
}

func (e *fakeEngine) ContainerLogs(_ context.Context, id string, _ int) ([]byte, error) {
	c, err := e.container(id)
	if err != nil {
		return nil, err
	}
	return []byte(c.logs), nil
}

func (e *fakeEngine) StopContainer(_ context.Context, id string, _ time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.containers[id]; ok {
		c.stopped = true
	}
	return nil
}

func (e *fakeEngine) RemoveContainer(_ context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.containers, id)
	for _, n := range e.networks {
		delete(n.connected, id)
	}
	return nil
}

func (e *fakeEngine) ListContainers(_ context.Context, labels map[string]string) ([]Summary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Summary
	for id, c := range e.containers {
		if matches(c.spec.Labels, labels) {
			out = append(out, Summary{ID: id, Name: c.name, Labels: c.spec.Labels})
		}
	}
	return out, nil
}

func (e *fakeEngine) CreateNetwork(_ context.Context, name string, spec NetworkSpec) (Network, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.networks[name]; ok {
		return Network{}, errors.New("network exists")
	}
	n := &fakeNetwork{id: fmt.Sprintf("n%d", len(e.networks)+1), spec: spec, connected: map[string]string{}}
	n.subnet = fmt.Sprintf("10.200.%d.0/24", e.nextSubnet())
	e.networks[name] = n
	return Network{ID: n.id, Name: name, Labels: spec.Labels, Subnet: n.subnet}, nil
}

func (e *fakeEngine) nextSubnet() int {
	e.next++
	return e.next
}

func (e *fakeEngine) RemoveNetwork(_ context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	n, ok := e.networks[name]
	if !ok {
		return nil
	}
	if len(n.connected) > 0 {
		return errors.New("network has active endpoints")
	}
	delete(e.networks, name)
	return nil
}

func (e *fakeEngine) ListNetworks(_ context.Context, labels map[string]string) ([]Network, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Network
	for name, n := range e.networks {
		if matches(n.spec.Labels, labels) {
			out = append(out, Network{ID: n.id, Name: name, Labels: n.spec.Labels, Subnet: n.subnet})
		}
	}
	return out, nil
}

func (e *fakeEngine) ConnectNetwork(_ context.Context, network, container string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n, ok := e.networks[network]
	if !ok {
		return "", errors.New("no such network")
	}
	ip := fmt.Sprintf("%s.%d", strings.TrimSuffix(n.subnet, ".0/24"), 2+len(n.connected))
	n.connected[container] = ip
	return ip, nil
}

func (e *fakeEngine) DisconnectNetwork(_ context.Context, network, container string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n, ok := e.networks[network]; ok {
		delete(n.connected, container)
	}
	return nil
}

func (e *fakeEngine) PublishedPort(context.Context, string, int) (int, error) { return 40000, nil }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newDriver(e *fakeEngine) *Driver {
	return &Driver{Engine: e, Image: "ghcr.io/oyzuai/executor@sha256:" + strings.Repeat("a", 64), Command: []string{"oyzu-executor", "--oyzu", "oyzu"},
		Server: "https://runs.example", Pool: "linux", Manager: 7, Slots: 2, CPUs: 2, MemoryBytes: 4 << 30, Log: quiet()}
}

// ready waits for the image pull Capacity starts and returns the capacity
// after it.
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

func TestCheckRefusesWeakIsolation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Driver)
	}{
		{"host network", func(d *Driver) { d.Network = "host" }},
		{"another container's network", func(d *Driver) { d.Network = "container:db" }},
		{"root", func(d *Driver) { d.User = "0:0" }},
		{"named user", func(d *Driver) { d.User = "builder" }},
		{"no image", func(d *Driver) { d.Image = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(newFakeEngine())
			tc.edit(d)
			if err := d.Check(); err == nil {
				t.Fatal("Check accepted it")
			}
		})
	}
	if err := newDriver(newFakeEngine()).Check(); err != nil {
		t.Fatalf("Check refused the defaults: %v", err)
	}
}

func TestFactsNeverAdvertiseDocker(t *testing.T) {
	f, err := newDriver(newFakeEngine()).Facts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := manager.Facts{
		manager.FactOS: "linux", manager.FactArch: "amd64", manager.FactIsolation: "container",
		manager.FactDocker: "false", manager.FactCPU: "2", manager.FactMemory: "4096Mi", manager.FactEgress: "open",
	}
	if !maps.Equal(f, want) {
		t.Fatalf("Facts = %v, want %v", f, want)
	}
}

func TestNoSlotIsReadyUntilTheImageIsPulled(t *testing.T) {
	e := newFakeEngine()
	e.pullErr = errors.New("registry down")
	d := newDriver(e)
	d.Now = func() time.Time { return time.Unix(1000, 0) }
	c, _ := d.Capacity(context.Background())
	if len(c.Ready) != 0 || c.Provisioning != 2 {
		t.Fatalf("first Capacity = %+v", c)
	}
	deadline := time.Now().Add(5 * time.Second)
	var err error
	for err == nil && time.Now().Before(deadline) {
		c, err = d.Capacity(context.Background())
		time.Sleep(5 * time.Millisecond)
	}
	if err == nil || len(c.Ready) != 0 || c.Provisioning != 0 {
		t.Fatalf("after a failed pull Capacity = %+v, %v", c, err)
	}
	if _, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 1, Attempt: 1}); err == nil {
		t.Fatal("Start ran a job without the image")
	}
	e.mu.Lock()
	e.pullErr = nil
	e.mu.Unlock()
	d.Now = func() time.Time { return time.Unix(1000, 0).Add(pullRetry) }
	if c := ready(t, d); len(c.Ready) != 2 {
		t.Fatalf("after the retry Capacity = %+v", c)
	}
	if e.pulls != 2 {
		t.Fatalf("pulls = %d, want 2", e.pulls)
	}
}

func TestStartRunsOneIsolatedContainerPerJob(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	ctx := context.Background()
	h, err := d.Start(ctx, "0", runnerclient.Claim{JobID: 42, Attempt: 2, StartupToken: "st_secret"})
	if err != nil {
		t.Fatal(err)
	}
	if e.pulls != 0 {
		t.Fatal("pulled an image that was already present")
	}
	c, err := e.container("c1")
	if err != nil {
		t.Fatal(err)
	}
	if !c.started || c.name != h.Ref || !strings.HasPrefix(h.Ref, "oyzu-7-job-42-2-") {
		t.Fatalf("container %+v, handle %+v", c, h)
	}
	s := c.spec
	if s.User != "1000:1000" || s.Network != "bridge" || s.PidsLimit != 4096 || s.NanoCPUs != 2e9 || s.MemoryBytes != 4<<30 {
		t.Fatalf("spec = %+v", s)
	}
	if s.Volume != h.Ref+"-work" || s.WorkDir != WorkDir {
		t.Fatalf("volume %q at %q", s.Volume, s.WorkDir)
	}
	if _, ok := e.volumes[s.Volume]; !ok {
		t.Fatal("workspace volume not created")
	}
	wantCmd := []string{"oyzu-executor", "--oyzu", "oyzu", "--server", "https://runs.example",
		"--startup-token-file", "/run/oyzu/startup-token", "--work-dir", "/work"}
	if !slices.Equal(s.Cmd, wantCmd) {
		t.Fatalf("Cmd = %q", s.Cmd)
	}
	if slices.ContainsFunc(s.Cmd, func(a string) bool { return strings.Contains(a, "st_secret") }) {
		t.Fatal("the startup token is on the command line")
	}
	want := map[string]string{LabelPool: "linux", LabelManager: "7", LabelJob: "42"}
	if !maps.Equal(s.Labels, want) {
		t.Fatalf("labels = %v", s.Labels)
	}
	tok := c.files["run/oyzu/startup-token"]
	dir := c.files["run/oyzu/"]
	if tok == nil || dir == nil || c.content["run/oyzu/startup-token"] != "st_secret" {
		t.Fatalf("token files = %v", c.files)
	}
	if tok.Mode != 0o400 || dir.Mode != 0o700 || tok.Uid != 1000 || tok.Gid != 1000 || dir.Uid != 1000 {
		t.Fatalf("token %o %d:%d, dir %o %d", tok.Mode, tok.Uid, tok.Gid, dir.Mode, dir.Uid)
	}
	cp, _ := d.Capacity(ctx)
	if cp.Running != 1 || !slices.Equal(cp.Ready, []manager.SlotID{"1"}) {
		t.Fatalf("Capacity = %+v", cp)
	}
	if _, err := d.Start(ctx, "0", runnerclient.Claim{JobID: 43, Attempt: 1}); err == nil {
		t.Fatal("Start reused a busy slot")
	}

	c.exit <- 3
	exit, err := d.Wait(ctx, h)
	if err != nil || exit.Reason != manager.ExitExited || exit.Code != 3 {
		t.Fatalf("Wait = %+v, %v", exit, err)
	}
	if err := d.Teardown(ctx, h); err != nil {
		t.Fatal(err)
	}
	if len(e.containers) != 0 || len(e.volumes) != 0 {
		t.Fatalf("left behind %v, %v", e.containers, e.volumes)
	}
	if cp, _ := d.Capacity(ctx); len(cp.Ready) != 2 {
		t.Fatalf("slot not freed: %+v", cp)
	}
}

func TestOutOfMemoryIsLost(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	h, err := d.Start(context.Background(), "1", runnerclient.Claim{JobID: 5, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := e.container("c1")
	c.oom = true
	c.exit <- 137
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Reason != manager.ExitLost {
		t.Fatalf("Wait = %+v, %v", exit, err)
	}
}

func TestAFailedExecutorKeepsTheEndOfItsOutput(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	h, err := d.Start(context.Background(), "0", runnerclient.Claim{JobID: 5, Attempt: 1, StartupToken: "startup-secret"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := e.container("c1")
	c.logs = "reading startup-secret\nx509: certificate signed by unknown authority\n"
	c.exit <- 1
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Code != 1 || !strings.Contains(exit.Detail, "x509: certificate signed by unknown authority") ||
		strings.Contains(exit.Detail, "startup-secret") {
		t.Fatalf("Wait = %+v, %v", exit, err)
	}
	if err := d.Teardown(context.Background(), h); err != nil {
		t.Fatal(err)
	}

	// A clean exit carries no output.
	h, _ = d.Start(context.Background(), "0", runnerclient.Claim{JobID: 6, Attempt: 1})
	c, _ = e.container("c2")
	c.logs = "all good"
	c.exit <- 0
	if exit, _ := d.Wait(context.Background(), h); !exit.Clean() || strings.Contains(exit.Detail, "all good") {
		t.Fatalf("clean Wait = %+v", exit)
	}
}

func TestReapRemovesOnlyOrphans(t *testing.T) {
	e := newFakeEngine()
	e.present = true
	d := newDriver(e)
	ready(t, d)
	ctx := context.Background()
	h, err := d.Start(ctx, "0", runnerclient.Claim{JobID: 1, Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	mine := func(job string) map[string]string {
		return map[string]string{LabelPool: "linux", LabelManager: "7", LabelJob: job}
	}
	_, _ = e.CreateContainer(ctx, "oyzu-7-job-2-1-old", Spec{Labels: mine("2")})
	_ = e.CreateVolume(ctx, "oyzu-7-job-2-1-old-work", mine("2"))
	_, _ = e.CreateContainer(ctx, "oyzu-7-job-3-1-live", Spec{Labels: mine("3")})
	other := mine("4")
	other[LabelManager] = "8"
	_, _ = e.CreateContainer(ctx, "oyzu-8-job-4-1-x", Spec{Labels: other})
	_ = e.CreateVolume(ctx, "oyzu-8-job-4-1-x-work", other)

	if err := d.Reap(ctx, []manager.JobID{3}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range e.containers {
		names = append(names, c.name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{h.Ref, "oyzu-7-job-3-1-live", "oyzu-8-job-4-1-x"}) {
		t.Fatalf("containers after Reap = %v", names)
	}
	if _, ok := e.volumes["oyzu-7-job-2-1-old-work"]; ok {
		t.Fatal("orphan volume kept")
	}
	if _, ok := e.volumes[h.Ref+"-work"]; !ok {
		t.Fatal("live job's volume removed")
	}
	if _, ok := e.volumes["oyzu-8-job-4-1-x-work"]; !ok {
		t.Fatal("another manager's volume removed")
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
			d := newDriver(newFakeEngine())
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

func TestJobsKeepTheIPv6SysctlsUnlessTheEngineKernelHasNoIPv6(t *testing.T) {
	ipv6Off := map[string]string{"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}
	start := func(t *testing.T, e *fakeEngine, d *Driver, job int64) Spec {
		t.Helper()
		h, err := d.Start(context.Background(), manager.SlotID(strconv.FormatInt(job%2, 10)), runnerclient.Claim{JobID: job, Attempt: 1, StartupToken: "st"})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range e.containers {
			if c.name == h.Ref {
				return c.spec
			}
		}
		t.Fatalf("no container %s", h.Ref)
		return Spec{}
	}
	for _, c := range []struct {
		name, probe string
		exit        int
		want        map[string]string
		probes      int
	}{
		// IPv6 present is remembered; the sysctls stay.
		{name: "kernel with IPv6", probe: "available", want: ipv6Off, probes: 1},
		// Only the kernel's own answer drops them, and it is asked every time.
		{name: "kernel booted without IPv6", probe: "disabled", want: nil, probes: 2},
		// Anything else keeps them for that container only.
		{name: "unexpected answer", probe: "disabled-ish", want: ipv6Off, probes: 2},
		{name: "extra output", probe: "noise\ndisabled", want: ipv6Off, probes: 2},
		{name: "probe fails", probe: "disabled", exit: 1, want: ipv6Off, probes: 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newFakeEngine()
			e.present = true
			e.ipv6Probe, e.ipv6ProbeExit = c.probe, c.exit
			d := newDriver(e)
			ready(t, d)
			for job := int64(1); job <= 2; job++ {
				if got := start(t, e, d, job).Sysctls; !maps.Equal(got, c.want) {
					t.Fatalf("job %d sysctls = %v, want %v", job, got, c.want)
				}
			}
			if e.ipv6Probes != c.probes {
				t.Fatalf("%d probes, want %d", e.ipv6Probes, c.probes)
			}
			for id, ct := range e.containers {
				if strings.HasPrefix(id, "ipv6-") {
					t.Fatalf("probe %s was not removed", id)
				}
				if slices.Contains(ct.spec.Cmd, "probe-ipv6") {
					t.Fatal("probe left behind")
				}
			}
		})
	}
}

func TestTheReadinessBoundarySaysWhenIPv6SysctlsAreLeftOut(t *testing.T) {
	boundary := func(probe string) readiness.Boundary {
		e := newFakeEngine()
		e.present = true
		e.ipv6Probe = probe
		d := newDriver(e)
		ready(t, d)
		d.Engine = identifiedEngine{e}
		b, err := d.ReadinessBoundary(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if with, without := boundary("available"), boundary("disabled"); with.Runtime == without.Runtime {
		t.Fatal("the boundary does not tell a kernel booted without IPv6 apart")
	}
}

// identifiedEngine is a fake engine with the identity a readiness boundary
// needs.
type identifiedEngine struct{ *fakeEngine }

func (e identifiedEngine) Info(ctx context.Context) (Info, error) {
	info, err := e.fakeEngine.Info(ctx)
	info.ID, info.ServerVersion = "engine-1", "29.0.0"
	return info, err
}
