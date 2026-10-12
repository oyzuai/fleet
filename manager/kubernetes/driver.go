// Package kubernetes is the Kubernetes pool driver: one pod per job in a
// namespace the manager owns, through the Kubernetes API with a service
// account limited to pods and secrets there.
//
// A job's pod runs the pinned executor image under the restricted Pod
// Security profile: a numeric non-root user, every capability dropped, no
// privilege escalation, the runtime's default seccomp profile, no service
// account token and no service links. Its only volume is an emptyDir
// workspace. The startup token reaches it through a per-job Secret, as an
// environment variable the runner unsets once read, and the Secret is owned
// by the pod so the cluster deletes it too. Pods report
// oyzu.io/isolation=pod, or sandboxed-pod with a runtime class such as Kata
// or gVisor, and oyzu.io/docker=false unless that runtime class gives each
// pod its own VM (IMPL-115).
package kubernetes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// Labels every pod and secret carries, so Reap can find what this manager
// created and a person can see which job a pod served.
const (
	LabelPool    = "oyzu.io/pool"
	LabelManager = "oyzu.io/manager"
	LabelJob     = "oyzu.io/job"
)

const (
	// WorkDir is where the job's emptyDir workspace is mounted.
	WorkDir = "/work"
	// TokenEnv is the variable the startup token arrives in.
	TokenEnv  = "OYZU_STARTUP_TOKEN"
	tokenKey  = "startup-token"
	container = "job"

	defaultUser         = 1000
	defaultStartTimeout = 5 * time.Minute
	defaultPoll         = 2 * time.Second
	defaultStopGrace    = 30 * time.Second
)

// Driver runs each job in a fresh pod. Slots are always ready: the cluster,
// or its autoscaler, finds a node after the claim, and a pod that is not
// running within StartTimeout is lost, so its job is handed back without
// using an attempt.
type Driver struct {
	API API
	// Image is the pinned executor image, by SHA-256 digest.
	Image string
	// Command starts the runner in the image; the job's flags follow it.
	Command []string
	// Server is the runs URL the runner calls.
	Server string
	// Pool and Manager name this manager; every pod and secret is labelled
	// with them.
	Pool    string
	Manager int64
	// MaxPods is how many jobs run at once; at least 1.
	MaxPods int
	// CPU, Memory and Disk are Kubernetes quantities ("2", "4Gi") each pod
	// requests and is limited to; Disk caps the workspace. Empty leaves it
	// unset.
	CPU, Memory, Disk string
	// Arch is the node architecture pods are pinned to; amd64 when empty.
	Arch string
	// RuntimeClass is the pods' runtimeClassName, such as kata or gvisor.
	RuntimeClass string
	// Docker reports oyzu.io/docker=true. It needs a RuntimeClass that gives
	// each pod its own VM, where a rootless BuildKit can run.
	Docker       bool
	NodeSelector map[string]string
	Tolerations  []Toleration
	// PriorityClass is the pods' priorityClassName, if any.
	PriorityClass string
	// User is the uid and gid jobs run as; 1000 when 0, so never root.
	User int64
	// StartTimeout is how long a pod may take to be scheduled and start;
	// 5 minutes, the startup token's lifetime, when 0.
	StartTimeout time.Duration
	// PollInterval is how often a running pod's status is read; 2s when 0.
	PollInterval time.Duration
	// StopGrace is how long a runner may report after it is asked to stop;
	// 30s when 0.
	StopGrace time.Duration
	// Egress is how jobs' network is controlled; open when empty. Enforce
	// and report need NewControl and an API that is an EgressAPI, and run
	// the gateway from Image, whose Command[0] is the executor.
	Egress EgressMode
	// NewControl builds the client for the gateway's control API from its
	// token; the manager reaches it through its Service in the cluster or
	// through the API server's proxy outside it.
	NewControl func(token string) GatewayControl
	// GatewayWait is how long the gateway may take to answer; 5 minutes
	// when 0.
	GatewayWait time.Duration
	Log         *slog.Logger
	Now         func() time.Time

	mu    sync.Mutex
	inUse map[manager.SlotID]*job
	// The gateway, once set up: its Service address and control client. The
	// self-test is tested once it has run, egressOK if it passed and
	// factsDirty until the manager has read the facts after it changed.
	gwReady, settingUp           bool
	setupErr                     error
	lastSetup                    time.Time
	gwIP                         string
	control                      GatewayControl
	tested, egressOK, factsDirty bool
}

// job is one job's pod and secret.
type job struct {
	name    string
	secret  string
	started time.Time
	// token is the claim's startup token, masked out of the log tail.
	token string
	// policy is the job's NetworkPolicy and registered says the gateway
	// knows the job, when egress is controlled.
	policy     string
	registered bool
}

var _ manager.Driver = (*Driver)(nil)

var imagePinned = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// labelValue is what Kubernetes accepts as a label value.
var labelValue = regexp.MustCompile(`^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$`)

// Check refuses configurations that would weaken a job's isolation or that
// the cluster would reject.
func (d *Driver) Check() error {
	switch {
	case d.API == nil || d.Image == "" || len(d.Command) == 0 || d.Server == "":
		return errors.New("kubernetes: API, Image, Command and Server are required")
	case !imagePinned.MatchString(d.Image):
		return fmt.Errorf("kubernetes: executor image %q is not pinned by digest", d.Image)
	case d.User < 0:
		return errors.New("kubernetes: User must be a non-root uid")
	case d.Docker && d.RuntimeClass == "":
		return errors.New("kubernetes: Docker needs a RuntimeClass that runs each pod in its own VM")
	case !d.Egress.Valid():
		return fmt.Errorf("kubernetes: egress mode %q is not enforce, report or open", d.Egress)
	}
	if d.sandboxed() {
		if _, err := d.egressAPI(); err != nil {
			return err
		}
		if d.NewControl == nil {
			return errors.New("kubernetes: egress needs NewControl to reach the gateway")
		}
	}
	return nil
}

func (d *Driver) slots() int { return max(1, d.MaxPods) }

func (d *Driver) user() int64 {
	if d.User == 0 {
		return defaultUser
	}
	return d.User
}

func (d *Driver) arch() string {
	if d.Arch == "" {
		return "amd64"
	}
	return d.Arch
}

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

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func (d *Driver) managerLabel() string { return strconv.FormatInt(d.Manager, 10) }

func (d *Driver) selector() string { return LabelManager + "=" + d.managerLabel() }

// Facts implements manager.Driver from the pod limits; the cluster's
// nodes are its own business.
func (d *Driver) Facts(context.Context) (manager.Facts, error) {
	f := manager.Facts{
		manager.FactOS:        "linux",
		manager.FactArch:      d.arch(),
		manager.FactIsolation: "pod",
		manager.FactDocker:    strconv.FormatBool(d.Docker),
	}
	if d.RuntimeClass != "" {
		f[manager.FactIsolation] = "sandboxed-pod"
	}
	if d.CPU != "" {
		f[manager.FactCPU] = d.CPU
	}
	if d.Memory != "" {
		f[manager.FactMemory] = d.Memory
	}
	if d.Disk != "" {
		f[manager.FactDisk] = d.Disk
	}
	d.egressFacts(f)
	return f, nil
}

// Capacity implements manager.Driver. Every free slot is ready.
func (d *Driver) Capacity(context.Context) (manager.Capacity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := manager.Capacity{Max: d.slots(), Running: len(d.inUse)}
	if d.sandboxed() {
		// The gateway and, when enforcing, its self-test come first; the
		// self-test is repeated while it fails.
		retry := d.gwReady && d.Egress == EgressEnforce && !d.egressOK || !d.gwReady
		if !d.settingUp && retry && (d.lastSetup.IsZero() || d.now().Sub(d.lastSetup) >= setupRetry) {
			d.settingUp, d.lastSetup = true, d.now()
			go d.setup(context.Background())
		}
		if !d.gwReady || d.Egress == EgressEnforce && !d.tested {
			c.Provisioning = c.Max - c.Running
			return c, d.setupErr
		}
	}
	for i := range d.slots() {
		id := manager.SlotID(strconv.Itoa(i))
		if _, busy := d.inUse[id]; !busy {
			c.Ready = append(c.Ready, id)
		}
	}
	return c, nil
}

// Provision implements manager.Driver. Nodes come from the cluster's
// autoscaler, which reacts to pending pods.
func (d *Driver) Provision(context.Context, int) error { return nil }

func (d *Driver) labels(jobID int64) map[string]string {
	l := map[string]string{LabelManager: d.managerLabel(), LabelJob: strconv.FormatInt(jobID, 10)}
	if d.Pool != "" && len(d.Pool) <= 63 && labelValue.MatchString(d.Pool) {
		l[LabelPool] = d.Pool
	}
	return l
}

// Start implements manager.Driver: the token's secret, then the pod,
// then the pod made the secret's owner.
func (d *Driver) Start(ctx context.Context, slot manager.SlotID, c runnerclient.Claim) (manager.Handle, error) {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("oyzu-%d-job-%d-%d-%s", d.Manager, c.JobID, c.Attempt, hex.EncodeToString(suffix))
	j := &job{name: name, secret: name + "-token", started: d.now(), token: c.StartupToken}
	d.mu.Lock()
	if d.sandboxed() && (!d.gwReady || d.Egress == EgressEnforce && !d.tested) {
		d.mu.Unlock()
		return manager.Handle{}, errors.New("the egress gateway is not ready")
	}
	if _, busy := d.inUse[slot]; busy {
		d.mu.Unlock()
		return manager.Handle{}, fmt.Errorf("slot %s is not ready", slot)
	}
	if d.inUse == nil {
		d.inUse = map[manager.SlotID]*job{}
	}
	d.inUse[slot] = j
	d.mu.Unlock()

	h := manager.Handle{Slot: slot, Job: c.JobID, Attempt: c.Attempt, Ref: name}
	labels := d.labels(c.JobID)
	if err := d.API.CreateSecret(ctx, Secret{
		Metadata: ObjectMeta{Name: j.secret, Labels: labels},
		Type:     "Opaque", Data: map[string][]byte{tokenKey: []byte(c.StartupToken)}, Immutable: true,
	}); err != nil {
		return h, fmt.Errorf("create the token secret: %w", err)
	}
	pod := d.pod(name, j.secret, labels)
	if d.sandboxed() {
		d.sandboxPod(&pod)
	}
	uid, err := d.API.CreatePod(ctx, pod)
	if err != nil {
		return h, fmt.Errorf("create the pod: %w", err)
	}
	owner := OwnerReference{APIVersion: "v1", Kind: "Pod", Name: name, UID: uid}
	if err := d.API.SetSecretOwner(ctx, j.secret, owner); err != nil {
		// Teardown and Reap delete the secret anyway.
		d.log().Warn("could not make the pod own its token secret", "pod", name, "error", err)
	}
	if d.sandboxed() {
		if err := d.openSandbox(ctx, j, labels, owner, d.allowFor(c)); err != nil {
			return h, err
		}
	}
	return h, nil
}

func ptr[T any](v T) *T { return &v }

// pod is the job's pod, with the restricted Pod Security profile.
func (d *Driver) pod(name, secret string, labels map[string]string) Pod {
	uid := d.user()
	args := append(append([]string{}, d.Command[1:]...),
		"--server", d.Server, "--startup-token-env", TokenEnv, "--work-dir", WorkDir)
	res := ResourceRequirements{}
	for k, v := range map[string]string{"cpu": d.CPU, "memory": d.Memory} {
		if v != "" {
			if res.Limits == nil {
				res.Limits, res.Requests = map[string]string{}, map[string]string{}
			}
			res.Limits[k], res.Requests[k] = v, v
		}
	}
	nodes := maps.Clone(d.NodeSelector)
	if nodes == nil {
		nodes = map[string]string{}
	}
	nodes["kubernetes.io/os"] = "linux"
	nodes["kubernetes.io/arch"] = d.arch()
	return Pod{
		Metadata: ObjectMeta{Name: name, Labels: labels},
		Spec: PodSpec{
			RestartPolicy:                 "Never",
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			RuntimeClassName:              d.RuntimeClass,
			PriorityClassName:             d.PriorityClass,
			NodeSelector:                  nodes,
			Tolerations:                   slices.Clone(d.Tolerations),
			TerminationGracePeriodSeconds: ptr(int64(orDefault(d.StopGrace, defaultStopGrace) / time.Second)),
			SecurityContext: &PodSecurityContext{
				RunAsNonRoot: ptr(true), RunAsUser: ptr(uid), RunAsGroup: ptr(uid), FSGroup: ptr(uid),
				SeccompProfile: &SeccompProfile{Type: "RuntimeDefault"},
			},
			Containers: []Container{{
				Name: container, Image: d.Image, ImagePullPolicy: "IfNotPresent",
				Command: d.Command[:1], Args: args, WorkingDir: WorkDir,
				Env: []EnvVar{
					{Name: "HOME", Value: WorkDir},
					{Name: TokenEnv, ValueFrom: &EnvVarSource{SecretKeyRef: &SecretKeySelector{Name: secret, Key: tokenKey}}},
				},
				Resources: res,
				SecurityContext: &ContainerSecurityContext{
					Privileged: ptr(false), AllowPrivilegeEscalation: ptr(false),
					Capabilities: &Capabilities{Drop: []string{"ALL"}},
				},
				VolumeMounts: []VolumeMount{{Name: "work", MountPath: WorkDir}},
			}},
			Volumes: []Volume{{Name: "work", EmptyDir: &EmptyDirVolume{SizeLimit: d.Disk}}},
		},
	}
}

func (d *Driver) job(h manager.Handle) (*job, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	j, ok := d.inUse[h.Slot]
	if !ok || j.name != h.Ref {
		return nil, fmt.Errorf("no pod %s in slot %s", h.Ref, h.Slot)
	}
	return j, nil
}

// fatalWaiting are reasons a pod's container will never start without a
// change to the pod.
var fatalWaiting = map[string]bool{
	"InvalidImageName": true, "ErrImageNeverPull": true, "CreateContainerConfigError": true,
}

// Wait implements manager.Driver by reading the pod's status until it
// ends. A pod that is evicted, killed for memory, deleted from under the
// manager, or not running within StartTimeout was lost. An executor that
// did not end cleanly has the masked end of its output in the exit's
// detail, read before Teardown deletes the pod.
func (d *Driver) Wait(ctx context.Context, h manager.Handle) (manager.Exit, error) {
	j, err := d.job(h)
	if err != nil {
		return manager.Exit{}, err
	}
	exit, err := d.wait(ctx, j)
	if err != nil || exit.Clean() {
		return exit, err
	}
	out, lerr := d.API.PodLog(ctx, j.name, manager.LogTailLines)
	if lerr != nil {
		if !errors.Is(lerr, ErrNotFound) {
			d.log().Warn("could not read the pod's output", "pod", j.name, "error", lerr)
		}
		return exit, nil
	}
	return exit.WithLogTail(manager.LogTail(out, j.token)), nil
}

func (d *Driver) wait(ctx context.Context, j *job) (manager.Exit, error) {
	timeout := orDefault(d.StartTimeout, defaultStartTimeout)
	poll := orDefault(d.PollInterval, defaultPoll)
	running := false
	for {
		st, err := d.API.GetPod(ctx, j.name)
		switch {
		case ctx.Err() != nil:
			return manager.Exit{}, ctx.Err()
		case errors.Is(err, ErrNotFound):
			return lost("pod %s was deleted", j.name), nil
		case err != nil:
			d.log().Warn("could not read the pod's status", "pod", j.name, "error", err)
		default:
			if exit, done := ended(j.name, st); done {
				return exit, nil
			}
			if st.Phase == "Running" {
				running = true
			}
			if !running {
				if w := waiting(st); w != nil && fatalWaiting[w.Reason] {
					return lost("pod %s cannot start: %s: %s", j.name, w.Reason, w.Message), nil
				}
				if d.now().Sub(j.started) >= timeout {
					return lost("pod %s did not start within %s: %s", j.name, timeout, pending(st)), nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return manager.Exit{}, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func lost(format string, a ...any) manager.Exit {
	return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: fmt.Sprintf(format, a...)}
}

func jobStatus(st PodStatus) *ContainerStatus {
	for i := range st.ContainerStatuses {
		if st.ContainerStatuses[i].Name == container {
			return &st.ContainerStatuses[i]
		}
	}
	return nil
}

func waiting(st PodStatus) *ContainerStateWaiting {
	if cs := jobStatus(st); cs != nil {
		return cs.State.Waiting
	}
	return nil
}

// ended reports how a pod that has finished ended.
func ended(name string, st PodStatus) (manager.Exit, bool) {
	if st.Phase != "Succeeded" && st.Phase != "Failed" {
		return manager.Exit{}, false
	}
	if st.Reason != "" {
		// Evicted, DeadlineExceeded, NodeLost, Shutdown and the like: the
		// cluster ended it, whatever the container said.
		return lost("pod %s: %s: %s", name, st.Reason, st.Message), true
	}
	cs := jobStatus(st)
	if cs == nil || cs.State.Terminated == nil {
		return lost("pod %s %s without a container status", name, strings.ToLower(st.Phase)), true
	}
	t := cs.State.Terminated
	if t.Reason == "OOMKilled" {
		return lost("out of memory in pod %s", name), true
	}
	return manager.Exit{Reason: manager.ExitExited, Code: t.ExitCode, Detail: "pod " + name}, true
}

// pending says why a pod has not started, for the executor failure record.
func pending(st PodStatus) string {
	if w := waiting(st); w != nil && w.Reason != "" {
		return w.Reason + ": " + w.Message
	}
	for _, c := range st.Conditions {
		if c.Type == "PodScheduled" && c.Status == "False" {
			return c.Reason + ": " + c.Message
		}
	}
	return "phase " + st.Phase
}

// Teardown implements manager.Driver: delete the pod, then its secret.
func (d *Driver) Teardown(ctx context.Context, h manager.Handle) error {
	j, err := d.job(h)
	if err != nil {
		return err
	}
	var errs []error
	if err := d.API.DeletePod(ctx, j.name, orDefault(d.StopGrace, defaultStopGrace)); err != nil {
		errs = append(errs, err)
	}
	if err := d.API.DeleteSecret(ctx, j.secret); err != nil {
		errs = append(errs, err)
	}
	if err := d.closeSandbox(ctx, j); err != nil {
		errs = append(errs, err)
	}
	// The slot is freed either way; Reap deletes what is left once the job
	// is no longer live.
	d.mu.Lock()
	delete(d.inUse, h.Slot)
	d.mu.Unlock()
	return errors.Join(errs...)
}

// Reap implements manager.Driver. Pods and secrets labelled with this
// manager that belong to no live job and no slot are deleted.
func (d *Driver) Reap(ctx context.Context, live []manager.JobID) error {
	keepJob := map[string]bool{}
	for _, j := range live {
		keepJob[strconv.FormatInt(j, 10)] = true
	}
	d.mu.Lock()
	keep := map[string]bool{}
	for _, j := range d.inUse {
		keep[j.name], keep[j.secret] = true, true
	}
	// A running self-test's probe is no orphan.
	testing := d.settingUp
	d.mu.Unlock()
	isLive := func(job string) bool { return keepJob[job] || testing && strings.HasPrefix(job, "probe-") }
	var errs []error
	pods, err := d.API.ListPods(ctx, d.selector())
	if err != nil {
		return err
	}
	for _, p := range pods {
		if keep[p.Name] || isLive(p.Labels[LabelJob]) {
			continue
		}
		if err := d.API.DeletePod(ctx, p.Name, orDefault(d.StopGrace, defaultStopGrace)); err != nil {
			errs = append(errs, err)
			continue
		}
		d.log().Info("reaped a pod", "pod", p.Name, "job", p.Labels[LabelJob])
		d.forget(ctx, p.Name)
	}
	if d.sandboxed() {
		if err := d.reapPolicies(ctx, keep, isLive); err != nil {
			errs = append(errs, err)
		}
	}
	secrets, err := d.API.ListSecrets(ctx, d.selector())
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, s := range secrets {
		if keep[s.Name] || isLive(s.Labels[LabelJob]) {
			continue
		}
		if err := d.API.DeleteSecret(ctx, s.Name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
