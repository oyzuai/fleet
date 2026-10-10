// Package container is the container pool driver: one container per job on
// the manager's host, through the local Docker or Podman API, started from a
// pinned executor image that holds the executor and oyzu and nothing
// job-specific.
//
// A job's container gets a fresh workspace volume as its only mount, the
// claim's startup token as its only credential, CPU, memory and process
// limits, no capabilities, no privilege escalation and the engine's default
// seccomp and AppArmor profiles. It never gets the engine's socket and never
// runs a daemon, so container pools do not advertise oyzu.io/docker and take
// no build that needs a RUN step (IMPL-114).
package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// Labels every container and volume carries, so Reap can find what this
// manager created and a person can see which job a container served.
const (
	LabelPool    = "oyzu.io/pool"
	LabelManager = "oyzu.io/manager"
	LabelJob     = "oyzu.io/job"
)

const (
	// WorkDir is where the job's workspace volume is mounted.
	WorkDir = "/work"
	// TokenDir holds the startup token inside the container; the runner
	// reads and deletes it before doing anything else.
	TokenDir  = "/run/oyzu"
	tokenFile = "startup-token"

	defaultUser      = "1000:1000"
	defaultNetwork   = "bridge"
	defaultPidsLimit = 4096
	defaultStopGrace = 30 * time.Second
	// pullRetry spaces out attempts to pull an image that failed.
	pullRetry = time.Minute
	// pullTimeout bounds one pull.
	pullTimeout = 30 * time.Minute
)

// Driver runs each job in a fresh container on this host. Slots are ready
// once the executor image is present, so a job is never claimed while the
// image is still being pulled.
type Driver struct {
	Engine Engine
	// Image is the pinned executor image, by digest or exact tag.
	Image string
	// Command starts the runner in the image; the job's flags follow it.
	Command []string
	// Server is the runs URL the runner calls.
	Server string
	// Pool and Manager name this manager; every container and volume is
	// labelled with them.
	Pool    string
	Manager int64
	// Slots is how many jobs run at once; at least 1.
	Slots int
	// CPUs and MemoryBytes cap each job's container; 0 leaves it uncapped.
	CPUs        float64
	MemoryBytes int64
	// PidsLimit caps each container's processes; 4096 when 0.
	PidsLimit int64
	// Network is the network containers join; bridge when empty. The host
	// network is refused.
	Network string
	// User is the uid:gid jobs run as; 1000:1000 when empty. Root is
	// refused.
	User string
	// StopGrace is how long a runner may report after it is asked to stop,
	// before it is killed; 30s when 0.
	StopGrace time.Duration
	Log       *slog.Logger
	Now       func() time.Time

	mu        sync.Mutex
	inUse     map[manager.SlotID]*job
	pulled    bool
	pulling   bool
	lastPull  time.Time
	pullError error
}

// job is one job's container.
type job struct {
	name   string
	volume string
	id     string
}

var _ manager.Driver = (*Driver)(nil)

// Check refuses configurations that would weaken a job's isolation.
func (d *Driver) Check() error {
	switch {
	case d.Engine == nil || d.Image == "" || len(d.Command) == 0 || d.Server == "":
		return errors.New("container: Engine, Image, Command and Server are required")
	case d.Network == "host" || strings.HasPrefix(d.Network, "container:"):
		return fmt.Errorf("container: network %q shares another namespace; jobs need their own", d.Network)
	}
	uid, _, _ := strings.Cut(d.user(), ":")
	if n, err := strconv.Atoi(uid); err != nil || n == 0 {
		return fmt.Errorf("container: User %q must be a numeric uid:gid other than root", d.user())
	}
	return nil
}

func (d *Driver) slots() int { return max(1, d.Slots) }

func (d *Driver) user() string {
	if d.User == "" {
		return defaultUser
	}
	return d.User
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

func (d *Driver) managerLabel() string { return strconv.FormatInt(d.Manager, 10) }

// Facts implements manager.Driver from the engine host, bounded by the
// per-job limits.
func (d *Driver) Facts(ctx context.Context) (manager.Facts, error) {
	info, err := d.Engine.Info(ctx)
	if err != nil {
		return nil, err
	}
	f := manager.Facts{
		manager.FactOS:        info.OSType,
		manager.FactIsolation: "container",
		manager.FactDocker:    "false",
	}
	switch info.Architecture {
	case "x86_64", "amd64":
		f[manager.FactArch] = "amd64"
	case "aarch64", "arm64":
		f[manager.FactArch] = "arm64"
	default:
		f[manager.FactArch] = info.Architecture
	}
	cpus := float64(info.NCPU)
	if d.CPUs > 0 && d.CPUs < cpus {
		cpus = d.CPUs
	}
	f[manager.FactCPU] = strconv.FormatFloat(cpus, 'f', -1, 64)
	mem := info.MemTotal
	if d.MemoryBytes > 0 && (mem == 0 || d.MemoryBytes < mem) {
		mem = d.MemoryBytes
	}
	if mem > 0 {
		f[manager.FactMemory] = strconv.FormatInt(mem>>20, 10) + "Mi"
	}
	return f, nil
}

// Capacity implements manager.Driver. Until the image is present no
// slot is ready and all of them count as provisioning; the first call
// starts the pull.
func (d *Driver) Capacity(context.Context) (manager.Capacity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := manager.Capacity{Max: d.slots(), Running: len(d.inUse)}
	if !d.pulled {
		if !d.pulling && (d.lastPull.IsZero() || d.now().Sub(d.lastPull) >= pullRetry) {
			d.pulling, d.lastPull = true, d.now()
			go d.pull()
		}
		if d.pulling {
			c.Provisioning = c.Max - c.Running
		}
		return c, d.pullError
	}
	for i := range d.slots() {
		id := manager.SlotID(strconv.Itoa(i))
		if _, busy := d.inUse[id]; !busy {
			c.Ready = append(c.Ready, id)
		}
	}
	return c, nil
}

// pull makes the executor image present.
func (d *Driver) pull() {
	ctx, cancel := context.WithTimeout(context.Background(), pullTimeout)
	defer cancel()
	present, err := d.Engine.ImagePresent(ctx, d.Image)
	if err == nil && !present {
		d.log().Info("pulling the executor image", "image", d.Image)
		err = d.Engine.PullImage(ctx, d.Image)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pulling = false
	if err != nil {
		d.pullError = fmt.Errorf("pull %s: %w", d.Image, err)
		d.log().Warn("the executor image is not available; no job will be claimed", "image", d.Image, "error", err)
		return
	}
	d.pulled, d.pullError = true, nil
}

// Provision implements manager.Driver. Container slots need nothing
// but the image, which Capacity already fetches.
func (d *Driver) Provision(context.Context, int) error { return nil }

// Start implements manager.Driver: a fresh workspace volume, then the
// container, then the startup token copied in, then start.
func (d *Driver) Start(ctx context.Context, slot manager.SlotID, c runnerclient.Claim) (manager.Handle, error) {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("oyzu-%d-job-%d-%d-%s", d.Manager, c.JobID, c.Attempt, hex.EncodeToString(suffix))
	j := &job{name: name, volume: name + "-work"}
	d.mu.Lock()
	if !d.pulled {
		d.mu.Unlock()
		return manager.Handle{}, errors.New("the executor image is not present yet")
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
	labels := map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelJob: strconv.FormatInt(c.JobID, 10)}
	if err := d.Engine.CreateVolume(ctx, j.volume, labels); err != nil {
		return h, fmt.Errorf("create the workspace volume: %w", err)
	}
	network := d.Network
	if network == "" {
		network = defaultNetwork
	}
	pids := d.PidsLimit
	if pids <= 0 {
		pids = defaultPidsLimit
	}
	cmd := append(append([]string{}, d.Command...),
		"--server", d.Server, "--startup-token-file", TokenDir+"/"+tokenFile, "--work-dir", WorkDir)
	id, err := d.Engine.CreateContainer(ctx, name, Spec{
		Image: d.Image, Cmd: cmd, User: d.user(), Labels: labels, Volume: j.volume, WorkDir: WorkDir,
		NanoCPUs: int64(d.CPUs * 1e9), MemoryBytes: d.MemoryBytes, PidsLimit: pids, Network: network,
	})
	if err != nil {
		return h, fmt.Errorf("create the container: %w", err)
	}
	d.mu.Lock()
	j.id = id
	d.mu.Unlock()
	archive, err := tokenArchive(d.user(), c.StartupToken)
	if err != nil {
		return h, err
	}
	if err := d.Engine.CopyFiles(ctx, id, "/", archive); err != nil {
		return h, fmt.Errorf("copy the startup token in: %w", err)
	}
	if err := d.Engine.StartContainer(ctx, id); err != nil {
		return h, fmt.Errorf("start the container: %w", err)
	}
	return h, nil
}

// tokenArchive is a tar holding TokenDir, owned by the job's user and
// closed to anyone else, with the startup token in it.
func tokenArchive(user, token string) ([]byte, error) {
	uidS, gidS, _ := strings.Cut(user, ":")
	uid, _ := strconv.Atoi(uidS)
	gid, err := strconv.Atoi(gidS)
	if err != nil {
		gid = uid
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	dir := strings.TrimPrefix(TokenDir, "/")
	now := time.Now()
	for _, h := range []*tar.Header{
		{Name: "run/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: now},
		{Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: uid, Gid: gid, ModTime: now},
		{Name: dir + "/" + tokenFile, Typeflag: tar.TypeReg, Mode: 0o400, Uid: uid, Gid: gid, Size: int64(len(token)), ModTime: now},
	} {
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
	}
	if _, err := tw.Write([]byte(token)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *Driver) job(h manager.Handle) (*job, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	j, ok := d.inUse[h.Slot]
	if !ok || j.name != h.Ref {
		return nil, fmt.Errorf("no container %s in slot %s", h.Ref, h.Slot)
	}
	return j, nil
}

// Wait implements manager.Driver. A container the kernel killed for
// memory was lost, not exited, so its job is handed back if the runner had
// not started.
func (d *Driver) Wait(ctx context.Context, h manager.Handle) (manager.Exit, error) {
	j, err := d.job(h)
	if err != nil {
		return manager.Exit{}, err
	}
	code, err := d.Engine.WaitContainer(ctx, j.id)
	if err != nil {
		if ctx.Err() != nil {
			return manager.Exit{}, ctx.Err()
		}
		return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: "wait: " + err.Error()}, nil
	}
	st, err := d.Engine.InspectContainer(ctx, j.id)
	switch {
	case err != nil:
		return manager.Exit{Reason: manager.ExitExited, Code: code, Detail: "container " + j.name}, nil
	case st.OOMKilled:
		return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: "out of memory in container " + j.name}, nil
	case st.Error != "":
		return manager.Exit{Reason: manager.ExitLost, Code: -1, Detail: st.Error}, nil
	}
	return manager.Exit{Reason: manager.ExitExited, Code: code, Detail: "container " + j.name}, nil
}

// Teardown implements manager.Driver: stop, remove the container, then
// its workspace volume.
func (d *Driver) Teardown(ctx context.Context, h manager.Handle) error {
	j, err := d.job(h)
	if err != nil {
		return err
	}
	grace := d.StopGrace
	if grace <= 0 {
		grace = defaultStopGrace
	}
	var errs []error
	if j.id != "" {
		if err := d.Engine.StopContainer(ctx, j.id, grace); err != nil {
			errs = append(errs, err)
		}
		if err := d.Engine.RemoveContainer(ctx, j.id); err != nil {
			errs = append(errs, err)
		}
	}
	if err := d.Engine.RemoveVolume(ctx, j.volume); err != nil {
		errs = append(errs, err)
	}
	d.mu.Lock()
	delete(d.inUse, h.Slot)
	d.mu.Unlock()
	return errors.Join(errs...)
}

// Reap implements manager.Driver. Containers and volumes labelled with
// this manager that belong to no live job and no slot are removed, running
// or not: unlike a process, a container is addressed by an id that is
// never reused, so a crashed predecessor's runner can be stopped safely.
func (d *Driver) Reap(ctx context.Context, live []manager.JobID) error {
	keepJob := map[string]bool{}
	for _, j := range live {
		keepJob[strconv.FormatInt(j, 10)] = true
	}
	d.mu.Lock()
	keep := map[string]bool{}
	for _, j := range d.inUse {
		keep[j.name], keep[j.volume] = true, true
	}
	d.mu.Unlock()
	mine := map[string]string{LabelManager: d.managerLabel()}
	var errs []error
	containers, err := d.Engine.ListContainers(ctx, mine)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if keep[c.Name] || keepJob[c.Labels[LabelJob]] {
			continue
		}
		if err := d.Engine.RemoveContainer(ctx, c.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		d.log().Info("reaped a container", "container", c.Name, "job", c.Labels[LabelJob])
	}
	volumes, err := d.Engine.ListVolumes(ctx, mine)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, v := range volumes {
		if keep[v.Name] || keepJob[v.Labels[LabelJob]] {
			continue
		}
		if err := d.Engine.RemoveVolume(ctx, v.Name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
