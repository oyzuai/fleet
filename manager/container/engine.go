package container

import (
	"context"
	"time"
)

// Engine is the subset of the Docker Engine API the driver uses. Podman
// serves the same API, so one implementation covers both.
type Engine interface {
	Info(ctx context.Context) (Info, error)
	// ImagePresent reports whether ref is in the local image store.
	ImagePresent(ctx context.Context, ref string) (bool, error)
	PullImage(ctx context.Context, ref string) error
	CreateVolume(ctx context.Context, name string, labels map[string]string) error
	// RemoveVolume removes a volume; one that is already gone succeeds.
	RemoveVolume(ctx context.Context, name string) error
	// ListVolumes returns the volumes carrying every label in labels.
	ListVolumes(ctx context.Context, labels map[string]string) ([]Volume, error)
	// CreateContainer creates a container named name and returns its id.
	CreateContainer(ctx context.Context, name string, spec Spec) (string, error)
	// CopyFiles extracts a tar archive into the container's filesystem at
	// path before it starts.
	CopyFiles(ctx context.Context, id, path string, tar []byte) error
	StartContainer(ctx context.Context, id string) error
	// WaitContainer blocks until the container stops and returns its exit
	// code.
	WaitContainer(ctx context.Context, id string) (int, error)
	InspectContainer(ctx context.Context, id string) (State, error)
	// ContainerLogs returns the last lines of the container's stdout and
	// stderr, interleaved.
	ContainerLogs(ctx context.Context, id string, lines int) ([]byte, error)
	// StopContainer asks the container to stop and kills it after grace;
	// one that is not running or is gone succeeds.
	StopContainer(ctx context.Context, id string, grace time.Duration) error
	// RemoveContainer force-removes a container and its anonymous volumes;
	// one that is already gone succeeds.
	RemoveContainer(ctx context.Context, id string) error
	// ListContainers returns the containers, in any state, carrying every
	// label in labels.
	ListContainers(ctx context.Context, labels map[string]string) ([]Summary, error)
	// CreateNetwork creates a bridge network and returns it with its subnet.
	CreateNetwork(ctx context.Context, name string, spec NetworkSpec) (Network, error)
	// RemoveNetwork removes a network; one that is already gone succeeds.
	RemoveNetwork(ctx context.Context, name string) error
	// ListNetworks returns the networks carrying every label in labels.
	ListNetworks(ctx context.Context, labels map[string]string) ([]Network, error)
	// ConnectNetwork attaches a container to a network and returns the
	// address it has there.
	ConnectNetwork(ctx context.Context, network, container string) (string, error)
	// DisconnectNetwork detaches a container from a network; one that is not
	// attached, or is gone, succeeds.
	DisconnectNetwork(ctx context.Context, network, container string) error
	// PublishedPort returns the port on the host's loopback address that
	// the container's port was published as (Spec.Publish).
	PublishedPort(ctx context.Context, id string, port int) (int, error)
}

// Info is the engine host's platform.
type Info struct {
	ID            string
	ServerVersion string
	OSType        string
	// Architecture is the kernel's: x86_64, aarch64 or arm64.
	Architecture string
	NCPU         int
	MemTotal     int64
}

// Spec is the container the driver creates for one job.
type Spec struct {
	Image string
	Cmd   []string
	// User is uid:gid; jobs never run as root.
	User   string
	Labels map[string]string
	// Volume is mounted at WorkDir; it is the only mount.
	Volume  string
	WorkDir string
	// NanoCPUs and MemoryBytes cap the container; 0 means no cap.
	NanoCPUs    int64
	MemoryBytes int64
	PidsLimit   int64
	// Network is the network the container joins, never "host".
	Network string
	// Env is set in the container besides HOME.
	Env []string
	// DNS lists the nameservers the container uses instead of the engine's.
	DNS []string
	// Sysctls are namespaced kernel settings.
	Sysctls map[string]string
	// Publish lists container ports published on the host's loopback
	// address only, on a port the engine picks.
	Publish []int
	// ReadOnly makes the root filesystem read-only.
	ReadOnly bool
}

// NetworkSpec is a network the driver creates.
type NetworkSpec struct {
	Labels map[string]string
	// Internal gives the network no route out: its containers reach each
	// other and nothing else.
	Internal bool
}

// Network is a network in a listing.
type Network struct {
	ID     string
	Name   string
	Labels map[string]string
	// Subnet is the network's first address range, in CIDR form.
	Subnet string
}

// Volume is a named volume.
type Volume struct {
	Name   string
	Labels map[string]string
}

// Summary is a container in a listing.
type Summary struct {
	ID     string
	Name   string
	Labels map[string]string
	State  string
}

// State is a container's state after it stopped.
type State struct {
	Running   bool
	ExitCode  int
	OOMKilled bool
	Error     string
}
