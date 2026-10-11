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
}

// Info is the engine host's platform.
type Info struct {
	OSType string
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
