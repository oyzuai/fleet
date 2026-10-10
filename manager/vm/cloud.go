// Package vm is the cloud VM pool driver: one fresh virtual machine per job,
// a warm pool of booted machines kept ready, and a machine destroyed after
// exactly one job. Everything that differs between clouds sits behind Cloud;
// the warm pool, the startup-token handover, teardown, reaping and spot loss
// live here once, so every cloud behaves the same.
package vm

import (
	"context"
	"time"

	"github.com/oyzuai/fleet/manager"
)

// Tags every instance carries, so Reap can find what this manager created
// and a person can see which job a machine served.
const (
	TagPool    = "oyzu.io/pool"
	TagManager = "oyzu.io/manager"
	TagJob     = "oyzu.io/job"
)

// Cloud is the only provider-specific code in a VM pool. An adapter calls
// its provider's API with the manager's own infrastructure identity, which
// never reaches an instance.
type Cloud interface {
	// Create boots one instance from spec with the given tags and returns
	// its id once the provider has accepted the request.
	Create(ctx context.Context, spec Spec, tags map[string]string) (string, error)
	// Describe reports the instances with these ids. An id the provider no
	// longer knows is left out.
	Describe(ctx context.Context, ids []string) (map[string]Instance, error)
	// List returns every instance tagged with this manager, in any state
	// but gone.
	List(ctx context.Context, manager string) ([]Instance, error)
	// Tag adds tags to an instance.
	Tag(ctx context.Context, id string, tags map[string]string) error
	// Destroy terminates an instance and deletes its disks. Destroying one
	// that is already gone succeeds.
	Destroy(ctx context.Context, id string) error
	// VerifyIdentity checks a provider-signed instance identity proof and
	// returns the instance it proves. It must reject proofs from another
	// account, project or subscription, and from another image.
	VerifyIdentity(ctx context.Context, proof Proof) (Identity, error)
	// Facts reports the oyzu.io/* facts of spec's machine shape from the
	// provider's catalogue: cpu, memory, architecture and operating system.
	Facts(ctx context.Context, spec Spec) (manager.Facts, error)
}

// Spec is what a pool's instances are made from.
type Spec struct {
	// Image is the baked executor image: an AMI, a Compute Engine image or
	// an Azure Compute Gallery image version.
	Image string
	// Shape is the machine type, such as c7i.2xlarge.
	Shape string
	// Spot asks for preemptible capacity; a reclaimed instance's job is
	// handed back without using an attempt.
	Spot bool
	// Network names where instances go: a subnet, plus a security group,
	// firewall tag or network security group, in the adapter's own terms.
	Network string
	// Identity is the instance's own narrow role, service account or
	// managed identity, never the manager's. Empty means none.
	Identity string
	// DiskGiB is the root disk size; the image's when 0.
	DiskGiB int
}

// State is an instance's lifecycle state, mapped from the provider's.
type State string

const (
	StatePending  State = "pending"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateGone     State = "gone"
)

// Instance is one machine as the provider reports it.
type Instance struct {
	ID    string
	State State
	// Address is the private address the instance's agent calls from.
	Address  string
	Launched time.Time
	Tags     map[string]string
	// Preempted is set when the provider reclaimed spot capacity.
	Preempted bool
	// Detail is the provider's reason for the state, for logs.
	Detail string
}

// Proof is what an instance's agent presents to prove which instance it is:
// the provider-signed identity document and its signature, exactly as the
// instance metadata service returned them. On AWS that is the identity
// document and its signature; on Google Cloud and Azure the document is a
// short-lived signed token and Signature is empty.
type Proof struct {
	Document  []byte `json:"document"`
	Signature []byte `json:"signature"`
}

// Identity is what a verified proof establishes.
type Identity struct {
	InstanceID string
	Image      string
}
