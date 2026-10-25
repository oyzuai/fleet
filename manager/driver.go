package manager

import (
	"context"
	"strconv"

	"github.com/oyzuai/fleet/runnerclient"
)

// Finalizer releases shared driver resources after all claimed jobs drain.
// The manager supplies a bounded context independent of its cancelled loop.
type Finalizer interface{ Finalize(context.Context) error }

// Driver provisions, starts, watches and cleans up executors in one kind of
// environment: local processes, containers, Kubernetes pods or cloud VMs. A
// pool has exactly one driver. The manager loop owns claiming and decides
// when to call it; a driver never talks to runs and never sees the manager's
// key. Every executor a driver creates carries the pool, manager and job it
// belongs to, so Reap can find what a crashed predecessor left behind.
//
// The manager calls Capacity and Provision from one goroutine. Start, Wait
// and Teardown are called from one goroutine per job, concurrently with the
// others; a slot is never passed to Start again until its Start returned.
// Every call gets a context that ends: Start's ends at the claim's startup
// expiry or the drain timeout, Teardown's after the manager's teardown
// timeout, so a driver must pass it to every call to its engine.
type Driver interface {
	// Facts reports the discovered oyzu.io/* labels and limits for this pool.
	Facts(ctx context.Context) (Facts, error)
	// Capacity reports running, ready, provisioning and maximum slots.
	Capacity(ctx context.Context) (Capacity, error)
	// Provision prepares n more slots, up to the maximum; it returns at once.
	// Slots appear in Capacity.Ready as they become ready.
	Provision(ctx context.Context, n int) error
	// Start runs a claimed job in a ready slot, handing the executor the
	// claim's startup token and nothing else from the manager. The slot is
	// no longer ready once Start returns, whether or not it succeeded. On
	// failure it still returns a Handle with Ref set if it created anything,
	// so Teardown can remove it.
	Start(ctx context.Context, slot SlotID, c runnerclient.Claim) (Handle, error)
	// Wait blocks until the job's executor exits, with the reason. A done
	// ctx stops the waiting, not the executor; Teardown stops it.
	Wait(ctx context.Context, h Handle) (Exit, error)
	// Teardown destroys the executor and its workspace, stopping it first if
	// it is still running. It is called once for every Handle with a Ref,
	// whatever happened.
	Teardown(ctx context.Context, h Handle) error
	// Reap removes anything carrying this manager's ID with no live job.
	Reap(ctx context.Context, live []JobID) error
}

// FactsChanger is implemented by a driver whose facts can change while it
// runs, such as when its egress self-test finishes. The manager reads the
// facts again as soon as it reports true, and the report that follows tells
// runs.
type FactsChanger interface {
	FactsChanged() bool
}

// JobID is a job's id at runs.
type JobID = int64

// SlotID names a slot within a driver: a process slot number, a warm
// container, pod or instance.
type SlotID string

// Handle is a started executor.
type Handle struct {
	Slot    SlotID
	Job     JobID
	Attempt int
	// Ref is the driver's own name for the executor, such as a process
	// directory, pod name or instance ID.
	Ref string
}

// Capacity is a driver's slots at one moment.
type Capacity struct {
	// Max is the most executors the pool may have at once, in any state.
	Max int
	// Running is how many slots hold a started job.
	Running int
	// Ready lists slots a job can start in immediately.
	Ready []SlotID
	// Provisioning is how many slots are being prepared.
	Provisioning int
}

// Room is how many more slots could be provisioned.
func (c Capacity) Room() int {
	return max(0, c.Max-c.Running-len(c.Ready)-c.Provisioning)
}

// Facts are a pool's discovered oyzu.io/* labels. Pool administrators
// cannot set these keys; only the manager reports them.
type Facts map[string]string

// Discovered fact keys.
const (
	FactOS        = "oyzu.io/os"
	FactArch      = "oyzu.io/arch"
	FactCPU       = "oyzu.io/cpu"
	FactMemory    = "oyzu.io/memory"
	FactDisk      = "oyzu.io/disk"
	FactIsolation = "oyzu.io/isolation"
	FactDocker    = "oyzu.io/docker"
	FactNetwork   = "oyzu.io/network"
	// FactRenovate says Renovate is installed beside oyzu, so the pool can
	// run renovate jobs.
	FactRenovate = "oyzu.io/renovate"
	// FactEgress says how the pool's network egress is controlled by the
	// manager's gateway: EgressEnforced, EgressReport or EgressOpen.
	FactEgress = "oyzu.io/egress"
	// FactUntrusted is UntrustedAccepted when the pool may run work from
	// untrusted triggers, such as pull requests. A manager reports it only
	// when its isolation is not process, its egress is enforced and its
	// startup egress self-test passed; otherwise it reports nothing.
	FactUntrusted = "oyzu.io/untrusted"
)

// Values of FactEgress and FactUntrusted.
const (
	EgressEnforced    = "enforced"
	EgressReport      = "report"
	EgressOpen        = "open"
	UntrustedAccepted = "accepted"
)

// ExitReason says how an executor ended.
type ExitReason string

const (
	// ExitExited means the executor program ended on its own, with Code.
	ExitExited ExitReason = "exited"
	// ExitLost means the environment ended it: killed, out of memory,
	// evicted, or its instance was lost.
	ExitLost ExitReason = "lost"
)

// Exit is how an executor ended.
type Exit struct {
	Reason ExitReason
	// Code is the executor program's exit code when Reason is ExitExited.
	Code int
	// Detail says more, for logs and the executor failure record.
	Detail string
}

// Clean reports whether the executor program exited successfully.
func (e Exit) Clean() bool { return e.Reason == ExitExited && e.Code == 0 }

func (e Exit) String() string {
	s := string(e.Reason)
	if e.Reason == ExitExited {
		s = "exit code " + strconv.Itoa(e.Code)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}
