package executor

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// ActionDriver is injected only into a trusted host executor. Ready must refuse
// engines that cannot provide the required Linux isolation. No host fallback.
type ActionDriver interface {
	Ready(context.Context) error
	RunAction(context.Context, runnerclient.ActionOwner, runnerclient.ActionAssignment, runnerclient.ActionInputs) runnerclient.ActionCompletion
}

func runAction(ctx context.Context, cfg Config, st runnerclient.Started) error {
	work, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	every := time.Duration(st.HeartbeatSeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); heartbeat(work, cfg.Client, st.JobToken, every, cancel, cfg.Log, st.Expires) }()
	result := runnerclient.ActionCompletion{ErrorCode: "FAILED_PRECONDITION", Message: "No isolated action runtime is configured."}
	if cfg.ActionDriver != nil && st.Job.Action != nil {
		if err := st.Job.Action.Validate(); err != nil {
			result.ErrorCode, result.Message = "INVALID_ARGUMENT", err.Error()
		} else if in, err := cfg.Client.ActionInputs(work, st.JobToken); err != nil {
			result.ErrorCode, result.Message = "UNAVAILABLE", "Action input transfer failed."
		} else {
			owner := runnerclient.ActionOwner{ManagerID: cfg.ManagerID, JobID: st.Job.ID, Attempt: st.Job.Attempt, Directory: cfg.JobDir}
			result = cfg.ActionDriver.RunAction(work, owner, *st.Job.Action, in)
		}
	}
	// Keep lease watching through output transfer. The server rechecks the live
	// attempt atomically; a lost assignment never receives a completion request.
	defer wg.Wait()
	defer cancel(nil)
	if errors.Is(context.Cause(work), errLost) {
		return errLost
	}
	if work.Err() != nil {
		result.Files, result.Directories = nil, nil
		if result.TerminationConfirmed {
			result.ErrorCode, result.Message = "CANCELLED", "Action stopped."
		} else {
			result.ErrorCode, result.Message = "INTERNAL", "Action termination was not confirmed."
		}
	}
	finish, done := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer done()
	if err := cfg.Client.ActionFinish(finish, st.JobToken, result); err != nil {
		return err
	}
	return nil
}
