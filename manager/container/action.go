package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path"
	"slices"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// ActionRuntime runs admitted source-free commands in a private child
// container. The trusted executor owns the engine connection; code never does.
type ActionRuntime struct {
	Engine     ActionEngine
	HelperPath string
}

func (r *ActionRuntime) Ready(ctx context.Context) error {
	if r == nil || r.Engine == nil {
		return errors.New("missing action container engine")
	}
	if _, err := r.helper(); err != nil {
		return err
	}
	return r.Engine.ActionReady(ctx)
}

func actionError(code, message string) runnerclient.ActionCompletion {
	return runnerclient.ActionCompletion{ErrorCode: code, Message: message}
}

func (r *ActionRuntime) RunAction(ctx context.Context, owner runnerclient.ActionOwner, a runnerclient.ActionAssignment, in runnerclient.ActionInputs) (result runnerclient.ActionCompletion) {
	if err := owner.Validate(); err != nil {
		return actionError("FAILED_PRECONDITION", err.Error())
	}
	if err := a.Validate(); err != nil {
		return actionError("INVALID_ARGUMENT", err.Error())
	}
	if err := in.Validate(); err != nil {
		return actionError("INVALID_ARGUMENT", err.Error())
	}
	archive, err := actionInputArchive(a, in)
	if err != nil {
		return actionError("INVALID_ARGUMENT", err.Error())
	}
	if err := r.Ready(ctx); err != nil {
		return actionError("FAILED_PRECONDITION", "Required isolated action runtime is unavailable.")
	}
	memory, cpus, _, ok := a.HostResources()
	capacity, err := r.Engine.Info(ctx)
	requiredCPUs := cpus / 1000000000
	if cpus%1000000000 != 0 {
		requiredCPUs++
	}
	if err != nil || !ok || capacity.MemTotal < memory || int64(capacity.NCPU) < requiredCPUs {
		return actionError("RESOURCE_EXHAUSTED", "Host cannot accommodate the complete action reservation.")
	}
	present, err := r.Engine.ImagePresent(ctx, a.Image)
	if err != nil || !present {
		return actionError("FAILED_PRECONDITION", "Admitted immutable image is not present on the engine.")
	}
	// Images are provisioned by the operator; an action never pulls an image.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return actionError("INTERNAL", "Could not allocate private action identity.")
	}
	name := "oyzu-action-" + hex.EncodeToString(nonce[:])
	record := actionRecord{Owner: owner, Name: name}
	record.Resources = record.planned()
	if err = writeActionRecord(record); err != nil {
		return actionError("FAILED_PRECONDITION", "Could not persist trusted action recovery identity.")
	}
	labels := record.resourceLabels("user")
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		if err := r.CleanupAction(cleanup, owner); err != nil {
			result.Files = nil
			result.Directories = nil
			result.Symlinks = nil
			result.WorkspaceNodes = nil
			result.TerminationConfirmed = false
			result.ErrorCode = "INTERNAL"
			result.Message = "Action cleanup is incomplete; recovery state retained."
		}
	}()
	if err := r.Engine.CreateActionVolume(ctx, name, record.resourceLabels("workspace"), a.WorkspaceBytes, a.WorkspaceInodes); err != nil {
		return actionError("INTERNAL", "Could not create private action volume.")
	}
	bootstrap := name + "-bootstrap"
	if err = r.Engine.CreateVolume(ctx, bootstrap, record.resourceLabels("bootstrap")); err != nil {
		return actionError("INTERNAL", "Could not create helper bootstrap volume.")
	}
	if err = r.Engine.VerifyActionVolume(ctx, bootstrap, record.resourceLabels("bootstrap"), nil); err != nil {
		return actionError("FAILED_PRECONDITION", "Helper bootstrap ownership differs.")
	}
	prepSpec := holderSpec(a.Image, bootstrap, "", record.resourceLabels("prepare"))
	prepSpec.VolumePath = "/bootstrap"
	prepSpec.VolumeReadOnly = false
	prep, err := r.Engine.CreateContainer(ctx, name+"-prepare", prepSpec)
	if err != nil {
		return actionError("INTERNAL", "Could not create stopped preparation container.")
	}
	if err = r.Engine.VerifyActionContainer(ctx, prep, prepSpec); err != nil {
		return actionError("FAILED_PRECONDITION", "Unsafe preparation allocation.")
	}
	helper, err := r.helper()
	if err != nil {
		return actionError("FAILED_PRECONDITION", "Installed static helper is unavailable.")
	}
	bootstrapTar, err := helperArchive(helper)
	if err != nil {
		return actionError("INTERNAL", "Could not prepare trusted helper.")
	}
	if err = r.Engine.CopyFiles(ctx, prep, "/bootstrap", bootstrapTar); err != nil {
		return actionError("INTERNAL", "Could not copy trusted helper.")
	}
	if err = r.Engine.RemoveContainer(ctx, prep); err != nil {
		return actionError("INTERNAL", "Could not remove preparation container.")
	}
	holderSpec := holderSpec(a.Image, name, bootstrap, record.resourceLabels("holder"))
	holder, err := r.Engine.CreateContainer(ctx, name+"-holder", holderSpec)
	if err != nil {
		return actionError("INTERNAL", "Could not create workspace holder.")
	}
	if err = r.Engine.VerifyActionContainer(ctx, holder, holderSpec); err != nil {
		return actionError("FAILED_PRECONDITION", "Unsafe holder allocation.")
	}
	if err = r.Engine.StartContainer(ctx, holder); err != nil {
		return actionError("INTERNAL", "Could not start workspace holder.")
	}
	holderAlive := func(check context.Context) bool {
		state, e := r.Engine.InspectContainer(check, holder)
		return e == nil && state.Running && !state.OOMKilled && state.Error == ""
	}
	if !holderAlive(ctx) {
		return actionError("INTERNAL", "Workspace holder is unavailable.")
	}
	env := make([]string, 0, len(a.Environment))
	for key, value := range a.Environment {
		env = append(env, key+"="+value)
	}
	slices.Sort(env)
	spec := Spec{Image: a.Image, Entrypoint: []string{a.Arguments[0]}, Cmd: append([]string{}, a.Arguments[1:]...), User: "1000:1000", Labels: labels,
		Volume: name, VolumePath: "/work", VolumeNoCopy: true, WorkDir: path.Join("/work", a.WorkingDirectory), Network: "none", ReadOnly: true,
		Env: env, NanoCPUs: a.NanoCPUs, MemoryBytes: a.MemoryBytes, PidsLimit: a.PidsLimit}
	id, err := r.Engine.CreateContainer(ctx, name, spec)
	if err != nil {
		return actionError("INTERNAL", "Could not create isolated action container.")
	}
	if err = r.Engine.VerifyActionContainer(ctx, id, spec); err != nil {
		return actionError("FAILED_PRECONDITION", "Engine did not provide the required action isolation.")
	}
	if err = r.Engine.CopyFiles(ctx, id, "/work", archive); err != nil {
		return actionError("INTERNAL", "Could not materialize action inputs.")
	}
	if !holderAlive(ctx) {
		return actionError("INTERNAL", "Workspace holder was lost before user start.")
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSeconds)*time.Second)
	defer cancel()
	holderLost := make(chan struct{})
	watchDone := make(chan struct{})
	defer func() { cancel(); <-watchDone }()
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				alive := holderAlive(runCtx)
				if runCtx.Err() != nil {
					return
				}
				if !alive {
					close(holderLost)
					cancel()
					return
				}
			}
		}
	}()
	// Start errors may be ambiguous: always stop and inspect after attempting it.
	startErr := r.Engine.StartContainer(runCtx, id)
	waitErr := startErr
	if startErr == nil {
		_, waitErr = r.Engine.WaitContainer(runCtx, id)
	}
	observe, done := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer done()
	if waitErr != nil || runCtx.Err() != nil {
		if err = r.Engine.StopContainer(observe, id, 5*time.Second); err != nil {
			return actionError("INTERNAL", "Action stop failed; termination is unconfirmed.")
		}
	}
	state, err := r.Engine.InspectContainer(observe, id)
	if err != nil || state.Running {
		return actionError("INTERNAL", "Action termination could not be confirmed.")
	}
	result.TerminationConfirmed = true
	select {
	case <-holderLost:
		result.ErrorCode = "INTERNAL"
		result.Message = "Workspace holder was lost."
		return result
	default:
	}
	if !holderAlive(observe) {
		result.ErrorCode = "INTERNAL"
		result.Message = "Workspace holder was lost."
		return result
	}
	if ctx.Err() != nil {
		result.ErrorCode = "CANCELLED"
		result.Message = "Action stopped."
		return result
	}
	if runCtx.Err() != nil {
		result.ErrorCode = "DEADLINE_EXCEEDED"
		result.Message = "Action exceeded its admitted timeout."
		return result
	}
	if waitErr != nil || state.Error != "" || state.OOMKilled {
		result.ErrorCode = "INTERNAL"
		result.Message = "Action runtime failed."
		return result
	}
	result.ExitCode = &state.ExitCode
	result.Stdout, result.Stderr, err = r.Engine.ContainerOutput(ctx, id)
	if err != nil {
		result.ErrorCode = "RESOURCE_EXHAUSTED"
		result.Message = "Action logs unavailable or over limit."
		return result
	}
	// Read only the private work volume after termination, without extracting
	// untrusted archives onto the executor's host filesystem.
	archive, err = r.Engine.ReadContainerArchive(ctx, id, "/work")
	if err != nil {
		result.ErrorCode = "RESOURCE_EXHAUSTED"
		result.Message = "Action outputs unavailable or over limit."
		return result
	}
	if !holderAlive(ctx) {
		result.ErrorCode = "INTERNAL"
		result.Message = "Workspace holder was lost during collection."
		return result
	}
	snapshot, e := actionSnapshot(archive, a)
	err = e
	if err != nil {
		result.ErrorCode = "FAILED_PRECONDITION"
		result.Message = "Unsafe or oversized action output."
		result.Files = nil
		result.Directories = nil
	} else {
		if !holderAlive(ctx) {
			result.ErrorCode = "INTERNAL"
			result.Message = "Workspace holder was lost before acceptance."
			return result
		}
		result.Files = snapshot.Files
		result.Directories = snapshot.Directories
		result.Symlinks = snapshot.Symlinks
		result.WorkspaceNodes = snapshot.WorkspaceNodes
	}
	return result
}
