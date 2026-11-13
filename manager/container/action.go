package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// ActionRuntime runs admitted source-free commands in a private child
// container. The trusted executor owns the engine connection; code never does.
type ActionRuntime struct{ Engine ActionEngine }

func (r *ActionRuntime) Ready(ctx context.Context) error {
	if r == nil || r.Engine == nil {
		return errors.New("missing action container engine")
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
	if err = writeActionRecord(record); err != nil {
		return actionError("FAILED_PRECONDITION", "Could not persist trusted action recovery identity.")
	}
	labels := record.labels()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		if err := r.CleanupAction(cleanup, owner); err != nil {
			result.Files = nil
			result.Directories = nil
			result.TerminationConfirmed = false
			result.ErrorCode = "INTERNAL"
			result.Message = "Action cleanup is incomplete; recovery state retained."
		}
	}()
	if err := r.Engine.CreateVolume(ctx, name, labels); err != nil {
		return actionError("INTERNAL", "Could not create private action volume.")
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
	if err = r.Engine.CopyFiles(ctx, id, "/work", archive); err != nil {
		return actionError("INTERNAL", "Could not materialize action inputs.")
	}
	if err = r.Engine.VerifyActionContainer(ctx, id, spec); err != nil {
		return actionError("FAILED_PRECONDITION", "Engine did not provide the required action isolation.")
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSeconds)*time.Second)
	defer cancel()
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
	result.Files, result.Directories, err = actionOutputs(archive, a)
	if err != nil {
		result.ErrorCode = "INVALID_ARGUMENT"
		result.Message = "Unsafe or oversized action output."
		result.Files = nil
		result.Directories = nil
	}
	return result
}

func actionInputArchive(a runnerclient.ActionAssignment, in runnerclient.ActionInputs) ([]byte, error) {
	var b actionArchiveBuffer
	tw := tar.NewWriter(&b)
	dirs := map[string]bool{".": true}
	addParents := func(p string) error {
		for p != "." {
			if dirs[p] {
				break
			}
			if len(dirs)+len(in.Files) >= runnerclient.MaxActionEntries {
				return errors.New("implicit action directories exceed entry limit")
			}
			dirs[p] = true
			p = path.Dir(p)
		}
		return nil
	}
	if len(in.Files)+len(dirs) > runnerclient.MaxActionEntries {
		return nil, errors.New("action archive exceeds entry limit")
	}
	for _, d := range in.Directories {
		if err := addParents(d); err != nil {
			return nil, err
		}
	}
	if a.WorkingDirectory != "" {
		if err := addParents(a.WorkingDirectory); err != nil {
			return nil, err
		}
	}
	for _, f := range in.Files {
		if err := addParents(path.Dir(f.Path)); err != nil {
			return nil, err
		}
	}
	// Output paths are relative to the command's working directory. Create parents,
	// never the output itself, which may be either a file or a directory.
	for _, p := range a.OutputPaths {
		joined := path.Join(a.WorkingDirectory, p)
		if !runnerclient.ActionPath(joined) {
			return nil, errors.New("invalid action output path below working directory")
		}
		if err := addParents(path.Dir(joined)); err != nil {
			return nil, err
		}
	}
	for _, f := range in.Files {
		if dirs[f.Path] {
			return nil, errors.New("action file conflicts with required directory")
		}
	}
	ordered := make([]string, 0, len(dirs))
	for d := range dirs {
		ordered = append(ordered, d)
	}
	slices.Sort(ordered)
	for _, d := range ordered {
		if err := tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0755, Uid: 1000, Gid: 1000}); err != nil {
			return nil, err
		}
	}
	for _, f := range in.Files {
		mode := int64(0644)
		if f.Executable {
			mode = 0755
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeReg, Mode: mode, Size: f.Size, Uid: 1000, Gid: 1000}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type actionArchiveBuffer struct{ buffer bytes.Buffer }

func (b *actionArchiveBuffer) Write(p []byte) (int, error) {
	if len(p) > runnerclient.MaxActionWire-b.buffer.Len() {
		return 0, errors.New("action input archive exceeds byte limit")
	}
	return b.buffer.Write(p)
}
func (b *actionArchiveBuffer) Bytes() []byte { return b.buffer.Bytes() }

func actionOutputs(archive []byte, a runnerclient.ActionAssignment) ([]runnerclient.ActionFile, []string, error) {
	tr := tar.NewReader(bytes.NewReader(archive))
	var files []runnerclient.ActionFile
	var directories []string
	seen := map[string]bool{}
	total, entries := int64(0), 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		entries++
		if entries > runnerclient.MaxActionEntries {
			return nil, nil, errors.New("too many output entries")
		}
		p := strings.TrimSuffix(h.Name, "/")
		if p == "work" && h.Typeflag == tar.TypeDir {
			continue
		}
		p, ok := strings.CutPrefix(p, "work/")
		if !ok || !runnerclient.ActionPath(p) || seen[p] {
			return nil, nil, errors.New("invalid output archive path")
		}
		seen[p] = true
		// Reject links and special files even if undeclared, so a declared
		// descendant cannot traverse an undeclared link or device.
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			return nil, nil, errors.New("action output links and special files unsupported")
		}
		wanted := false
		for _, output := range a.OutputPaths {
			rootOutput := path.Join(a.WorkingDirectory, output)
			if p == rootOutput || strings.HasPrefix(p, rootOutput+"/") {
				wanted = true
				break
			}
		}
		if !wanted {
			continue
		}
		if a.WorkingDirectory != "" {
			p = strings.TrimPrefix(p, a.WorkingDirectory+"/")
		}
		if h.Typeflag == tar.TypeDir {
			directories = append(directories, p)
			continue
		}
		if h.Size < 0 || h.Size > runnerclient.MaxActionBytes-total {
			return nil, nil, errors.New("output byte limit exceeded")
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, nil, fmt.Errorf("invalid output content")
		}
		total += h.Size
		sum := sha256.Sum256(data)
		files = append(files, runnerclient.ActionFile{Path: p, Data: data, Size: h.Size, SHA256: hex.EncodeToString(sum[:]), Executable: h.Mode&0111 != 0})
	}
	if err := (runnerclient.ActionInputs{Files: files, Directories: directories}).Validate(); err != nil {
		return nil, nil, err
	}
	return files, directories, nil
}
