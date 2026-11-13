package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func testAction() runnerclient.ActionAssignment {
	return runnerclient.ActionAssignment{InstanceID: "instance", OperationID: "operation", Image: "test/image@sha256:" + strings.Repeat("a", 64), Arguments: []string{"/bin/sh", "-c", "cat input > out"}, OutputPaths: []string{"out"}, TimeoutSeconds: 30, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}
}

func actionFile(p, content string) runnerclient.ActionFile {
	b := []byte(content)
	sum := sha256.Sum256(b)
	return runnerclient.ActionFile{Path: p, Data: b, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
}

func testActionOwner(t *testing.T) runnerclient.ActionOwner {
	t.Helper()
	owner := runnerclient.ActionOwner{ManagerID: 7, JobID: 42, Attempt: 1, Directory: t.TempDir()}
	if err := runnerclient.WriteActionOwner(owner); err != nil {
		t.Fatal(err)
	}
	return owner
}

func outputArchive(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type actionEngineFake struct {
	*fakeEngine
	spec          Spec
	archive       []byte
	verifyErr     error
	wait          func(context.Context) error
	stopErr       error
	running       bool
	stops         int
	exitCode      int
	inputTar      []byte
	volumeCreates int
}

func (e *actionEngineFake) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	e.volumeCreates++
	return e.fakeEngine.CreateVolume(ctx, name, labels)
}

func (e *actionEngineFake) ActionReady(context.Context) error { return nil }
func (e *actionEngineFake) VerifyActionContainer(_ context.Context, _ string, s Spec) error {
	e.spec = s
	return e.verifyErr
}
func (e *actionEngineFake) ReadContainerArchive(context.Context, string, string) ([]byte, error) {
	return e.archive, nil
}
func (e *actionEngineFake) ContainerOutput(context.Context, string) ([]byte, []byte, error) {
	return []byte("stdout"), []byte("stderr"), nil
}
func (e *actionEngineFake) CopyFiles(ctx context.Context, id, p string, b []byte) error {
	e.inputTar = slices.Clone(b)
	return e.fakeEngine.CopyFiles(ctx, id, p, b)
}
func (e *actionEngineFake) WaitContainer(ctx context.Context, _ string) (int, error) {
	if e.wait != nil {
		return 0, e.wait(ctx)
	}
	return e.exitCode, nil
}
func (e *actionEngineFake) InspectContainer(context.Context, string) (State, error) {
	return State{Running: e.running, ExitCode: e.exitCode}, nil
}
func (e *actionEngineFake) StopContainer(context.Context, string, time.Duration) error {
	e.stops++
	return e.stopErr
}

func TestActionRuntimeIsolatesAndReturnsProcessResult(t *testing.T) {
	e := &actionEngineFake{fakeEngine: newFakeEngine(), exitCode: 7, archive: outputArchive(t, &tar.Header{Name: "work/sub/out", Typeflag: tar.TypeReg, Mode: 0755, Size: 1})}
	e.present = true
	a := testAction()
	a.Environment = map[string]string{"EXPLICIT": "value"}
	a.WorkingDirectory = "sub"
	out := (&ActionRuntime{Engine: e}).RunAction(context.Background(), testActionOwner(t), a, runnerclient.ActionInputs{Files: []runnerclient.ActionFile{actionFile("input", "hello")}, Directories: []string{"empty"}})
	if out.ErrorCode != "" || !out.TerminationConfirmed || out.ExitCode == nil || *out.ExitCode != 7 || string(out.Stdout) != "stdout" || string(out.Stderr) != "stderr" || len(out.Files) != 1 || !out.Files[0].Executable {
		t.Fatalf("result: %+v", out)
	}
	s := e.spec
	if s.User != "1000:1000" || s.Network != "none" || !s.ReadOnly || s.VolumePath != "/work" || !s.VolumeNoCopy || s.WorkDir != "/work/sub" || !slices.Equal(s.Entrypoint, []string{"/bin/sh"}) || !slices.Equal(s.Cmd, a.Arguments[1:]) || !slices.Equal(s.Env, []string{"EXPLICIT=value"}) || s.NanoCPUs != a.NanoCPUs || s.MemoryBytes != a.MemoryBytes || s.PidsLimit != 32 {
		t.Fatalf("spec: %+v", s)
	}
	tr := tar.NewReader(bytes.NewReader(e.inputTar))
	paths := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 1000 || h.Gid != 1000 {
			t.Fatal("wrong ownership")
		}
		paths[h.Name] = true
	}
	if !paths["."] || !paths["input"] || !paths["empty"] || !paths["sub"] {
		t.Fatalf("missing input entries: %v", paths)
	}
	if e.pulls != 0 || len(e.volumes) != 0 || len(e.containers) != 0 {
		t.Fatal("pull or resource leak")
	}
}

func TestActionRuntimeRefusesUnsafeInputsAndUnverifiedSandbox(t *testing.T) {
	for _, unsafe := range []bool{true, false} {
		e := &actionEngineFake{fakeEngine: newFakeEngine(), verifyErr: errors.New("sandbox missing")}
		e.present = true
		in := runnerclient.ActionInputs{}
		if unsafe {
			in.Files = []runnerclient.ActionFile{actionFile("../token", "bad")}
		}
		out := (&ActionRuntime{Engine: e}).RunAction(context.Background(), testActionOwner(t), testAction(), in)
		if out.ErrorCode == "" || out.TerminationConfirmed {
			t.Fatalf("accepted: %+v", out)
		}
		for _, c := range e.containers {
			if c.started {
				t.Fatal("unsafe action started")
			}
		}
		if len(e.volumes) != 0 || len(e.containers) != 0 {
			t.Fatal("refusal leaked resources")
		}
	}
}

func TestActionRuntimeCancellationRequiresObservedStop(t *testing.T) {
	for _, running := range []bool{false, true} {
		e := &actionEngineFake{fakeEngine: newFakeEngine(), running: running}
		e.present = true
		ctx, cancel := context.WithCancel(context.Background())
		e.wait = func(ctx context.Context) error { cancel(); <-ctx.Done(); return ctx.Err() }
		out := (&ActionRuntime{Engine: e}).RunAction(ctx, testActionOwner(t), testAction(), runnerclient.ActionInputs{})
		expectedStops := 1
		if running {
			expectedStops = 2
		}
		if e.stops != expectedStops || out.TerminationConfirmed == running || len(out.Files) != 0 {
			t.Fatalf("stop result: %+v, stops %d", out, e.stops)
		}
		if running && out.ErrorCode != "INTERNAL" || !running && out.ErrorCode != "CANCELLED" {
			t.Fatalf("wrong status: %+v", out)
		}
	}
}

func TestActionInputImplicitDirectoriesAndArchiveBytesBoundedBeforeAllocation(t *testing.T) {
	a := testAction()
	// Each explicit leaf contributes hundreds of distinct implicit parents.
	for n := 0; n < 100; n++ {
		a.OutputPaths = append(a.OutputPaths, fmt.Sprintf("tree%d/", n)+strings.Repeat("d/", 200)+"out")
	}
	e := &actionEngineFake{fakeEngine: newFakeEngine()}
	e.present = true
	out := (&ActionRuntime{Engine: e}).RunAction(context.Background(), testActionOwner(t), a, runnerclient.ActionInputs{})
	if out.ErrorCode != "INVALID_ARGUMENT" || e.next != 0 || e.volumeCreates != 0 || len(e.volumes) != 0 {
		t.Fatalf("implicit directory expansion allocated resources: %+v", out)
	}
	// PAX long-path records can exceed the wire budget below the entry cap.
	in := runnerclient.ActionInputs{}
	for n := 0; n < 7000; n++ {
		in.Files = append(in.Files, actionFile(fmt.Sprintf("%04d", n)+strings.Repeat("x", 4000), ""))
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	out = (&ActionRuntime{Engine: e}).RunAction(context.Background(), testActionOwner(t), testAction(), in)
	if out.ErrorCode != "INVALID_ARGUMENT" || e.volumeCreates != 0 || e.next != 0 {
		t.Fatalf("oversized encoded archive reached engine allocation: %+v", out)
	}
}

type cleanupFailActionEngine struct {
	*actionEngineFake
	fail bool
}

func (e *cleanupFailActionEngine) RemoveVolume(ctx context.Context, name string) error {
	if e.fail {
		return errors.New("volume cleanup unavailable")
	}
	return e.fakeEngine.RemoveVolume(ctx, name)
}

func TestActionRuntimeCleanupFailureRetainsJournalAndRefusesConfirmedCompletion(t *testing.T) {
	fake := &actionEngineFake{fakeEngine: newFakeEngine(), archive: outputArchive(t, &tar.Header{Name: "work/out", Typeflag: tar.TypeReg, Size: 1})}
	fake.present = true
	engine := &cleanupFailActionEngine{actionEngineFake: fake, fail: true}
	runtime := &ActionRuntime{Engine: engine}
	owner := testActionOwner(t)
	out := runtime.RunAction(context.Background(), owner, testAction(), runnerclient.ActionInputs{})
	if out.ErrorCode != "INTERNAL" || out.TerminationConfirmed || len(out.Files) != 0 || len(fake.volumes) != 1 {
		t.Fatalf("cleanup failure acknowledged completion: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(owner.Directory, actionRecordFile)); err != nil {
		t.Fatal("cleanup failure discarded recovery journal", err)
	}
	engine.fail = false
	if err := runtime.CleanupAction(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	if len(fake.volumes) != 0 {
		t.Fatal("recovery retained owned volume")
	}
	if _, err := os.Stat(filepath.Join(owner.Directory, actionRecordFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery journal remained after successful cleanup", err)
	}
}

type ambiguousActionEngine struct {
	*actionEngineFake
	volume    bool
	container bool
}

func (e ambiguousActionEngine) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	if err := e.fakeEngine.CreateVolume(ctx, name, labels); err != nil {
		return err
	}
	if e.volume {
		return errors.New("lost create response")
	}
	return nil
}
func (e ambiguousActionEngine) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	id, err := e.fakeEngine.CreateContainer(ctx, name, spec)
	if err != nil {
		return id, err
	}
	if e.container {
		return "", errors.New("lost create response")
	}
	return id, nil
}

func TestActionRecoveryHandlesAmbiguousAllocationResponses(t *testing.T) {
	for _, volume := range []bool{true, false} {
		fake := &actionEngineFake{fakeEngine: newFakeEngine()}
		fake.present = true
		owner := testActionOwner(t)
		runtime := &ActionRuntime{Engine: ambiguousActionEngine{actionEngineFake: fake, volume: volume, container: !volume}}
		out := runtime.RunAction(context.Background(), owner, testAction(), runnerclient.ActionInputs{})
		if out.ErrorCode == "" || out.TerminationConfirmed || len(fake.volumes) != 0 || len(fake.containers) != 0 {
			t.Fatalf("ambiguous create leaked resources: %+v", out)
		}
		if _, err := os.Stat(filepath.Join(owner.Directory, actionRecordFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("completed cleanup retained journal", err)
		}
	}
}

func TestActionOutputRejectsEscapesLinksAndBounds(t *testing.T) {
	for _, h := range []*tar.Header{
		{Name: "work/../token", Typeflag: tar.TypeReg},
		{Name: "work/out", Typeflag: tar.TypeSymlink, Linkname: "/run/token"},
		{Name: "work/out", Typeflag: tar.TypeLink, Linkname: "work/input"},
		{Name: "work/out", Typeflag: tar.TypeFifo},
		{Name: "/work/out", Typeflag: tar.TypeReg},
	} {
		if _, _, err := actionOutputs(outputArchive(t, h), testAction()); err == nil {
			t.Fatalf("accepted unsafe header %+v", h)
		}
	}
	archive := outputArchive(t, &tar.Header{Name: "work/out", Typeflag: tar.TypeDir}, &tar.Header{Name: "work/out/empty", Typeflag: tar.TypeDir}, &tar.Header{Name: "work/input", Typeflag: tar.TypeReg, Size: 1})
	f, dirs, err := actionOutputs(archive, testAction())
	if err != nil || len(f) != 0 || !slices.Equal(dirs, []string{"out", "out/empty"}) {
		t.Fatalf("declared directories: %v %v %v", f, dirs, err)
	}
}
