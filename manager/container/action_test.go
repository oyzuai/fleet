package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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
	spec      Spec
	archive   []byte
	verifyErr error
	wait      func(context.Context) error
	stopErr   error
	running   bool
	stops     int
	exitCode  int
	inputTar  []byte
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
	out := (&ActionRuntime{Engine: e}).RunAction(context.Background(), a, runnerclient.ActionInputs{Files: []runnerclient.ActionFile{actionFile("input", "hello")}, Directories: []string{"empty"}})
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
		out := (&ActionRuntime{Engine: e}).RunAction(context.Background(), testAction(), in)
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
		out := (&ActionRuntime{Engine: e}).RunAction(ctx, testAction(), runnerclient.ActionInputs{})
		if e.stops != 1 || out.TerminationConfirmed == running || len(out.Files) != 0 {
			t.Fatalf("stop result: %+v, stops %d", out, e.stops)
		}
		if running && out.ErrorCode != "INTERNAL" || !running && out.ErrorCode != "CANCELLED" {
			t.Fatalf("wrong status: %+v", out)
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
