// Command action-crash-proof checks the bounded action runtime and child-crash
// recovery against a cached immutable image. Only the trusted controller gets
// the engine connection; action code receives its private workspace alone.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/container"
	"github.com/oyzuai/fleet/runnerclient"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	if len(os.Args) < 2 {
		return errors.New("usage: action-crash-proof [runtime] IMAGE@sha256:DIGEST")
	}
	if os.Getenv("FLEET_ACTION_HELPER") == "" {
		return errors.New("FLEET_ACTION_HELPER must name the trusted installed static Linux Fleet executor")
	}
	engine, err := container.NewDocker(os.Getenv("FLEET_CRASH_ENGINE"), container.DockerOptions{})
	if err != nil {
		return err
	}
	runtime := &container.ActionRuntime{Engine: engine, HelperPath: os.Getenv("FLEET_ACTION_HELPER")}
	if os.Args[1] == "runtime" {
		if len(os.Args) != 3 {
			return errors.New("usage: action-crash-proof runtime IMAGE@sha256:DIGEST")
		}
		return runtimeCases(engine, os.Args[2])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if os.Args[1] == "helper" {
		if len(os.Args) != 4 {
			return errors.New("invalid helper arguments")
		}
		owner, err := runnerclient.ReadActionOwner(os.Args[2])
		if err != nil {
			return err
		}
		result := runtime.RunAction(ctx, owner, runnerclient.ActionAssignment{InstanceID: "crash-proof", OperationID: "crash-proof", Image: os.Args[3], OutputStyle: "paths", WorkspaceBytes: runnerclient.MaxWorkspaceBytes, WorkspaceInodes: runnerclient.MaxWorkspaceInodes, Arguments: []string{"/bin/sleep", "300"}, TimeoutSeconds: 300, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}, runnerclient.ActionInputs{})
		return fmt.Errorf("helper unexpectedly completed: %+v", result)
	}
	image := os.Args[1]
	if err = runtime.Ready(ctx); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "fleet-action-crash-")
	if err != nil {
		return err
	}
	retain := false
	defer func() {
		if retain {
			fmt.Fprintln(os.Stderr, "retained recovery directory:", root)
		} else {
			runErr = errors.Join(runErr, os.RemoveAll(root))
		}
	}()
	p := &manager.Process{Manager: 7331, WorkDir: root, Slots: 1, Docker: false, ActionCleanup: runtime.CleanupAction}
	directory := filepath.Join(root, "manager-7331", "job-42-3-crashproof")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	owner := runnerclient.ActionOwner{ManagerID: 7331, JobID: 42, Attempt: 3, Directory: directory}
	if err = runnerclient.WriteActionOwner(owner); err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, err := os.Stat(directory); err == nil {
			if err = runtime.CleanupAction(cleanup, owner); err != nil {
				retain = true
				runErr = errors.Join(runErr, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			retain = true
			runErr = errors.Join(runErr, err)
		}
	}()
	// This task-owned foreign sentinel shares broad labels but has a different
	// job identity. Reconciliation must preserve it until this proof cleans it.
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	sentinel := "fleet-crash-sentinel-" + hex.EncodeToString(nonce[:])
	foreign := map[string]string{"oyzu.io/action": sentinel, "oyzu.io/action-manager": "7331", "oyzu.io/action-job": "99", "oyzu.io/action-attempt": "1", "oyzu.io/action-owner": directory, "oyzu.io/action-role": "sentinel"}
	sentinelCleaned := false
	defer func() {
		if sentinelCleaned {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := cleanupSentinel(cleanup, engine, sentinel, foreign); err != nil {
			retain = true
			runErr = errors.Join(runErr, err)
		}
	}()
	if err = engine.CreateVolume(ctx, sentinel, foreign); err != nil {
		return err
	}
	sentinelID, err := engine.CreateContainer(ctx, sentinel, container.Spec{Image: image, Entrypoint: []string{"/bin/sleep"}, Cmd: []string{"300"}, User: "1000:1000", Labels: foreign, Network: "none", ReadOnly: true, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32})
	if err != nil {
		return err
	}
	sentinels, err := engine.ListContainers(ctx, foreign)
	if err != nil {
		return err
	}
	if len(sentinels) != 1 || sentinels[0].ID != sentinelID || sentinels[0].Name != sentinel || !hasLabels(sentinels[0].Labels, foreign) {
		return errors.New("sentinel create did not resolve to its exact owned identity")
	}
	if err = engine.StartContainer(ctx, sentinelID); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "helper", directory, image)
	var helperOutput bytes.Buffer
	cmd.Stdout = &helperOutput
	cmd.Stderr = &helperOutput
	if err = cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	labels := map[string]string{"oyzu.io/action-manager": "7331", "oyzu.io/action-job": "42", "oyzu.io/action-attempt": "3", "oyzu.io/action-owner": directory}
	deadline := time.Now().Add(20 * time.Second)
	for {
		rows, err := engine.ListContainers(ctx, labels)
		if err != nil {
			return err
		}
		if len(rows) == 2 && rows[0].State == "running" && rows[1].State == "running" {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			waited = true
			return fmt.Errorf("action never became running: %s", helperOutput.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err = cmd.Process.Kill(); err != nil {
		return err
	}
	cmd.Wait()
	waited = true
	rows, err := engine.ListContainers(ctx, labels)
	if err != nil || len(rows) != 2 || rows[0].State != "running" || rows[1].State != "running" {
		return fmt.Errorf("crash fixture did not leave a live isolated child: %v %v", rows, err)
	}
	if err = p.Reap(ctx, nil); err != nil {
		return err
	}
	rows, err = engine.ListContainers(ctx, labels)
	if err != nil || len(rows) != 0 {
		return fmt.Errorf("owned action survived reaping: %v %v", rows, err)
	}
	volumes, err := engine.ListVolumes(ctx, labels)
	if err != nil || len(volumes) != 0 {
		return fmt.Errorf("owned volume survived reaping: %v %v", volumes, err)
	}
	state, err := engine.InspectContainer(ctx, sentinelID)
	if err != nil || !state.Running {
		return fmt.Errorf("foreign sentinel was altered: %+v %v", state, err)
	}
	volumes, err = engine.ListVolumes(ctx, foreign)
	if err != nil || len(volumes) != 1 {
		return fmt.Errorf("foreign volume was altered: %v %v", volumes, err)
	}
	if _, err = os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("recovery directory was not removed")
	}
	capacity, err := p.Capacity(ctx)
	if err != nil || capacity.Running != 0 || len(capacity.Ready) != 1 {
		return fmt.Errorf("recovered slot not reusable: %+v %v", capacity, err)
	}
	if err = cleanupSentinel(ctx, engine, sentinel, foreign); err != nil {
		return err
	}
	sentinelCleaned = true
	source, modified := proofSource()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"case": "child-crash-reap", "result": "passed", "source_revision": source, "source_modified": modified, "image": image, "own_resources": "absent", "foreign_sentinel": "preserved-then-cleaned", "capacity": "reusable", "controller_restart": "not-tested"}); err != nil {
		return err
	}
	return nil
}

func hasLabels(actual, expected map[string]string) bool {
	for k, v := range expected {
		if actual[k] != v {
			return false
		}
	}
	return true
}

func cleanupSentinel(ctx context.Context, engine container.ActionEngine, name string, labels map[string]string) error {
	rows, err := engine.ListContainers(ctx, labels)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == "" || row.Name != name || !hasLabels(row.Labels, labels) {
			return errors.New("sentinel container ownership mismatch")
		}
	}
	for _, row := range rows {
		if err = engine.StopContainer(ctx, row.ID, time.Second); err != nil {
			return err
		}
		state, e := engine.InspectContainer(ctx, row.ID)
		if e != nil {
			return e
		}
		if state.Running {
			return errors.New("sentinel remains running")
		}
		if err = engine.RemoveContainer(ctx, row.ID); err != nil {
			return err
		}
	}
	rows, err = engine.ListContainers(ctx, labels)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return errors.New("sentinel container remains")
	}
	volumes, err := engine.ListVolumes(ctx, labels)
	if err != nil {
		return err
	}
	for _, v := range volumes {
		if v.Name != name || !hasLabels(v.Labels, labels) {
			return errors.New("sentinel volume ownership mismatch")
		}
	}
	for _, v := range volumes {
		if err = engine.RemoveVolume(ctx, v.Name); err != nil {
			return err
		}
	}
	volumes, err = engine.ListVolumes(ctx, labels)
	if err != nil {
		return err
	}
	if len(volumes) != 0 {
		return errors.New("sentinel volume remains")
	}
	return nil
}

func proofSource() (string, string) {
	source, modified := "unknown", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				source = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
	}
	return source, modified
}

// snapshotEngine checks actual engine state at the archive boundary. It does
// not replace any allocation, isolation, quota or cleanup implementation.
type snapshotEngine struct {
	container.ActionEngine
	user, holder                    string
	archiveChecked, userStopChecked bool
	unselectedBytes                 int64
	physicalFiles, physicalEntries  int
}

func (e *snapshotEngine) CreateContainer(ctx context.Context, name string, spec container.Spec) (string, error) {
	id, err := e.ActionEngine.CreateContainer(ctx, name, spec)
	if err == nil {
		switch spec.Labels["oyzu.io/action-role"] {
		case "user":
			e.user = id
		case "holder":
			e.holder = id
		}
	}
	return id, err
}

func (e *snapshotEngine) StopContainer(ctx context.Context, id string, grace time.Duration) error {
	if err := e.ActionEngine.StopContainer(ctx, id, grace); err != nil {
		return err
	}
	if id == e.user {
		state, err := e.ActionEngine.InspectContainer(ctx, id)
		if err != nil {
			return err
		}
		if state.Running {
			return errors.New("user remains running after stop")
		}
		e.userStopChecked = true
	}
	return nil
}

func (e *snapshotEngine) ReadContainerArchive(ctx context.Context, id, p string) ([]byte, error) {
	if id != e.user || p != "/work" {
		return nil, errors.New("unexpected output archive request")
	}
	user, err := e.ActionEngine.InspectContainer(ctx, e.user)
	if err != nil {
		return nil, err
	}
	holder, err := e.ActionEngine.InspectContainer(ctx, e.holder)
	if err != nil {
		return nil, err
	}
	if user.Running || !holder.Running {
		return nil, errors.New("archive boundary lacks stopped user and live holder")
	}
	archive, err := e.ActionEngine.ReadContainerArchive(ctx, id, p)
	if err != nil {
		return nil, err
	}
	holder, err = e.ActionEngine.InspectContainer(ctx, e.holder)
	if err != nil || !holder.Running {
		return nil, errors.New("holder was lost while reading the archive")
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		e.physicalEntries++
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			e.physicalFiles++
		}
		if h.Name == "work/unselected" {
			e.unselectedBytes = h.Size
		}
	}
	e.archiveChecked = true
	return archive, nil
}

func proofLabels(owner runnerclient.ActionOwner) map[string]string {
	return map[string]string{"oyzu.io/action-manager": strconv.FormatInt(owner.ManagerID, 10), "oyzu.io/action-job": strconv.FormatInt(owner.JobID, 10), "oyzu.io/action-attempt": strconv.Itoa(owner.Attempt), "oyzu.io/action-owner": owner.Directory}
}

func proveClean(ctx context.Context, engine container.ActionEngine, owner runnerclient.ActionOwner) error {
	containers, err := engine.ListContainers(ctx, proofLabels(owner))
	if err != nil {
		return err
	}
	volumes, err := engine.ListVolumes(ctx, proofLabels(owner))
	if err != nil {
		return err
	}
	if len(containers) != 0 || len(volumes) != 0 {
		return fmt.Errorf("owned resources remain: containers=%d volumes=%d", len(containers), len(volumes))
	}
	if _, err = os.Stat(filepath.Join(owner.Directory, runnerclient.ActionResourcesFile)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("action journal remains: %v", err)
	}
	return nil
}

// waitUser selects only this attempt's exact role/nonce labels. A ready log
// proves the fixture files exist without archiving a running workspace.
func waitUser(ctx context.Context, engine container.ActionEngine, owner runnerclient.ActionOwner) (string, error) {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return "", errors.New("user did not reach the running fixture")
		case <-tick.C:
			rows, err := engine.ListContainers(ctx, proofLabels(owner))
			if err != nil {
				return "", err
			}
			var user, holder container.Summary
			for _, row := range rows {
				if !hasLabels(row.Labels, proofLabels(owner)) {
					return "", errors.New("observed container owner labels differ")
				}
				switch row.Labels["oyzu.io/action-role"] {
				case "user":
					if user.ID != "" {
						return "", errors.New("multiple owned user containers")
					}
					user = row
				case "holder":
					if holder.ID != "" {
						return "", errors.New("multiple owned holder containers")
					}
					holder = row
				}
			}
			if user.ID == "" || holder.ID == "" {
				continue
			}
			nonce := user.Labels["oyzu.io/action"]
			if nonce == "" || holder.Labels["oyzu.io/action"] != nonce || user.Name != nonce || holder.Name != nonce+"-holder" {
				return "", errors.New("role identity differs from the shared action nonce")
			}
			us, err := engine.InspectContainer(ctx, user.ID)
			if err != nil {
				return "", err
			}
			hs, err := engine.InspectContainer(ctx, holder.ID)
			if err != nil {
				return "", err
			}
			if !us.Running || !hs.Running {
				continue
			}
			logs, err := engine.ContainerLogs(ctx, user.ID, 1)
			if err != nil {
				return "", err
			}
			if bytes.Contains(logs, []byte("proof-ready\n")) {
				return holder.ID, nil
			}
		}
	}
}

func runtimeCases(engine container.ActionEngine, image string) (proofErr error) {
	if err := os.Setenv("FLEET_RUNTIME_PROOF_CANARY", "not-a-secret-runtime-fixture"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "fleet-action-runtime-")
	if err != nil {
		return err
	}
	retain := false
	defer func() {
		if retain {
			fmt.Fprintln(os.Stderr, "retained recovery directory:", root)
		} else {
			proofErr = errors.Join(proofErr, os.RemoveAll(root))
		}
	}()
	managerDir := filepath.Join(root, "manager-7332")
	if err = os.Mkdir(managerDir, 0700); err != nil {
		return err
	}
	source, modified := proofSource()
	input := []byte("persisted contained input\n")
	sum := sha256.Sum256(input)
	inputs := runnerclient.ActionInputs{Files: []runnerclient.ActionFile{{Path: "shared/input", Data: input, Size: int64(len(input)), SHA256: hex.EncodeToString(sum[:])}}, Directories: []string{"src"}, Symlinks: []runnerclient.ActionSymlink{{Path: "alias", Target: "src"}, {Path: "src/input-link", Target: "../shared/input"}}}
	cases := []struct {
		name, script  string
		bytes, inodes int64
		control       string
	}{
		{"normal", `
test "$(id -u)" = 1000
test "${FLEET_RUNTIME_PROOF_CANARY+x}" != x
test ! -e /var/run/docker.sock
test ! -e /bootstrap/executor
test ! -e /run/secrets
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status
if touch /must-stay-read-only 2>/dev/null; then exit 41; fi
if nc -w 1 1.1.1.1 443 </dev/null 2>/dev/null; then exit 42; fi
awk 'NR > 1 && $2 == "00000000" { bad=1 } END { exit bad }' /proc/net/route
test "$(readlink input-link)" = ../shared/input
cat input-link > result
chmod +x result
ln -s ../shared/input output-link
mkdir -p tree/empty
ln -s ../../shared/input tree/link
printf 'normal-ok uid=1000\n'
`, runnerclient.MaxWorkspaceBytes, runnerclient.MaxWorkspaceInodes, ""},
		{"bytes", `
printf pending > result
if failure=$(dd if=/dev/zero of=unselected bs=65536 count=128 2>&1); then exit 51; fi
case "$failure" in *"No space left on device"*) ;; *) printf '%s\n' "$failure" >&2; exit 52 ;; esac
n=$(wc -c < unselected)
test "$n" -ge 3000000
test "$n" -le 4194304
printf 'bytes-enospc\n' > result
printf 'bytes-enospc %s\n' "$n"
`, 4 << 20, runnerclient.MaxWorkspaceInodes, ""},
		{"inodes", `
printf pending > result
n=0
while failure=$(touch "node$n" 2>&1); do n=$((n+1)); test "$n" -le 64; done
case "$failure" in *"No space left on device"*) ;; *) printf '%s\n' "$failure" >&2; exit 61 ;; esac
test "$n" -gt 0
test "$n" -lt 64
printf 'inodes-enospc\n' > result
printf 'inodes-enospc %s\n' "$n"
`, 4 << 20, 64, ""},
		{"holder-loss", "printf must-not-publish > result; ln -s result output-link; printf 'proof-ready\\n'; sleep 30", 4 << 20, 64, "holder-loss"},
		{"cancellation", "printf must-not-publish > result; ln -s result output-link; printf 'proof-ready\\n'; sleep 30", 4 << 20, 64, "cancel"},
	}
	for index, fixture := range cases {
		directory := filepath.Join(managerDir, fmt.Sprintf("job-%d-1-%s", 100+index, fixture.name))
		if err = os.Mkdir(directory, 0700); err != nil {
			return err
		}
		owner := runnerclient.ActionOwner{ManagerID: 7332, JobID: int64(100 + index), Attempt: 1, Directory: directory}
		if err = runnerclient.WriteActionOwner(owner); err != nil {
			return err
		}
		observed := &snapshotEngine{ActionEngine: engine}
		runtime := &container.ActionRuntime{Engine: observed, HelperPath: os.Getenv("FLEET_ACTION_HELPER")}
		a := runnerclient.ActionAssignment{InstanceID: "runtime-proof", OperationID: fixture.name, Image: image, Arguments: []string{"/bin/sh", "-ec", fixture.script}, Environment: map[string]string{"LC_ALL": "C"}, OutputStyle: "paths", Outputs: []runnerclient.ActionOutput{{Path: "result", Kind: "any"}}, WorkspaceBytes: fixture.bytes, WorkspaceInodes: fixture.inodes, TimeoutSeconds: 40, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}
		in := runnerclient.ActionInputs{}
		if fixture.name == "normal" {
			a.WorkingDirectory = "alias"
			a.Outputs = append(a.Outputs, runnerclient.ActionOutput{Path: "output-link", Kind: "any"}, runnerclient.ActionOutput{Path: "tree", Kind: "any"})
			in = inputs
		}
		if fixture.control != "" {
			a.Outputs = append(a.Outputs, runnerclient.ActionOutput{Path: "output-link", Kind: "any"})
		}
		result, runErr := func() (result runnerclient.ActionCompletion, runErr error) {
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
				defer stop()
				if err := runtime.CleanupAction(cleanup, owner); err != nil {
					retain = true
					runErr = errors.Join(runErr, err)
				} else if err = proveClean(cleanup, engine, owner); err != nil {
					retain = true
					runErr = errors.Join(runErr, err)
				}
			}()
			actionCtx, stop := context.WithCancel(ctx)
			defer stop()
			if fixture.control == "" {
				return runtime.RunAction(actionCtx, owner, a, in), nil
			}
			finished := make(chan runnerclient.ActionCompletion, 1)
			go func() { finished <- runtime.RunAction(actionCtx, owner, a, in) }()
			holder, err := waitUser(actionCtx, engine, owner)
			if err == nil && fixture.control == "holder-loss" {
				err = engine.StopContainer(actionCtx, holder, time.Second)
			} else {
				stop()
			}
			if err != nil {
				stop()
			}
			result = <-finished
			return result, err
		}()
		if runErr != nil {
			return fmt.Errorf("%s: %w", fixture.name, runErr)
		}
		var allocated int64
		exit := "none"
		if result.ExitCode != nil {
			exit = strconv.Itoa(*result.ExitCode)
		}
		if fixture.control != "" {
			want := "INTERNAL"
			if fixture.control == "cancel" {
				want = "CANCELLED"
			}
			if result.ErrorCode != want || !result.TerminationConfirmed || !observed.userStopChecked || observed.archiveChecked || len(result.Files)+len(result.Directories)+len(result.Symlinks)+len(result.WorkspaceNodes) != 0 {
				return fmt.Errorf("%s did not stop/discard outputs: code=%s message=%q termination=%t stopped=%t archive=%t", fixture.name, result.ErrorCode, result.Message, result.TerminationConfirmed, observed.userStopChecked, observed.archiveChecked)
			}
		} else {
			if result.ErrorCode != "" || result.ExitCode == nil || *result.ExitCode != 0 || !result.TerminationConfirmed || !observed.archiveChecked || len(result.Files) != 1 || result.Files[0].Path != "result" {
				return fmt.Errorf("%s action failed: code=%s message=%q exit=%s termination=%t stdout=%q stderr=%q", fixture.name, result.ErrorCode, result.Message, exit, result.TerminationConfirmed, result.Stdout, result.Stderr)
			}
			switch fixture.name {
			case "normal":
				links := map[string]string{}
				for _, l := range result.Symlinks {
					links[l.Path] = l.Target
				}
				if !bytes.Equal(result.Files[0].Data, input) || !result.Files[0].Executable || len(result.Directories) != 2 || result.Directories[0] != "tree" || result.Directories[1] != "tree/empty" || len(links) != 2 || links["output-link"] != "../shared/input" || links["tree/link"] != "../../shared/input" || string(result.Stdout) != "normal-ok uid=1000\n" {
					return errors.New("normal input/output persistence, alias, literal link or mode mismatch")
				}
			case "bytes", "inodes":
				marker := fixture.name + "-enospc"
				if string(result.Files[0].Data) != marker+"\n" {
					return errors.New("quota result did not overwrite the existing inode")
				}
				if n, err := fmt.Sscanf(string(result.Stdout), marker+" %d\n", &allocated); err != nil || n != 1 {
					return fmt.Errorf("invalid quota allocation observation: %q", result.Stdout)
				}
				if fixture.name == "bytes" && (allocated < 3000000 || allocated > fixture.bytes || observed.unselectedBytes != allocated) {
					return errors.New("byte exhaustion outside configured quota")
				}
				if fixture.name == "inodes" && (allocated < 1 || allocated >= fixture.inodes || len(result.WorkspaceNodes) != int(allocated)+1 || observed.physicalFiles != int(allocated)+1 || observed.physicalEntries != int(allocated)+2) {
					return errors.New("inode exhaustion does not match snapshot metadata")
				}
			}
		}
		receipt := map[string]any{"case": fixture.name, "result": "passed", "source_revision": source, "source_modified": modified, "image": image, "workspace_bytes": fixture.bytes, "workspace_inodes": fixture.inodes, "memory_bytes": a.MemoryBytes, "outputs": len(result.Files), "symlinks": len(result.Symlinks), "workspace_nodes": len(result.WorkspaceNodes), "cleanup": "absent"}
		if fixture.name == "bytes" {
			receipt["allocated_bytes"] = allocated
		}
		if fixture.name == "inodes" {
			receipt["allocated_files"] = observed.physicalFiles
			receipt["archive_entries"] = observed.physicalEntries
		}
		if len(result.Files) == 1 {
			receipt["selected_sha256"] = result.Files[0].SHA256
		}
		if err = json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
			return err
		}
	}
	return nil
}
