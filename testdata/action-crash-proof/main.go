// Command action-crash-proof demonstrates recovery after a trusted executor is
// killed while its isolated child is still running. Run with a cached image
// digest and a trusted controller's engine connection; never mount that
// connection into the action child.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: action-crash-proof IMAGE@sha256:DIGEST")
	}
	engine, err := container.NewDocker(os.Getenv("FLEET_CRASH_ENGINE"), container.DockerOptions{})
	if err != nil {
		return err
	}
	runtime := &container.ActionRuntime{Engine: engine}
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
		result := runtime.RunAction(ctx, owner, runnerclient.ActionAssignment{InstanceID: "crash-proof", OperationID: "crash-proof", Image: os.Args[3], Arguments: []string{"/bin/sleep", "300"}, TimeoutSeconds: 300, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}, runnerclient.ActionInputs{})
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
	defer os.RemoveAll(root)
	p := &manager.Process{Manager: 7331, WorkDir: root, Slots: 1, ActionCleanup: runtime.CleanupAction}
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
			runtime.CleanupAction(cleanup, owner)
		}
	}()
	// This task-owned foreign sentinel shares broad labels but has a different
	// job identity. Reconciliation must preserve it until this proof cleans it.
	sentinel := "fleet-crash-sentinel-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	foreign := map[string]string{"oyzu.io/action": sentinel, "oyzu.io/action-manager": "7331", "oyzu.io/action-job": "99", "oyzu.io/action-attempt": "1", "oyzu.io/action-owner": directory}
	if err = engine.CreateVolume(ctx, sentinel, foreign); err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		engine.RemoveVolume(cleanup, sentinel)
	}()
	sentinelID, err := engine.CreateContainer(ctx, sentinel, container.Spec{Image: image, Entrypoint: []string{"/bin/sleep"}, Cmd: []string{"300"}, User: "1000:1000", Labels: foreign, Network: "none", ReadOnly: true, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		engine.StopContainer(cleanup, sentinelID, time.Second)
		engine.RemoveContainer(cleanup, sentinelID)
	}()
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
		if len(rows) == 1 && rows[0].State == "running" {
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
	if err != nil || len(rows) != 1 || rows[0].State != "running" {
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
	fmt.Println("PASS: executor SIGKILL left a live action; restarted Process.Reap stopped and removed only the recorded job/attempt resources, preserved foreign sentinel, and returned capacity.")
	return nil
}
