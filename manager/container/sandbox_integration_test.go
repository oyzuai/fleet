package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestDaemonlessOCIWithContainerPolicy(t *testing.T) {
	image := os.Getenv("FLEET_RUNTIME_IMAGE")
	if image == "" {
		t.Skip("run oyzu run container-runtime-proof for actual rootless OCI qualification")
	}
	engine, err := NewDocker("", DockerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := fmt.Sprintf("fleet-runtime-%d", time.Now().UnixNano())
	labels := map[string]string{LabelPool: name, LabelManager: "runtime-proof"}
	if err := engine.CreateVolume(ctx, name+"-work", labels); err != nil {
		t.Fatal(err)
	}
	defer engine.RemoveVolume(context.Background(), name+"-work")
	id, err := engine.CreateContainer(ctx, name, Spec{Image: image, Cmd: []string{"/probe"}, User: "1000:1000", WorkDir: WorkDir, Volume: name + "-work", Labels: labels, Network: "none", PidsLimit: 256, MemoryBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.RemoveContainer(context.Background(), id)
	allocation, err := engine.InspectReadinessAllocation(ctx, id)
	if err != nil || !allocation.SandboxApplied || allocation.User != "1000:1000" || allocation.Privileged || allocation.ExtraMount {
		t.Fatalf("applied outer runtime policy: %+v %v", allocation, err)
	}
	if err := engine.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	code, err := engine.WaitContainer(ctx, id)
	logs, logErr := engine.ContainerLogs(ctx, id, 20)
	if err != nil || logErr != nil || code != 0 {
		t.Fatalf("actual OCI process: exit=%d wait=%v logs=%v\n%s", code, err, logErr, logs)
	}
	var result struct {
		State         string `json:"state"`
		Digest        string `json:"native_output_sha256"`
		EmptyCaps     bool   `json:"outer_capabilities_empty"`
		NNP           bool   `json:"no_new_privileges"`
		Namespaces    bool   `json:"private_pid_network"`
		DeniedKeyRead bool   `json:"keyctl_read_denied"`
	}
	if err := json.Unmarshal(logs, &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "passed" || len(result.Digest) != 64 || !result.EmptyCaps || !result.NNP || !result.Namespaces || !result.DeniedKeyRead {
		t.Fatalf("native runtime result: %+v", result)
	}
	for _, drift := range []string{"syscall-default", "changed-proc-mask"} {
		body := createBody(Spec{Image: image, Cmd: []string{"/probe"}, User: "1000:1000", WorkDir: WorkDir, Labels: labels, Network: "none"})
		if drift == "syscall-default" {
			body.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
		} else {
			body.HostConfig.MaskedPaths = append(body.HostConfig.MaskedPaths, "/proc/keys")
		}
		var created struct {
			ID string `json:"Id"`
		}
		if err := engine.do(ctx, "POST", "/containers/create", url.Values{"name": {name + "-" + drift}}, body, &created); err != nil {
			t.Fatal(err)
		}
		defer engine.RemoveContainer(context.Background(), created.ID)
		observed, err := engine.InspectReadinessAllocation(ctx, created.ID)
		if err != nil || observed.SandboxApplied {
			t.Fatalf("actual changed %s policy was accepted: %+v %v", drift, observed, err)
		}
	}
	t.Logf("actual rootless OCI process passed; native output sha256:%s", result.Digest)
}
