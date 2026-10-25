//go:build linux

package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPodmanPeer(context.Context, string) (podmanIdentity, error) {
	return podmanIdentity{pid: 123, start: "test"}, nil
}
func TestPodmanManagedProfileConcurrentAndTamper(t *testing.T) {
	runtime := t.TempDir()
	if e := os.Chmod(runtime, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	var wg sync.WaitGroup
	paths := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := newPodmanProfileForPeer(context.Background(), "test", testPodmanPeer, func(*podmanProfile) error { return nil })
			if e != nil {
				t.Error(e)
				return
			}
			paths <- p.path
		}()
	}
	wg.Wait()
	close(paths)
	var path string
	for p := range paths {
		if path != "" && p != path {
			t.Fatal("not content addressed")
		}
		path = p
	}
	if path == "" {
		t.Fatal("no profile")
	}
	p, e := newPodmanProfileForPeer(context.Background(), "test", testPodmanPeer, func(*podmanProfile) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if p.validate() == nil {
		t.Fatal("public file mode accepted")
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if p.validate() == nil {
		t.Fatal("public directory mode accepted")
	}
	if e = os.Chmod(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if p.validate() == nil {
		t.Fatal("changed profile accepted")
	}
	if _, e = newPodmanProfileForPeer(context.Background(), "test", testPodmanPeer, func(*podmanProfile) error { return nil }); e == nil {
		t.Fatal("tamper overwritten")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(runtime, "outside")
	if e = os.WriteFile(outside, []byte(daemonlessSyscallPolicy), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, path); e != nil {
		t.Fatal(e)
	}
	if _, e = newPodmanProfileForPeer(context.Background(), "test", testPodmanPeer, func(*podmanProfile) error { return nil }); e == nil {
		t.Fatal("profile symlink reused")
	}
}

func TestPodmanEffectiveSandbox(t *testing.T) {
	socket, image := os.Getenv("FLEET_PODMAN_PROOF_SOCKET"), os.Getenv("FLEET_PODMAN_PROOF_IMAGE")
	if socket == "" || image == "" {
		t.Skip("dedicated uid1002 Podman4.9 proof requires explicit socket and immutable image")
	}
	if os.Geteuid() != 1002 || !strings.HasPrefix(socket, "/run/user/1002/") || !strings.HasPrefix(image, "ghcr.io/oyzuai/oyzu-execution/base@sha256:") {
		t.Fatal("proof is restricted to dedicated uid1002 and immutable image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	engine, e := NewDocker("unix://"+socket, DockerOptions{})
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("oyzu-pool-sandbox-api-%d", time.Now().UnixNano())
	id, e := engine.CreateContainer(ctx, name, Spec{Image: image, Cmd: []string{"/bin/sh", "-c", "cat /proc/self/status; cat /proc/self/mountinfo; sleep 2"}, User: "1000:1000", WorkDir: "/work", Network: "none", PidsLimit: 64, MemoryBytes: 128 << 20, Labels: map[string]string{LabelPool: "oyzu-pool-slice1-proof", LabelManager: "sandbox-adapter"}})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := engine.RemoveContainer(cleanup, id); e != nil {
			t.Error(e)
		}
	}()
	if e = engine.StartContainer(ctx, id); e != nil {
		t.Fatal(e)
	}
	a, e := engine.InspectReadinessAllocation(ctx, id)
	if e != nil || !a.SandboxApplied || a.Privileged || a.HostNetwork || a.ExtraMount {
		var metadata struct {
			HostConfig    struct{ SecurityOpt []string }
			OCIConfigPath string
		}
		_ = engine.do(ctx, "GET", "/containers/"+id+"/json", nil, nil, &metadata)
		t.Logf("own container policy metadata: %+v", metadata)
		t.Fatalf("actual OCI sandbox rejected: %+v %v", a, e)
	}
	code, e := engine.WaitContainer(ctx, id)
	if e != nil || code != 0 {
		t.Fatalf("probe exit%d %v", code, e)
	}
	logs, e := engine.ContainerLogs(ctx, id, 500)
	if e != nil {
		t.Fatal(e)
	}
	text := string(logs)
	for _, want := range []string{"NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000", "CapPrm:\t0000000000000000", "Uid:\t1000\t1000\t1000\t1000"} {
		if !strings.Contains(text, want) {
			t.Fatalf("effective control absent: %s", want)
		}
	}
	sysSeen := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 6 && (fields[4] == "/sys" || strings.HasPrefix(fields[4], "/sys/")) {
			if !strings.Contains(","+fields[5]+",", ",ro,") {
				t.Fatalf("writable effective sys mount: %s", line)
			}
			if fields[4] == "/sys" {
				sysSeen = true
			}
		}
	}
	if !sysSeen {
		t.Fatal("effective sys mount missing")
	}
	t.Logf("Podman4.9 actual OCI and effective kernel sandbox passed; container%s fixedprofile%s", id, filepath.Base(engine.profile.path))
}
func TestPodmanRejectsForwardedAndRemoteEngine(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "socket")
	listener, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			c.Close()
		}
	}()
	if _, e = qualifyPodmanPeer(context.Background(), sock); e == nil {
		t.Fatal("arbitrary local Unix peer qualified")
	}
	d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /version": reply(200, `{"Version":"4.9.3","Components":[{"Name":"Podman Engine"}]}`)})
	if _, e = d.CreateContainer(context.Background(), "no", Spec{}); e == nil {
		t.Fatal("remote Podman accepted")
	}
}
func TestPodmanNormalizesOnlyKnownProfileEcho(t *testing.T){
 path:="/run/user/1002/oyzu-fleet-sandbox/known.json"
 if !podmanEchoedOptions([]string{"no-new-privileges","seccomp="+path},path){t.Fatal("native normalized echo refused")}
 for _,options:=range [][]string{{"no-new-privileges","seccomp=/tmp/arbitrary"},{"no-new-privileges:false","seccomp="+path},{"no-new-privileges","seccomp="+path,"apparmor=unconfined"}}{if podmanEchoedOptions(options,path){t.Fatalf("unqualified echo accepted: %v",options)}}
}
func expectedOCISeccomp(t *testing.T) json.RawMessage {
	t.Helper()
	var input struct {
		DefaultAction   string        `json:"defaultAction"`
		DefaultErrnoRet uint          `json:"defaultErrnoRet"`
		Syscalls        []seccompRule `json:"syscalls"`
	}
	if e := json.Unmarshal([]byte(daemonlessSyscallPolicy), &input); e != nil {
		t.Fatal(e)
	}
	var rules []seccompRule
	for _, r := range input.Syscalls {
		if len(r.Includes.Caps) > 0 || len(r.Includes.Arches) > 0 && !containsArch(r.Includes.Arches) || containsArch(r.Excludes.Arches) {
			continue
		}
		r.Includes = seccompRule{}.Includes
		r.Excludes = seccompRule{}.Excludes
		rules = append(rules, r)
	}
	b, e := json.Marshal(map[string]any{"defaultAction": input.DefaultAction, "defaultErrnoRet": input.DefaultErrnoRet, "architectures": []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}, "syscalls": rules})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func containsArch(a []string) bool {
	for _, s := range a {
		if s == "amd64" {
			return true
		}
	}
	return false
}
func TestPodmanAppliedOCIRejectsControlDrift(t *testing.T) {
	var o ociSandbox
	o.Process.User.UID = 1000
	o.Process.User.GID = 1000
	o.Process.NoNewPrivileges = true
	b, _ := json.Marshal(map[string]any{"mounts": []any{map[string]any{"destination": "/sys", "type": "sysfs", "options": []string{"ro", "nosuid", "nodev", "noexec"}}}, "linux": map[string]any{"maskedPaths": containerSandboxPolicy().MaskedPaths, "namespaces": []any{map[string]string{"type": "pid"}, map[string]string{"type": "ipc"}, map[string]string{"type": "uts"}, map[string]string{"type": "mount"}, map[string]string{"type": "cgroup"}, map[string]string{"type": "network"}}}})
	_ = json.Unmarshal(b, &o)
	o.Linux.Seccomp = expectedOCISeccomp(t)
	if e := verifyPodmanOCI(o, "1000:1000"); e != nil {
		t.Fatal(e)
	}
	for _, drift := range []string{"NNP", "caps", "proc", "namespace", "sys", "seccomp"} {
		copy := o
		data, _ := json.Marshal(o)
		_ = json.Unmarshal(data, &copy)
		switch drift {
		case "NNP":
			copy.Process.NoNewPrivileges = false
		case "caps":
			copy.Process.Capabilities = map[string][]string{"effective": {"CAP_SYS_ADMIN"}}
		case "proc":
			copy.Linux.ReadonlyPaths = []string{"/proc/sys"}
		case "namespace":
			copy.Linux.Namespaces[0].Path = "/proc/1/ns/pid"
		case "sys":
			copy.Mounts[0].Options = []string{"rw"}
		case "seccomp":
			copy.Linux.Seccomp = []byte(strings.Replace(string(copy.Linux.Seccomp), "SCMP_ACT_ERRNO", "SCMP_ACT_ALLOW", 1))
		}
		if verifyPodmanOCI(copy, "1000:1000") == nil {
			t.Fatalf("accepted %s drift", drift)
		}
	}
}
