//go:build linux

// This native fixture checks the real nested OCI boundary. It is not an Oyzu
// build or a substitute for admitted contribution verification.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const payload = "native rootless OCI process succeeded\n"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, required := range []string{"CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !strings.Contains(string(status), required) {
			return fmt.Errorf("missing actual process control: %s", required)
		}
	}
	if len(os.Args) == 2 && os.Args[1] == "inner" {
		if os.Getpid() != 1 {
			return fmt.Errorf("OCI process is not in its private PID namespace")
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		if len(interfaces) != 1 || interfaces[0].Name != "lo" {
			return fmt.Errorf("OCI process has an external network attachment")
		}
		return os.WriteFile("/output/result.txt", []byte(payload), 0o600)
	}
	// Invalid, effect-free arguments distinguish denied calls without making
	// kernel changes or reading any real key. The OCI runtime may only join a
	// session keyring; build code never receives keyring read permission.
	if _, _, errno := syscall.Syscall6(syscall.SYS_KEYCTL, 11, 0, 0, 0, 0, 0); errno != syscall.EPERM {
		return fmt.Errorf("keyctl read is not denied: %v", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWNET, 0, 0); errno != syscall.EPERM {
		return fmt.Errorf("outer network namespace ownership is not enforced: %v", errno)
	}
	for _, path := range []string{"/work/bundle", "/work/output"} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	noCaps := map[string]any{}
	for _, name := range []string{"bounding", "effective", "inheritable", "permitted", "ambient"} {
		noCaps[name] = []string{}
	}
	namespaces := []map[string]string{}
	for _, name := range []string{"pid", "network", "ipc", "uts", "mount", "user"} {
		namespaces = append(namespaces, map[string]string{"type": name})
	}
	spec := map[string]any{
		"ociVersion": "1.0.2", "hostname": "fleet-rootless-proof",
		"process": map[string]any{"terminal": false, "user": map[string]int{"uid": 1000, "gid": 1000}, "args": []string{"/probe", "inner"}, "cwd": "/", "env": []string{"PATH=/usr/bin:/bin"}, "capabilities": noCaps, "noNewPrivileges": true},
		"root":    map[string]any{"path": "/rootfs", "readonly": true},
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc", "options": []string{"nosuid", "nodev", "noexec"}},
			{"destination": "/output", "type": "bind", "source": "/work/output", "options": []string{"rbind", "rw", "nosuid", "nodev"}},
		},
		"linux": map[string]any{"uidMappings": []map[string]int{{"containerID": 1000, "hostID": 1000, "size": 1}}, "gidMappings": []map[string]int{{"containerID": 1000, "hostID": 1000, "size": 1}}, "namespaces": namespaces},
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/work/bundle/config.json", raw, 0o600); err != nil {
		return err
	}
	command := exec.Command("/crun", "--root", "/work/crun-state", "--cgroup-manager=disabled", "run", "--bundle", "/work/bundle", "fleet-rootless-proof")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return err
	}
	result, err := os.ReadFile("/work/output/result.txt")
	if err != nil {
		return err
	}
	if string(result) != payload {
		return fmt.Errorf("native output differs")
	}
	digest := sha256.Sum256(result)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": "passed", "native_output_sha256": hex.EncodeToString(digest[:]), "outer_capabilities_empty": true, "no_new_privileges": true, "private_pid_network": true, "keyctl_read_denied": true})
}
