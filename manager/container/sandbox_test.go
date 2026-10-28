package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
)

func TestSandboxPolicyProvenanceAndRequiredDenials(t *testing.T) {
	digest := sha256.Sum256(syscallPolicyInput)
	if hex.EncodeToString(digest[:]) != "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6" {
		t.Fatal("upstream syscall policy snapshot changed without a provenance review")
	}
	var policy struct {
		DefaultAction string
		Syscalls      []struct {
			Names    []string
			Action   string
			Includes map[string]any
			Args     []struct {
				Index, Value int
				Op           string
			}
		}
	}
	if err := json.Unmarshal([]byte(daemonlessSyscallPolicy), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatal("syscall policy is not default-deny")
	}
	join := false
	for _, rule := range policy.Syscalls {
		if rule.Action != "SCMP_ACT_ALLOW" || len(rule.Includes) != 0 {
			continue
		}
		for _, name := range []string{"bpf", "setns", "chroot", "reboot", "init_module", "delete_module", "add_key", "request_key"} {
			if slices.Contains(rule.Names, name) {
				t.Fatalf("unconditional permission for %s", name)
			}
		}
		if slices.Contains(rule.Names, "keyctl") {
			if len(rule.Args) != 1 || rule.Args[0].Index != 0 || rule.Args[0].Value != 1 || rule.Args[0].Op != "SCMP_CMP_EQ" {
				t.Fatal("keyctl permission exceeds session-keyring creation")
			}
			join = true
		}
	}
	if !join {
		t.Fatal("rootless runtime cannot create its session keyring")
	}
}

func TestSandboxPolicyAppliedStateRejectsDrift(t *testing.T) {
	valid := containerSandboxPolicy()
	slices.Reverse(valid.SecurityOpt)
	slices.Reverse(valid.MaskedPaths)
	if !valid.applied() {
		t.Fatal("equivalent applied options were rejected")
	}
	for name, alter := range map[string]func(*sandboxPolicy){
		"capability added":         func(p *sandboxPolicy) { p.CapAdd = []string{"SYS_ADMIN"} },
		"capabilities not dropped": func(p *sandboxPolicy) { p.CapDrop = nil },
		"privilege escalation":     func(p *sandboxPolicy) { p.SecurityOpt[0] = "no-new-privileges:false" },
		"unconfined syscalls":      func(p *sandboxPolicy) { p.SecurityOpt[1] = "seccomp=unconfined" },
		"unobserved profile":       func(p *sandboxPolicy) { p.SecurityOpt = p.SecurityOpt[:1] },
		"changed proc policy":      func(p *sandboxPolicy) { p.MaskedPaths = append(p.MaskedPaths, "/proc/keys") },
		"writable sys":             func(p *sandboxPolicy) { p.ReadonlyPaths = nil },
		"extra option":             func(p *sandboxPolicy) { p.SecurityOpt = append(p.SecurityOpt, "apparmor=unconfined") },
		"host PID":                 func(p *sandboxPolicy) { p.PidMode = "host" },
		"shared IPC":               func(p *sandboxPolicy) { p.IpcMode = "container:other" },
		"host UTS":                 func(p *sandboxPolicy) { p.UTSMode = "host" },
		"host cgroup":              func(p *sandboxPolicy) { p.CgroupnsMode = "host" },
		"userns override":          func(p *sandboxPolicy) { p.UsernsMode = "host" },
	} {
		t.Run(name, func(t *testing.T) {
			actual := containerSandboxPolicy()
			alter(&actual)
			if actual.applied() {
				t.Fatal("changed allocation retained measured runtime authority")
			}
		})
	}
}
