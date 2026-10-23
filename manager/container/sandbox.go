package container

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

//go:embed profiles/docker-default.json
var syscallPolicyInput []byte

// This fixed profile supports Oyzu's rootless OCI worker without granting the
// outer job capabilities. Kernel namespace ownership still prevents entering or
// changing the parent's namespaces. There is no caller-provided policy input.
var daemonlessSyscallPolicy = makeDaemonlessPolicy()

func makeDaemonlessPolicy() string {
	var policy map[string]any
	if err := json.Unmarshal(syscallPolicyInput, &policy); err != nil {
		panic("invalid embedded container syscall policy")
	}
	rules := policy["syscalls"].([]any)
	rules = append(rules,
		map[string]any{
			"names":   []string{"clone", "unshare", "mount", "umount2", "pivot_root", "sethostname"},
			"action":  "SCMP_ACT_ALLOW",
			"comment": "Fleet daemonless OCI v1: rootless namespace setup; outer capabilities remain empty",
		},
		map[string]any{
			"names": []string{"keyctl"}, "action": "SCMP_ACT_ALLOW",
			"args":    []any{map[string]any{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}},
			"comment": "Fleet daemonless OCI v1: KEYCTL_JOIN_SESSION_KEYRING only; read, link and other operations remain denied",
		},
	)
	policy["syscalls"] = rules
	data, err := json.Marshal(policy)
	if err != nil {
		panic("invalid embedded daemonless syscall policy")
	}
	return string(data)
}

type sandboxPolicy struct {
	CapDrop, CapAdd, SecurityOpt, MaskedPaths, ReadonlyPaths []string
	PidMode, IpcMode, UTSMode, CgroupnsMode, UsernsMode      string
}

func containerSandboxPolicy() sandboxPolicy {
	return sandboxPolicy{
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + daemonlessSyscallPolicy},
		// Outer proc submounts make a new private proc mount impossible in a
		// descendant user namespace. Proc access retains non-root kernel/DAC
		// checks; the OCI worker mounts and restricts its own private proc.
		MaskedPaths:   []string{"/sys/firmware", "/sys/devices/virtual/powercap"},
		ReadonlyPaths: []string{"/sys"},
		IpcMode:       "private", CgroupnsMode: "private",
	}
}

func sandboxPolicyFingerprint() string {
	data, _ := json.Marshal(struct {
		Version string
		Policy  sandboxPolicy
	}{"daemonless-oci-v1", containerSandboxPolicy()})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (p sandboxPolicy) applied() bool {
	expected := containerSandboxPolicy()
	if len(p.CapAdd) != 0 || !sameStrings(p.CapDrop, expected.CapDrop) ||
		!sameStrings(p.MaskedPaths, expected.MaskedPaths) || !sameStrings(p.ReadonlyPaths, expected.ReadonlyPaths) ||
		len(p.SecurityOpt) != 2 {
		return false
	}
	for _, mode := range []string{p.PidMode, p.IpcMode, p.UTSMode, p.CgroupnsMode} {
		if mode != "" && mode != "private" {
			return false
		}
	}
	if p.UsernsMode != "" {
		return false
	}
	nnp, seccomp := false, false
	for _, option := range p.SecurityOpt {
		if option == "no-new-privileges:true" {
			if nnp {
				return false
			}
			nnp = true
			continue
		}
		value, ok := strings.CutPrefix(option, "seccomp=")
		if !ok || seccomp {
			return false
		}
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) != nil {
			return false
		}
		canonical, err := json.Marshal(decoded)
		if err != nil || string(canonical) != daemonlessSyscallPolicy {
			return false
		}
		seccomp = true
	}
	return nnp && seccomp
}
