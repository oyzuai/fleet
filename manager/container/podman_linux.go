//go:build linux

package container

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type podmanProfile struct {
	path, socket string
	identity     podmanIdentity
	peer         func(context.Context, string) (podmanIdentity, error)
	shared       func(*podmanProfile) error
}
type podmanIdentity struct {
	pid   int32
	start string
}

func processStart(pid int32) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return "", errors.New("invalid process metadata")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("incomplete process metadata")
	}
	return fields[19], nil
}

func qualifyPodmanPeer(ctx context.Context, socket string) (podmanIdentity, error) {
	var zero podmanIdentity
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return zero, errors.New("not a Unix engine connection")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return zero, err
	}
	var cred *syscall.Ucred
	var sockerr error
	err = raw.Control(func(fd uintptr) {
		cred, sockerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || sockerr != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) {
		return zero, errors.New("Podman service must run as the manager's effective UID")
	}
	start, err := processStart(cred.Pid)
	if err != nil {
		return zero, err
	}
	socketInfo, err := os.Lstat(socket)
	if err != nil {
		return zero, err
	}
	socketOwner, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || socketInfo.Mode()&os.ModeSocket == 0 || socketOwner.Uid != cred.Uid {
		return zero, errors.New("Podman socket owner differs from its peer UID")
	}
	proc := fmt.Sprintf("/proc/%d", cred.Pid)
	exe, err := os.Open(proc + "/exe")
	if err != nil {
		return zero, err
	}
	defer exe.Close()
	info, err := exe.Stat()
	if err != nil {
		return zero, err
	}
	trusted, err := openNoSymlinks("/usr/bin/podman", syscall.O_RDONLY)
	if err != nil {
		return zero, err
	}
	defer trusted.Close()
	trustedInfo, err := trusted.Stat()
	if err != nil || !os.SameFile(info, trustedInfo) {
		return zero, errors.New("Unix peer is not the trusted directly-bound /usr/bin/podman; proxies/socket activation are unqualified")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return zero, errors.New("Podman executable must be root-owned and not group/world writable")
	}
	for _, name := range []string{"ns/pid", "root"} {
		a, e := os.Stat(proc + "/" + name)
		b, f := os.Stat("/proc/self/" + name)
		if e != nil || f != nil || !os.SameFile(a, b) {
			return zero, errors.New("Podman and manager must share host PID namespace and filesystem root")
		}
	}
	// Kernel-reported UIDs are relative to this manager's user namespace. A
	// rootless daemon may have an internal UID0, but its effective host UID
	// must be exactly this manager and be covered by its kernel UID mapping.
	status, err := os.ReadFile(proc + "/status")
	if err != nil {
		return zero, err
	}
	effective := ""
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "Uid:" {
			effective = fields[2]
		}
	}
	if effective != strconv.Itoa(os.Geteuid()) {
		return zero, errors.New("Podman effective host UID differs")
	}
	mapping, err := os.ReadFile(proc + "/uid_map")
	if err != nil {
		return zero, err
	}
	mapped := false
	for _, line := range strings.Split(string(mapping), "\n") {
		v := strings.Fields(line)
		if len(v) != 3 {
			continue
		}
		outer, e := strconv.ParseUint(v[1], 10, 64)
		count, f := strconv.ParseUint(v[2], 10, 64)
		uid := uint64(cred.Uid)
		if e == nil && f == nil && uid >= outer && uid-outer < count {
			mapped = true
		}
	}
	if !mapped {
		return zero, errors.New("Podman UID mapping does not cover its host identity")
	}
	after, err := processStart(cred.Pid)
	if err != nil || after != start {
		return zero, errors.New("Podman peer identity changed during qualification")
	}
	return podmanIdentity{pid: cred.Pid, start: start}, nil
}

// openNoSymlinks traverses every component with openat(O_NOFOLLOW), retaining
// directory handles across lookups. No config, engine response or environment
// path can redirect a profile/config read through a symlink.
func openNoSymlinks(path string, flags int) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("expected a clean absolute path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		f := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_DIRECTORY
		if i == len(parts)-1 {
			f = flags | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		}
		next, e := syscall.Openat(fd, part, f, 0)
		_ = syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
func privateOwned(f *os.File, dir bool) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !ok || st.Uid != uint32(os.Geteuid()) || dir && (!info.IsDir() || mode != 0700) || !dir && (!info.Mode().IsRegular() || (mode != 0600 && mode != 0400)) {
		return errors.New("managed Podman policy requires private files/directories owned by the manager UID")
	}
	return nil
}
func newPodmanProfile(ctx context.Context, socket string) (*podmanProfile, error) {
	return newPodmanProfileForPeer(ctx, socket, qualifyPodmanPeer, validateSharedProfile)
}
func newPodmanProfileForPeer(ctx context.Context, socket string, peer func(context.Context, string) (podmanIdentity, error), shared func(*podmanProfile) error) (*podmanProfile, error) {
	identity, e := peer(ctx, socket)
	if e != nil {
		return nil, e
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	root, e := openNoSymlinks(base, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if e != nil {
		return nil, errors.New("Podman requires a private XDG_RUNTIME_DIR without symlinks")
	}
	defer root.Close()
	if e = privateOwned(root, true); e != nil {
		return nil, e
	}
	const dirname = "oyzu-fleet-sandbox"
	if e = syscall.Mkdirat(int(root.Fd()), dirname, 0700); e != nil && !errors.Is(e, syscall.EEXIST) {
		return nil, e
	}
	dirpath := filepath.Join(base, dirname)
	dir, e := openNoSymlinks(dirpath, syscall.O_RDONLY|syscall.O_DIRECTORY)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	if e = privateOwned(dir, true); e != nil {
		return nil, e
	}
	h := sha256.Sum256([]byte(daemonlessSyscallPolicy))
	name := "daemonless-" + hex.EncodeToString(h[:]) + ".json"
	path := filepath.Join(dirpath, name)
	if _, e = os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return nil, e
		}
		tmp := filepath.Join(dirpath, ".policy-"+hex.EncodeToString(nonce[:]))
		fd, e := syscall.Openat(int(dir.Fd()), filepath.Base(tmp), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return nil, e
		}
		f := os.NewFile(uintptr(fd), tmp)
		defer os.Remove(tmp)
		_, e = io.WriteString(f, daemonlessSyscallPolicy)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return nil, e
		}
		if e = os.Link(tmp, path); e != nil && !errors.Is(e, os.ErrExist) {
			return nil, e
		}
		if e = dir.Sync(); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	p := &podmanProfile{path: path, socket: socket, identity: identity, peer: peer, shared: shared}
	if e = p.validate(); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *podmanProfile) validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCallTimeout)
	defer cancel()
	identity, e := p.peer(ctx, p.socket)
	if e != nil || identity != p.identity {
		return errors.New("Podman endpoint identity changed or is unqualified")
	}
	base, e := openNoSymlinks(filepath.Dir(filepath.Dir(p.path)), syscall.O_RDONLY|syscall.O_DIRECTORY)
	if e != nil {
		return e
	}
	defer base.Close()
	if e = privateOwned(base, true); e != nil {
		return e
	}
	dir, e := openNoSymlinks(filepath.Dir(p.path), syscall.O_RDONLY|syscall.O_DIRECTORY)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = privateOwned(dir, true); e != nil {
		return e
	}
	f, e := openNoSymlinks(p.path, syscall.O_RDONLY)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = privateOwned(f, false); e != nil {
		return e
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(len(daemonlessSyscallPolicy)+1)))
	if e != nil || !bytes.Equal(b, []byte(daemonlessSyscallPolicy)) {
		return errors.New("managed Podman profile content changed")
	}
	return p.shared(p)
}

func validateSharedProfile(p *podmanProfile) error {
	// /proc/PID/root is the one intentional kernel magic-link anchor. All
	// components after that held descriptor use O_NOFOLLOW. A different mount
	// namespace qualifies only when the actual private directory and fixed file
	// are the very same device/inode on both sides, never a lookalike pathname.
	root, e := syscall.Open(fmt.Sprintf("/proc/%d/root", p.identity.pid), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer syscall.Close(root)
	openPeer := func(path string, flags int) (*os.File, error) {
		fd, e := syscall.Dup(root)
		if e != nil {
			return nil, e
		}
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i, part := range parts {
			f := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
			if i == len(parts)-1 {
				f = flags | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
			}
			next, e := syscall.Openat(fd, part, f, 0)
			syscall.Close(fd)
			if e != nil {
				return nil, e
			}
			fd = next
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	for _, path := range []string{filepath.Dir(p.path), p.path} {
		dir := path != p.path
		flags := syscall.O_RDONLY
		if dir {
			flags |= syscall.O_DIRECTORY
		}
		local, e := openNoSymlinks(path, flags)
		if e != nil {
			return e
		}
		peer, e := openPeer(path, flags)
		if e != nil {
			local.Close()
			return e
		}
		a, ae := local.Stat()
		b, be := peer.Stat()
		local.Close()
		if ae != nil || be != nil || !os.SameFile(a, b) {
			peer.Close()
			return errors.New("Podman and manager do not share the same profile directory/file")
		}
		if e = privateOwned(peer, dir); e != nil {
			peer.Close()
			return e
		}
		if !dir {
			bytesRead, e := io.ReadAll(io.LimitReader(peer, int64(len(daemonlessSyscallPolicy)+1)))
			if e != nil || !bytes.Equal(bytesRead, []byte(daemonlessSyscallPolicy)) {
				peer.Close()
				return errors.New("Podman-visible fixed policy differs")
			}
		}
		peer.Close()
	}
	after, e := processStart(p.identity.pid)
	if e != nil || after != p.identity.start {
		return errors.New("Podman peer was replaced during filesystem validation")
	}
	return nil
}

type ociSandbox struct {
	Root struct { Readonly bool }
	Process struct {
		Args []string
		User            struct{ UID, GID uint32 }
		NoNewPrivileges bool
		Capabilities    map[string][]string
	}
	Mounts []struct {
		Destination, Type, Source string
		Options                   []string
	}
	Linux struct {
		Resources struct {
			Memory struct { Limit, Swap *int64 }
			CPU struct { Quota *int64; Period *uint64 }
			Pids struct { Limit int64 }
		}
		MaskedPaths, ReadonlyPaths []string
		Namespaces                 []struct{ Type, Path string }
		Seccomp                    json.RawMessage
	}
}

func (p *podmanProfile) inspectOCI(path, id, user string) error {
	o, err := p.readOCI(path, id)
	if err != nil { return err }
	return verifyPodmanOCI(o, user)
}
func (p *podmanProfile) readOCI(path, id string) (o ociSandbox, err error) {
	if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" || !strings.HasSuffix(path, "/overlay-containers/"+id+"/userdata/config.json") {
		return o, errors.New("Podman supplied an unqualified OCI config path")
	}
	f, e := openNoSymlinks(path, syscall.O_RDONLY)
	if e != nil {
		return o, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return o, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return o, errors.New("untrusted Podman OCI configuration")
	}
	if e = json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&o); e != nil {
		return o, e
	}
	for _, n := range o.Linux.Namespaces {
		if n.Type == "network" && n.Path != "" {
			if filepath.Dir(n.Path) != filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "netns") {
				return o, errors.New("unqualified Podman network namespace path")
			}
			ns, e := openNoSymlinks(n.Path, syscall.O_RDONLY)
			if e != nil {
				return o, e
			}
			info, e := ns.Stat()
			ns.Close()
			if e != nil {
				return o, e
			}
			for _, host := range []string{"/proc/self/ns/net", fmt.Sprintf("/proc/%d/ns/net", p.identity.pid)} {
				hostInfo, e := os.Stat(host)
				if e != nil || os.SameFile(info, hostInfo) {
					return o, errors.New("Podman network namespace is not private")
				}
			}
		}
	}
	return o, nil
}

func (p *podmanProfile) hostIdentity() (string, error) {
	if err := p.validate(); err != nil { return "", err }
	return configurationDigest(struct { PID int32; Start string }{p.identity.pid, p.identity.start}), nil
}

func (p *podmanProfile) inspectAnchor(path, id string, spec Spec, pid int) (string, string, error) {
	before, err := processStart(int32(pid))
	if err != nil { return "", "", err }
	o, err := p.readOCI(path, id)
	if err != nil { return "", "", err }
	if err := verifyPodmanOCI(o, spec.User); err != nil { return "", "", err }
	r := o.Linux.Resources
	if !o.Root.Readonly || !slices.Equal(o.Process.Args, spec.Cmd) || r.Memory.Limit == nil || *r.Memory.Limit != spec.MemoryBytes ||
		r.Memory.Swap == nil || *r.Memory.Swap != spec.MemoryBytes || r.Pids.Limit != spec.PidsLimit || r.CPU.Quota == nil || r.CPU.Period == nil ||
		*r.CPU.Period == 0 || *r.CPU.Quota <= 0 || *r.CPU.Quota*1_000_000_000 / int64(*r.CPU.Period) != spec.NanoCPUs {
		return "", "", errors.New("namespace anchor effective OCI command/resources differ")
	}
	namespace := ""
	for _, n := range o.Linux.Namespaces { if n.Type == "network" && n.Path != "" {
		f, err := openNoSymlinks(n.Path, syscall.O_RDONLY); if err != nil { return "", "", err }
		st, err := f.Stat(); f.Close(); if err != nil { return "", "", err }
		stat, ok := st.Sys().(*syscall.Stat_t); if !ok { return "", "", errors.New("unobservable anchor network namespace") }
		namespace = fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	} }
	after, err := processStart(int32(pid))
	if err != nil || before != after || namespace == "" { return "", "", errors.New("namespace anchor process or namespace changed") }
	return namespace, fmt.Sprintf("%d:%s", pid, before), nil
}
func verifyPodmanOCI(o ociSandbox, user string) error {
	uid, gid, ok := strings.Cut(user, ":")
	u, e := strconv.ParseUint(uid, 10, 32)
	g, f := strconv.ParseUint(gid, 10, 32)
	if !ok || e != nil || f != nil || u == 0 || o.Process.User.UID != uint32(u) || o.Process.User.GID != uint32(g) || !o.Process.NoNewPrivileges {
		return errors.New("Podman applied user or NNP differs")
	}
	for _, caps := range o.Process.Capabilities {
		if len(caps) != 0 {
			return errors.New("Podman granted capabilities")
		}
	}
	for _, ns := range []string{"pid", "ipc", "uts", "mount", "cgroup", "network"} {
		found := false
		for _, n := range o.Linux.Namespaces {
			if n.Type == ns && (n.Path == "" || ns == "network") {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("Podman %s namespace is not private", ns)
		}
	}
	actualMasks := slices.Clone(o.Linux.MaskedPaths)
	slices.Sort(actualMasks)
	actualMasks = slices.Compact(actualMasks)
	if !sameStrings(actualMasks, containerSandboxPolicy().MaskedPaths) || len(o.Linux.ReadonlyPaths) != 0 {
		return fmt.Errorf("Podman applied proc/sys path restrictions differ: masked=%v readonly=%v", o.Linux.MaskedPaths, o.Linux.ReadonlyPaths)
	}
	sysro := false
	for _, m := range o.Mounts {
		if m.Destination == "/sys" {
			sysro = m.Type == "sysfs" && slices.Contains(m.Options, "ro") && !slices.Contains(m.Options, "rw")
		}
		if strings.HasPrefix(m.Destination, "/sys/") && (!slices.Contains(m.Options, "ro") || slices.Contains(m.Options, "rw")) {
			return errors.New("Podman /sys submount is writable")
		}
	}
	if !sysro {
		return errors.New("Podman /sys mount is not read-only sysfs")
	}
	if !sameResolvedSeccomp(o.Linux.Seccomp) {
		return errors.New("Podman applied seccomp differs from the fixed policy")
	}
	return nil
}

type seccompArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}
type seccompRule struct {
	Names              []string     `json:"names"`
	Action             string       `json:"action"`
	ErrnoRet           *uint        `json:"errnoRet,omitempty"`
	Args               []seccompArg `json:"args,omitempty"`
	Includes, Excludes struct {
		Caps, Arches []string
		MinKernel    string
	}
}

// Resolve only the fixed empty-capability profile on currently qualified
// amd64 Linux >=4.8. Comparison expands grouped rules so engine ordering does
// not change the policy identity. Other architectures fail closed for now.
func sameResolvedSeccomp(raw json.RawMessage) bool {
	if runtime.GOARCH != "amd64" {
		return false
	}
	var input struct {
		DefaultAction   string
		DefaultErrnoRet uint
		Syscalls        []seccompRule
	}
	var actual struct {
		DefaultAction   string
		DefaultErrnoRet uint
		Architectures   []string
		Syscalls        []seccompRule
	}
	if json.Unmarshal([]byte(daemonlessSyscallPolicy), &input) != nil || json.Unmarshal(raw, &actual) != nil || input.DefaultAction != actual.DefaultAction || input.DefaultErrnoRet != actual.DefaultErrnoRet || !sameStrings(actual.Architectures, []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}) {
		return false
	}
	resolve := func(rules []seccompRule, filter bool) []string {
		var result []string
		for _, r := range rules {
			if filter && (len(r.Includes.Caps) > 0 || len(r.Includes.Arches) > 0 && !slices.Contains(r.Includes.Arches, "amd64") || slices.Contains(r.Excludes.Arches, "amd64")) {
				continue
			}
			for _, name := range r.Names {
				errno := uint(0)
				if r.ErrnoRet != nil {
					errno = *r.ErrnoRet
				}
				b, _ := json.Marshal(struct {
					Name, Action string
					Errno        uint
					Args         []seccompArg
				}{name, r.Action, errno, r.Args})
				result = append(result, string(b))
			}
		}
		slices.Sort(result)
		return result
	}
	return slices.Equal(resolve(input.Syscalls, true), resolve(actual.Syscalls, false))
}
