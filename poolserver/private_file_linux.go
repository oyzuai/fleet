//go:build linux

package poolserver

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const systemdCredentials = "/run/credentials/oyzu-pool-server.service"

func openPrivateFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private file requires a clean absolute path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	if e == nil {
		e = checkRootOwner(info)
	}
	if e == nil && !info.Mode().IsRegular() {
		e = errors.New("private file must be regular")
	}
	if e == nil && info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 {
		if info.Mode().Perm() != 0440 || !protectedCredential(f, path) {
			e = errors.New("expected private0400/0600 file or protected systemd credential ACL")
		}
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func protectedCredential(f *os.File, path string) bool {
	if os.Getenv("CREDENTIALS_DIRECTORY") != systemdCredentials || filepath.Dir(path) != systemdCredentials {
		return false
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != 0x01021994 || fs.Flags&15 != 15 {
		return false
	}
	i, e := f.Stat()
	if e != nil {
		return false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return false
	}
	// Every traversed directory is real and not group/world writable. The final
	// mount is root-owned0550 on systemd255 (its ACL grants service traversal).
	for dir := filepath.Dir(path); dir != "/"; dir = filepath.Dir(dir) {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return false
		}
	}
	mount, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return false
	}
	defer mount.Close()
	scan := bufio.NewScanner(mount)
	qualified := false
	for scan.Scan() {
		parts := strings.Fields(scan.Text())
		if len(parts) < 10 || parts[4] != systemdCredentials {
			continue
		}
		sep := -1
		for j, v := range parts {
			if v == "-" {
				sep = j
				break
			}
		}
		if sep < 0 || sep+1 >= len(parts) || parts[sep+1] != "tmpfs" {
			return false
		}
		opts := strings.Split(parts[5], ",")
		qualified = contains(opts, "ro") && contains(opts, "nosuid") && contains(opts, "nodev") && contains(opts, "noexec") && contains(opts, "nosymfollow")
	}
	if scan.Err() != nil || !qualified {
		return false
	}
	acl, err := fileACL(f)
	return err == nil && credentialACL(acl, uint32(os.Geteuid()))
}
func fileACL(f *os.File) ([]byte, error) {
	name, e := syscall.BytePtrFromString("system.posix_acl_access")
	if e != nil {
		return nil, e
	}
	buf := make([]byte, 256)
	n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, f.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return buf[:int(n)], nil
}
func credentialACL(b []byte, uid uint32) bool {
	if len(b) != 4+5*8 || binary.LittleEndian.Uint32(b[:4]) != 2 || uid == 0 {
		return false
	}
	seen := map[uint16]bool{}
	for p := 4; p < len(b); p += 8 {
		tag := binary.LittleEndian.Uint16(b[p:])
		perm := binary.LittleEndian.Uint16(b[p+2:])
		id := binary.LittleEndian.Uint32(b[p+4:])
		if seen[tag] {
			return false
		}
		seen[tag] = true
		switch tag {
		case 1, 16:
			if perm != 4 || id != ^uint32(0) {
				return false
			}
		case 2:
			if perm != 4 || id != uid {
				return false
			}
		case 4, 32:
			if perm != 0 || id != ^uint32(0) {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 5
}
