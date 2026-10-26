//go:build linux

package executor

import (
	"syscall"
	"time"
	"unsafe"
)

// UTIMENSAT with AT_SYMLINK_NOFOLLOW changes the link's own timestamp without
// touching its target. Snapshot execution is supported on Linux only.
func snapshotLinkTime(name string, modified time.Time) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	ts := syscall.NsecToTimespec(modified.UnixNano())
	times := [2]syscall.Timespec{ts, ts}
	_, _, errno := syscall.Syscall6(syscall.SYS_UTIMENSAT, ^uintptr(99), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&times[0])), 0x100, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
