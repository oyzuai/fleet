//go:build windows

package container

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// defaultHost is the local engine when no host is given: Docker Desktop's
// named pipe.
const defaultHost = "npipe:////./pipe/docker_engine"

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW        = kernel32.NewProc("CreateEventW")
	procGetOverlappedResult = kernel32.NewProc("GetOverlappedResult")
)

const (
	fileFlagOverlapped     = 0x40000000
	securitySQOSPresent    = 0x00100000
	securityIdentification = 0x00010000
	errorPipeBusy          = syscall.Errno(231)
	errorIOPending         = syscall.Errno(997)
	errorBrokenPipe        = syscall.Errno(109)
	errorOperationAborted  = syscall.Errno(995)
)

// dialPipe opens a named pipe for overlapped I/O, so a read waiting for the
// engine's answer never blocks the next write, as it would on a synchronous
// handle. A busy pipe is retried until ctx ends.
func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	for {
		// SECURITY_IDENTIFICATION stops the engine impersonating the
		// manager's user beyond identifying it.
		h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
			syscall.OPEN_EXISTING, fileFlagOverlapped|securitySQOSPresent|securityIdentification, 0)
		if err == nil {
			return &pipeConn{h: h, path: path}, nil
		}
		if !errors.Is(err, errorPipeBusy) {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// pipeConn is a net.Conn over an overlapped pipe handle. Deadlines are not
// supported; the HTTP client's contexts bound each call instead, and
// closing the handle cancels whatever is in flight.
type pipeConn struct {
	h    syscall.Handle
	path string
	once sync.Once
}

func (c *pipeConn) io(write bool, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	ev, _, err := procCreateEventW.Call(0, 1, 0, 0)
	if ev == 0 {
		return 0, err
	}
	defer syscall.CloseHandle(syscall.Handle(ev))
	ov := &syscall.Overlapped{HEvent: syscall.Handle(ev)}
	var n uint32
	if write {
		err = syscall.WriteFile(c.h, b, &n, ov)
	} else {
		err = syscall.ReadFile(c.h, b, &n, ov)
	}
	if errors.Is(err, errorIOPending) {
		r, _, e := procGetOverlappedResult.Call(uintptr(c.h), uintptr(unsafe.Pointer(ov)), uintptr(unsafe.Pointer(&n)), 1)
		if r == 0 {
			err = e
		} else {
			err = nil
		}
	}
	switch {
	case err == nil:
		if !write && n == 0 {
			return 0, io.EOF
		}
		return int(n), nil
	case errors.Is(err, errorBrokenPipe):
		return int(n), io.EOF
	case errors.Is(err, errorOperationAborted):
		return int(n), net.ErrClosed
	}
	return int(n), &net.OpError{Op: map[bool]string{true: "write", false: "read"}[write], Net: "pipe", Err: err}
}

func (c *pipeConn) Read(b []byte) (int, error) { return c.io(false, b) }

func (c *pipeConn) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.io(true, b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *pipeConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = syscall.CancelIoEx(c.h, nil)
		err = syscall.CloseHandle(c.h)
	})
	return err
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (c *pipeConn) LocalAddr() net.Addr              { return pipeAddr(c.path) }
func (c *pipeConn) RemoteAddr() net.Addr             { return pipeAddr(c.path) }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }
