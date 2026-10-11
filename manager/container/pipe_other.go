//go:build !windows

package container

import (
	"context"
	"errors"
	"net"
)

// defaultHost is the local engine when no host is given.
const defaultHost = "unix:///var/run/docker.sock"

func dialPipe(context.Context, string) (net.Conn, error) {
	return nil, errors.New("container engine: named pipes exist only on Windows; use unix:// or tcp://")
}
