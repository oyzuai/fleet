//go:build !linux

package executor

import (
	"errors"
	"time"
)

func snapshotLinkTime(string, time.Time) error {
	return errors.New("snapshot link restoration requires Linux")
}
