//go:build !unix

package poolserver

import (
	"errors"
	"os"
)

func checkRootOwner(os.FileInfo) error {
	return errors.New("pool-server requires Unix file ownership checks")
}
