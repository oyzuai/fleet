//go:build !linux && !windows

package manager

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// processStart is when pid started, as ps reports it.
func processStart(pid int) (string, error) {
	out, err := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid)).Output()
	s := strings.TrimSpace(string(out))
	var exit *exec.ExitError
	if s == "" && (err == nil || errors.As(err, &exit)) {
		return "", errProcessGone
	}
	if err != nil {
		return "", err
	}
	return s, nil
}
