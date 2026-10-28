package egressgate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// What `oyzu-executor gateway probe-ipv6` prints about the kernel it runs on.
const (
	// IPv6Disabled means the kernel was booted with IPv6 turned off
	// (ipv6.disable=1): no process or network namespace on it can have an
	// IPv6 address.
	IPv6Disabled = "disabled"
	// IPv6Available means the kernel has IPv6, or can load it on demand.
	IPv6Available = "available"
)

// ipv6ParameterFile holds the kernel's ipv6.disable boot setting. It exists
// when IPv6 is built in or its module is loaded.
const ipv6ParameterFile = "/sys/module/ipv6/parameters/disable"

// ipv6Command implements `gateway probe-ipv6`. The pool manager runs it in
// the executor image, on the engine's own kernel, to learn whether it can
// leave out the sysctls that turn IPv6 off; see the container driver.
func ipv6Command(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: oyzu-executor gateway probe-ipv6")
	}
	state, err := ipv6State(ipv6ParameterFile)
	if err != nil {
		return err
	}
	fmt.Println(state)
	return nil
}

// ipv6State reads the ipv6.disable setting at path. Only a setting of 1 is
// IPv6Disabled. A missing file is IPv6Available: IPv6 is then a module that
// is not loaded yet, and opening an IPv6 socket loads it.
func ipv6State(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return IPv6Available, nil
	}
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(string(raw)) {
	case "1":
		return IPv6Disabled, nil
	case "0":
		return IPv6Available, nil
	}
	return "", fmt.Errorf("%s holds %q, not 0 or 1", path, strings.TrimSpace(string(raw)))
}
