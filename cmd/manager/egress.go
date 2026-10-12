package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// egressFile records a manager's egress mode in its state directory, so the
// default is decided once: a manager enrolled by this version enforces,
// while one that was already enrolled when egress control arrived starts in
// report mode, which changes nothing for its jobs but logs what enforcing
// would block. An operator moves it on with --egress enforce.
const egressFile = "egress"

// Egress modes, as --egress spells them.
const (
	egressEnforce = "enforce"
	egressReport  = "report"
	egressOpen    = "open"
)

// readEgress returns the mode recorded in the state directory, or "".
func readEgress(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, egressFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeEgress(stateDir, mode string) error {
	return os.WriteFile(filepath.Join(stateDir, egressFile), []byte(mode+"\n"), 0o600)
}

// recordNewEgress makes enforce the recorded mode of a manager that has just
// been enrolled, unless it was already enrolled before.
func recordNewEgress(stateDir string, existed bool) error {
	if existed || readEgress(stateDir) != "" {
		return nil
	}
	return writeEgress(stateDir, egressEnforce)
}

// resolveEgress picks the mode a container or kubernetes manager runs in. An
// explicit --egress wins and is remembered. Otherwise the recorded mode
// applies; a manager with none was enrolled before egress control, and runs
// in report mode, or open if it was given a --network, which only open
// allows.
func resolveEgress(flagValue, stateDir string, networkSet bool) (mode, why string, err error) {
	switch flagValue {
	case "":
	case egressEnforce, egressReport, egressOpen:
		if err := writeEgress(stateDir, flagValue); err != nil {
			return "", "", fmt.Errorf("record the egress mode: %w", err)
		}
		return flagValue, "from --egress", nil
	default:
		return "", "", fmt.Errorf("--egress %q: use enforce, report or open", flagValue)
	}
	switch m := readEgress(stateDir); m {
	case egressEnforce, egressReport, egressOpen:
		return m, "recorded in the state directory", nil
	case "":
		if networkSet {
			return egressOpen, "this manager predates egress control and was given --network", nil
		}
		if err := writeEgress(stateDir, egressReport); err != nil {
			return "", "", fmt.Errorf("record the egress mode: %w", err)
		}
		return egressReport, "this manager predates egress control; pass --egress enforce to block what it logs", nil
	default:
		return "", "", fmt.Errorf("%s holds %q, not enforce, report or open", filepath.Join(stateDir, egressFile), m)
	}
}

// checkEngineForEgress refuses an engine whose published ports the manager
// cannot reach: the gateway's control port is published on the engine
// host's loopback address.
func checkEngineForEgress(engine string) error {
	if engine == "" || strings.HasPrefix(engine, "unix:") || strings.HasPrefix(engine, "npipe:") {
		return nil
	}
	u, err := url.Parse(engine)
	if err != nil {
		return nil
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); h == "localhost" || ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("egress control needs the engine on this machine: the gateway's control port is published on the engine host's loopback address; use a local socket, or --egress open")
}
