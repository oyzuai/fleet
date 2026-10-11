package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// driverFlags lists which drivers each driver-specific `run` flag applies to.
// A flag set explicitly for a driver that ignores it is an error, not a no-op.
var driverFlags = map[string][]string{
	"executor":               {"process"},
	"oyzu":                   {"process"},
	"renovate":               {"process"},
	"pass-env":               {"process"},
	"work-dir":               {"process"},
	"kind-state-dir":         {"process"},
	"docker":                 {"process", "kubernetes"},
	"image":                  {"container", "kubernetes"},
	"cpus":                   {"container", "kubernetes"},
	"memory-mib":             {"container", "kubernetes"},
	"engine":                 {"container"},
	"engine-cert-path":       {"container"},
	"engine-allow-plaintext": {"container"},
	"network":                {"container"},
	"user":                   {"container"},
	"namespace":              {"kubernetes"},
	"runtime-class":          {"kubernetes"},
	"node-selector":          {"kubernetes"},
	"disk-gib":               {"kubernetes"},
	"kube-server":            {"kubernetes"},
	"kube-token-file":        {"kubernetes"},
	"kube-ca":                {"kubernetes"},
}

// checkDriverFlags returns an error naming every flag in set that the chosen
// driver would silently ignore.
func checkDriverFlags(driver string, set map[string]bool) error {
	var bad []string
	for name, drivers := range driverFlags {
		if !set[name] {
			continue
		}
		applies := false
		for _, d := range drivers {
			applies = applies || d == driver
		}
		if !applies {
			bad = append(bad, fmt.Sprintf("--%s (%s driver only)", name, strings.Join(drivers, " and ")))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("the %s driver ignores %s", driver, strings.Join(bad, ", "))
}

// absPath makes a path flag absolute so it means the same thing after a child
// process changes its working directory. An empty path stays empty.
func absPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	return filepath.Abs(p)
}

// absCommand makes a command flag absolute only when it names a path; a bare
// name such as "oyzu" is looked up on PATH and stays as it is.
func absCommand(c string) (string, error) {
	if c == "" || !strings.ContainsAny(c, `/\`) {
		return c, nil
	}
	return filepath.Abs(c)
}
