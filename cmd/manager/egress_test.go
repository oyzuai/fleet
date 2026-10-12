package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressFlagBelongsToContainerAndKubernetes(t *testing.T) {
	for driver, bad := range map[string]bool{"container": false, "kubernetes": false, "process": true} {
		err := checkDriverFlags(driver, map[string]bool{"egress": true})
		if (err != nil) != bad {
			t.Errorf("%s: --egress error = %v", driver, err)
		}
	}
}

func TestANewlyEnrolledManagerEnforcesAndAnOlderOneReports(t *testing.T) {
	// Enrolled by this version: enforce.
	fresh := t.TempDir()
	if err := recordNewEgress(fresh, false); err != nil {
		t.Fatal(err)
	}
	if m, _, err := resolveEgress("", fresh, false); err != nil || m != "enforce" {
		t.Fatalf("new manager = %q, %v", m, err)
	}
	// A rekey of an existing manager records nothing.
	older := t.TempDir()
	if err := recordNewEgress(older, true); err != nil {
		t.Fatal(err)
	}
	if readEgress(older) != "" {
		t.Fatal("a rekey recorded a mode")
	}
	// With no record the manager predates egress control: report, and it stays.
	m, why, err := resolveEgress("", older, false)
	if err != nil || m != "report" || !strings.Contains(why, "predates") {
		t.Fatalf("older manager = %q, %q, %v", m, why, err)
	}
	if readEgress(older) != "report" {
		t.Fatal("the report default was not recorded")
	}
	// An older manager configured with --network keeps working, open.
	custom := t.TempDir()
	if m, _, err := resolveEgress("", custom, true); err != nil || m != "open" {
		t.Fatalf("older manager with --network = %q, %v", m, err)
	}
	if readEgress(custom) != "" {
		t.Fatal("a mode was recorded for it")
	}
}

func TestAnExplicitEgressFlagWinsAndIsRemembered(t *testing.T) {
	dir := t.TempDir()
	if m, _, err := resolveEgress("enforce", dir, false); err != nil || m != "enforce" {
		t.Fatalf("explicit = %q, %v", m, err)
	}
	if m, _, _ := resolveEgress("", dir, false); m != "enforce" {
		t.Fatalf("remembered = %q", m)
	}
	if m, _, _ := resolveEgress("open", dir, true); m != "open" {
		t.Fatalf("explicit open = %q", m)
	}
	if _, _, err := resolveEgress("strict", dir, false); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "egress"), []byte("nonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveEgress("", dir, false); err == nil {
		t.Fatal("a corrupt record was accepted")
	}
}

func TestEgressNeedsALocalEngine(t *testing.T) {
	for engine, ok := range map[string]bool{
		"": true, "unix:///var/run/docker.sock": true, "npipe:////./pipe/docker_engine": true,
		"tcp://127.0.0.1:2375": true, "tcp://localhost:2376": true, "tcp://[::1]:2375": true,
		"tcp://build-host:2376": false, "https://10.0.0.5:2376": false,
	} {
		if err := checkEngineForEgress(engine); (err == nil) != ok {
			t.Errorf("checkEngineForEgress(%q) = %v", engine, err)
		}
	}
}
