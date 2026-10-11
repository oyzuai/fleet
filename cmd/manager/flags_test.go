package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDriverFlags(t *testing.T) {
	cases := []struct {
		driver string
		set    []string
		bad    string // "" for accepted, else a substring of the error
	}{
		{"container", nil, ""},
		{"container", []string{"image", "cpus", "network", "user", "engine"}, ""},
		{"container", []string{"renovate"}, "--renovate"},
		{"container", []string{"pass-env", "oyzu"}, "--oyzu"},
		{"container", []string{"docker"}, "--docker"},
		{"kubernetes", []string{"image", "namespace", "docker", "disk-gib"}, ""},
		{"kubernetes", []string{"network"}, "--network"},
		{"process", []string{"renovate", "pass-env", "oyzu", "docker", "work-dir"}, ""},
		{"process", []string{"image"}, "--image"},
		{"process", []string{"cpus"}, "--cpus"},
	}
	for _, c := range cases {
		set := map[string]bool{}
		for _, n := range c.set {
			set[n] = true
		}
		err := checkDriverFlags(c.driver, set)
		switch {
		case c.bad == "" && err != nil:
			t.Errorf("%s %v: unexpected error %v", c.driver, c.set, err)
		case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s %v: error = %v, want mention of %s", c.driver, c.set, err, c.bad)
		}
	}
}

func TestAbsPathAndCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	if got, _ := absPath("jobs"); !filepath.IsAbs(got) {
		t.Errorf("absPath(jobs) = %q", got)
	}
	if got, _ := absPath(""); got != "" {
		t.Errorf("absPath(\"\") = %q", got)
	}
	if got, _ := absCommand("oyzu"); got != "oyzu" {
		t.Errorf("a bare command name must stay for PATH lookup, got %q", got)
	}
	if got, _ := absCommand("./bin/oyzu"); !filepath.IsAbs(got) {
		t.Errorf("absCommand(./bin/oyzu) = %q", got)
	}
}
