package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeclaresTask(t *testing.T) {
	cases := map[string]struct {
		toml string
		want bool
	}{
		"plain":            {"[tasks.policy-check]\nrun = \"x\"\n", true},
		"trailing comment": {"[tasks.policy-check] # required check\nrun = \"x\"\n", true},
		"spaced":           {"[ tasks.policy-check ]\nrun = \"x\"\n", true},
		"single quoted":    {"[tasks.'policy-check']\nrun = \"x\"\n", true},
		"double quoted":    {"[tasks.\"policy-check\"]\nrun = \"x\"\n", true},
		"inline table":     {"[tasks]\npolicy-check = { run = \"x\" }\n", true},
		"dotted key":       {"tasks.policy-check.run = \"x\"\n", true},
		"other task":       {"[tasks.build]\nrun = \"x\"\n", false},
		"in a string":      {"[tasks.build]\nrun = \"\"\"\n[tasks.policy-check]\n\"\"\"\n", false},
		"no tasks":         {"[project]\nname = \"x\"\n", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "oyzu.toml")
			if err := os.WriteFile(p, []byte(c.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := declaresTask(p, "policy-check")
			if err != nil || got != c.want {
				t.Fatalf("declaresTask = %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

func TestDeclaresTaskMissingAndInvalid(t *testing.T) {
	dir := t.TempDir()
	if got, err := declaresTask(filepath.Join(dir, "oyzu.toml"), "x"); got || err != nil {
		t.Fatalf("missing file = %v, %v; want false, nil", got, err)
	}
	p := filepath.Join(dir, "oyzu.toml")
	if err := os.WriteFile(p, []byte("[tasks.x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := declaresTask(p, "x"); err == nil {
		t.Fatal("a file that does not parse must be an error, not a skip")
	}
}
