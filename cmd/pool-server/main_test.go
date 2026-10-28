package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenSubcommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"callers":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	previousArgs, previousOut := os.Args, os.Stdout
	defer func() { os.Args, os.Stdout = previousArgs, previousOut }()
	invoke := func(action string) string {
		t.Helper()
		rd, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = wr
		os.Args = []string{"pool-server", "token", action, "--config", path, "--name", "alice"}
		err = run()
		wr.Close()
		b, _ := io.ReadAll(rd)
		rd.Close()
		if err != nil {
			t.Fatal(action, err)
		}
		return string(b)
	}
	if token := invoke("create"); !strings.HasPrefix(token, "oyzp_") || strings.Count(token, "\n") != 1 {
		t.Fatal("create output", token)
	}
	if names := invoke("list"); names != "alice\n" {
		t.Fatal("list output", names)
	}
	if output := invoke("revoke"); output != "" {
		t.Fatal("revoke output", output)
	}
	if names := invoke("list"); names != "" {
		t.Fatal("revoked name", names)
	}
}
