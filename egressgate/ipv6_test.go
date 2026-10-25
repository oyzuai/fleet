package egressgate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIPv6StateIsDisabledOnlyWhenTheKernelSaysSo(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, c := range []struct {
		name, path, want string
		fails            bool
	}{
		{name: "booted with ipv6.disable=1", path: write("one", "1\n"), want: IPv6Disabled},
		{name: "IPv6 on", path: write("zero", "0\n"), want: IPv6Available},
		{name: "module not loaded", path: filepath.Join(dir, "missing"), want: IPv6Available},
		{name: "unexpected value", path: write("other", "yes\n"), fails: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := ipv6State(c.path)
			if c.fails {
				if err == nil || got == IPv6Disabled {
					t.Fatalf("got %q, %v; want an error", got, err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
