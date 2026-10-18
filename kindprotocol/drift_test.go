package kindprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestSchemasMatchCanonicalDigests keeps the embedded schemas equal to the
// canonical oyzu files: testdata/canonical-schemas.sha256 lists their SHA-256
// values as `sha256sum` prints them, recorded from the commit in
// testdata/canonical-source.txt. A schema changed here without changing oyzu
// first, or a stale copy after oyzu moved on, fails this test.
func TestSchemasMatchCanonicalDigests(t *testing.T) {
	list, err := os.ReadFile("testdata/canonical-schemas.sha256")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("bad digest line %q", line)
		}
		want[f[1]] = f[0]
	}
	entries, err := schemaFiles.ReadDir("schema")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		seen++
		b, err := schemaFiles.ReadFile("schema/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want[e.Name()] {
			t.Errorf("%s: sha256 %s, canonical %s", e.Name(), got, want[e.Name()])
		}
	}
	if seen != len(want) {
		t.Errorf("embedded %d schemas, canonical list has %d", seen, len(want))
	}
	src, err := os.ReadFile("testdata/canonical-source.txt")
	if err != nil || !strings.Contains(string(src), "commit: ") {
		t.Fatalf("testdata/canonical-source.txt must record the oyzu commit: %v", err)
	}
}
