package kindrunner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlanFilesRoundTrip(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "terraform.tfplan"), []byte("plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	archive, n, err := tarFlat(src, maxPlanFiles)
	if err != nil || n != 1 {
		t.Fatalf("tar: %d %v", n, err)
	}
	dst := t.TempDir()
	if err := untarFlat(archive, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "terraform.tfplan")); string(b) != "plan" {
		t.Fatalf("unpacked %q", b)
	}
	empty, n, err := tarFlat(t.TempDir(), maxPlanFiles)
	if err != nil || n != 0 || len(empty) == 0 {
		t.Fatalf("empty dir: %d %v", n, err)
	}
}
