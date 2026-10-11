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

func TestTarFlatBoundsSparseFilesBeforeReading(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, _, err := tarFlat(dir, 1024); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestTarFlatCountsHeadersPaddingAndTrailer(t *testing.T) {
	dir := t.TempDir()
	// A 512-byte payload needs a 512-byte header and a 1024-byte trailer.
	if err := os.WriteFile(filepath.Join(dir, "data"), make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{512, 2047} {
		if _, _, err := tarFlat(dir, limit); err == nil {
			t.Fatalf("archive exceeded %d", limit)
		}
	}
	archive, _, err := tarFlat(dir, 2048)
	if err != nil || len(archive) != 2048 {
		t.Fatalf("bytes=%d err=%v", len(archive), err)
	}
}
