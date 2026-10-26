package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func snapshotTar(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestSnapshotExtractionPreservesFilesAndRelativeLinks(t *testing.T) {
	root := t.TempDir()
	modified := time.Unix(1720000000, 123456789)
	archive := snapshotTar(t, &tar.Header{Name: "bin", Typeflag: tar.TypeDir, Mode: 0755, ModTime: modified, Format: tar.FormatPAX}, &tar.Header{Name: "bin/tool", Typeflag: tar.TypeReg, Size: 3, Mode: 0751, ModTime: modified, Format: tar.FormatPAX}, &tar.Header{Name: "tool", Typeflag: tar.TypeSymlink, Linkname: "bin/tool", Mode: 0777, ModTime: modified, Format: tar.FormatPAX}, &tar.Header{Name: "self", Typeflag: tar.TypeSymlink, Linkname: ".", Mode: 0777, ModTime: modified, Format: tar.FormatPAX})
	if err := extractSnapshot(root, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "tool"))
	if err != nil || string(b) != "xxx" {
		t.Fatalf("%q %v", b, err)
	}
	info, err := os.Stat(filepath.Join(root, "bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0751 || !info.ModTime().Equal(modified) {
		t.Fatalf("metadata %v %v", info.Mode(), info.ModTime())
	}
	info, err = os.Lstat(filepath.Join(root, "tool"))
	if err != nil || !info.ModTime().Equal(modified) {
		t.Fatalf("link timestamp %v %v", info, err)
	}
}

func TestSnapshotExtractionRefusesEscapesAndSpecialEntries(t *testing.T) {
	for _, h := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/escape", Typeflag: tar.TypeReg},
		{Name: ".git/config", Typeflag: tar.TypeReg}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../escape"},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, {Name: "hard", Typeflag: tar.TypeLink, Linkname: "file"},
		{Name: "device", Typeflag: tar.TypeChar},
	} {
		t.Run(h.Name+string(h.Typeflag), func(t *testing.T) {
			if err := extractSnapshot(t.TempDir(), bytes.NewReader(snapshotTar(t, h))); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	archive := snapshotTar(t, &tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "b"}, &tar.Header{Name: "a/file", Typeflag: tar.TypeReg})
	if err := extractSnapshot(t.TempDir(), bytes.NewReader(archive)); err == nil {
		t.Fatal("write through link accepted")
	}
}

func TestSnapshotDownloadChecksDigestBeforeDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("job credential leaked")
		}
		w.Write([]byte("not zstd"))
	}))
	defer srv.Close()
	cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: t.TempDir()}
	err := restoreSnapshot(context.Background(), cfg, runnerclient.Source{Kind: "snapshot", URL: srv.URL, Digest: "sha256:" + strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("%v", err)
	}
}

func TestSnapshotDownloadDecodesVerifiedArchive(t *testing.T) {
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("executor runtime requires zstd on PATH")
	}
	archive := snapshotTar(t, &tar.Header{Name: "changed", Typeflag: tar.TypeReg, Size: 4, Mode: 0644, ModTime: time.Unix(1720000000, 0)})
	cmd := exec.Command("zstd", "-q", "--stdout")
	cmd.Stdin = bytes.NewReader(archive)
	compressed, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(compressed)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(compressed) }))
	defer srv.Close()
	for _, name := range []string{"ordinary", "read-only-parent"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			workDir := root
			if name == "read-only-parent" {
				if runtime.GOOS != "linux" {
					t.Skip("Linux executor filesystem contract")
				}
				// /proc/self/fd is immutable even for a root test process,
				// unlike a chmod-only fixture. Its directory descriptor names
				// the writable work directory without permitting sibling files.
				dir, err := os.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				defer dir.Close()
				workDir = "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10)
				probe, err := os.CreateTemp(filepath.Dir(workDir), ".source-probe-*")
				if err == nil {
					probe.Close()
					os.Remove(probe.Name())
					t.Fatal("fixture parent unexpectedly permits staging")
				}
			}
			cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: workDir}
			if err := restoreSnapshot(context.Background(), cfg, runnerclient.Source{Kind: "snapshot", URL: srv.URL, Digest: "sha256:" + hex.EncodeToString(h[:])}); err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(root, "changed")); err != nil || string(b) != "xxxx" {
				t.Fatalf("%q %v", b, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "changed" {
				t.Fatalf("archive staging survived restoration: %v %v", entries, err)
			}
		})
	}
}
