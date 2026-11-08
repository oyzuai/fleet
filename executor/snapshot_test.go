package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/oyzuai/fleet/runnerclient"
)

func snapshotDigest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func snapshotManifest(t *testing.T, entries ...runnerclient.SourceEntry) []byte {
	t.Helper()
	data, err := json.Marshal(runnerclient.SourceManifest{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func snapshotSource(url string, manifest []byte) runnerclient.Source {
	digest := snapshotDigest(manifest)
	return runnerclient.Source{Kind: "snapshot", URL: url + "/accounts/test/sources/" + digest + "?download=test-grant", Digest: digest}
}

func TestSnapshotDownloadRestoresFilesMetadataAndRelativeLinks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux executor filesystem contract")
	}
	content := []byte("changed source")
	blob := snapshotDigest(content)
	modified := time.Unix(1720000000, 123456789)
	manifest := snapshotManifest(t,
		runnerclient.SourceEntry{Path: "bin", Kind: "directory", Mode: 0750, Mtime: modified.UnixNano()},
		runnerclient.SourceEntry{Path: "bin/tool", Kind: "file", Mode: 0751, Mtime: modified.UnixNano(), Size: int64(len(content)), Digest: blob},
		runnerclient.SourceEntry{Path: "self", Kind: "symlink", Target: "."},
		runnerclient.SourceEntry{Path: "tool", Kind: "symlink", Target: "bin/tool"},
	)
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	compressed := encoder.EncodeAll(content, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Query().Get("download") != "test-grant" {
			t.Error("download leaked job bearer or lost source grant")
		}
		if strings.Contains(r.URL.Path, "/sources/") {
			_, _ = w.Write(manifest)
		} else if strings.HasSuffix(r.URL.Path, "/blobs/"+blob) {
			w.Header().Set("Content-Encoding", "zstd")
			_, _ = w.Write(compressed)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	for _, name := range []string{"ordinary", "read-only-parent"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			workDir := root
			if name == "read-only-parent" {
				dir, err := os.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				defer dir.Close()
				workDir = "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10)
			}
			cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: workDir}
			if err := restoreSnapshot(context.Background(), cfg, snapshotSource(srv.URL, manifest)); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(root, "tool"))
			if err != nil || !bytes.Equal(got, content) {
				t.Fatalf("restored file %q %v", got, err)
			}
			for path, mode := range map[string]os.FileMode{"bin": 0750, "bin/tool": 0751} {
				info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode || !info.ModTime().Equal(modified) {
					t.Fatalf("metadata %s %v %v", path, info.Mode(), info.ModTime())
				}
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 3 {
				t.Fatalf("unexpected staging files %v %v", entries, err)
			}
		})
	}
}

func TestSnapshotDownloadVerifiesManifestAndEveryBlob(t *testing.T) {
	for _, mode := range []string{"manifest-digest", "manifest-invalid", "blob-digest", "blob-size", "link-unresolved"} {
		t.Run(mode, func(t *testing.T) {
			content := []byte("expected")
			manifest := snapshotManifest(t, runnerclient.SourceEntry{Path: "file", Kind: "file", Mode: 0644, Size: int64(len(content)), Digest: snapshotDigest(content)})
			if mode == "manifest-invalid" {
				manifest = []byte(`{"entries":[],"unknown":1}`)
			}
			if mode == "link-unresolved" {
				manifest = snapshotManifest(t, runnerclient.SourceEntry{Path: "link", Kind: "symlink", Target: "missing"})
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/sources/") {
					if mode == "manifest-digest" {
						_, _ = w.Write([]byte("incorrect manifest"))
					} else {
						_, _ = w.Write(manifest)
					}
				} else if mode == "blob-size" {
					_, _ = w.Write(append(content, 'x'))
				} else {
					_, _ = w.Write([]byte("tampered"))
				}
			}))
			defer srv.Close()
			cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: t.TempDir()}
			if err := restoreSnapshot(context.Background(), cfg, snapshotSource(srv.URL, manifest)); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}

func TestSnapshotZstdBlobValidation(t *testing.T) {
	// Span several blocks and a small window so streaming history must wrap.
	content := bytes.Repeat([]byte("snapshot source with repeated cross-block matches\n"), 32768)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(128<<10))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	compressed := encoder.EncodeAll(content, nil)
	for _, mode := range []string{"valid", "malformed", "two-block-huffman", "truncated", "checksum", "size", "digest"} {
		t.Run(mode, func(t *testing.T) {
			entry := runnerclient.SourceEntry{Path: "source", Kind: "file", Mode: 0644, Size: int64(len(content)), Digest: snapshotDigest(content)}
			data := bytes.Clone(compressed)
			switch mode {
			case "malformed":
				data = []byte("not a zstd frame")
			case "two-block-huffman":
				// GHSA-fpmh-frq8-7rj8: the second block's invalid Huffman
				// weight table must return an error rather than panic.
				// https://github.com/advisories/GHSA-fpmh-frq8-7rj8
				data = bytes.Join([][]byte{
					{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f},
					bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37),
					{0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a},
					bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365),
					{0x8c, 0x31},
					bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365),
					{0x63, 0x2c},
					bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
					{0x31, 0x46},
					bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
					{0x31, 0x06, 0x00},
				}, nil)
			case "truncated":
				data = data[:len(data)-5]
			case "checksum":
				data[len(data)-1] ^= 0xff
			case "size":
				entry.Size--
			case "digest":
				entry.Digest = snapshotDigest([]byte("different source"))
			}
			manifest := snapshotManifest(t, entry)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/sources/") {
					_, _ = w.Write(manifest)
					return
				}
				w.Header().Set("Content-Encoding", "zstd")
				_, _ = w.Write(data)
			}))
			defer srv.Close()
			cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: t.TempDir()}
			err := restoreSnapshot(context.Background(), cfg, snapshotSource(srv.URL, manifest))
			if mode != "valid" {
				if err == nil {
					t.Fatalf("accepted %s compressed blob", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(cfg.WorkDir, entry.Path))
			if err != nil || !bytes.Equal(got, content) {
				t.Fatalf("restored source differs: %v", err)
			}
		})
	}
}

func TestSnapshotDownloadsAtMostEightFilesInParallel(t *testing.T) {
	content := []byte("shared blob")
	entries := make([]runnerclient.SourceEntry, 24)
	for i := range entries {
		entries[i] = runnerclient.SourceEntry{Path: fmt.Sprintf("file-%02d", i), Kind: "file", Mode: 0644, Size: int64(len(content)), Digest: snapshotDigest(content)}
	}
	manifest := snapshotManifest(t, entries...)
	var active, peak, count atomic.Int32
	gate := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sources/") {
			_, _ = w.Write(manifest)
			return
		}
		n := active.Add(1)
		defer active.Add(-1)
		count.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		if n == 8 {
			once.Do(func() { close(gate) })
		}
		select {
		case <-gate:
			_, _ = w.Write(content)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: t.TempDir()}
	if err := restoreSnapshot(ctx, cfg, snapshotSource(srv.URL, manifest)); err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 8 || count.Load() != 24 {
		t.Fatalf("parallel downloads peak=%d total=%d", peak.Load(), count.Load())
	}
}
