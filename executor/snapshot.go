package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/oyzuai/fleet/runnerclient"
)

// restoreSnapshot verifies the original manifest bytes, then restores its file
// blobs with at most eight concurrent requests. Downloads send only the scoped
// grant, using the runner's configured transport without a subprocess.
func restoreSnapshot(ctx context.Context, cfg Config, source runnerclient.Source) error {
	u, err := url.Parse(source.URL)
	if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return errors.New("invalid snapshot download URL")
	}
	if !runnerclient.ValidSourceDigest(source.Digest) || !strings.HasSuffix(u.Path, "/sources/"+source.Digest) {
		return errors.New("invalid snapshot digest or manifest URL")
	}
	resp, err := cfg.Client.DownloadSource(ctx, source.URL)
	if err != nil {
		return errors.New("snapshot download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("snapshot download answered HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, runnerclient.SourceLimit+1))
	if err != nil {
		return errors.New("snapshot download interrupted")
	}
	if int64(len(data)) > runnerclient.SourceLimit {
		return errors.New("snapshot manifest exceeds 512 MiB")
	}
	h := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(h[:]) != source.Digest {
		return errors.New("snapshot digest mismatch")
	}
	manifest, err := runnerclient.ParseSourceManifest(data)
	if err != nil {
		return err
	}
	return restoreSourceTree(ctx, cfg, u, manifest)
}

func restoreSourceTree(ctx context.Context, cfg Config, sourceURL *url.URL, manifest runnerclient.SourceManifest) error {
	entries, err := os.ReadDir(cfg.WorkDir)
	if err != nil || len(entries) != 0 {
		return errors.New("snapshot destination must be empty")
	}
	// Resolve the existing root once; all source entries are validated relative
	// paths and links are withheld until every file has finished writing.
	root, err := filepath.EvalSymlinks(cfg.WorkDir)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		full := filepath.Join(root, filepath.FromSlash(entry.Path))
		dir := filepath.Dir(full)
		if entry.Kind == "directory" {
			dir = full
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan runnerclient.SourceEntry)
	var workers sync.WaitGroup
	var once sync.Once
	var firstErr error
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for entry := range jobs {
				if workCtx.Err() != nil {
					continue
				}
				if err := restoreSourceFile(workCtx, cfg, sourceURL, root, entry); err != nil {
					once.Do(func() {
						firstErr = err
						cancel()
					})
				}
			}
		}()
	}
enqueue:
	for _, entry := range manifest.Entries {
		if entry.Kind != "file" {
			continue
		}
		select {
		case jobs <- entry:
		case <-workCtx.Done():
			break enqueue
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil {
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		if entry.Kind == "symlink" {
			if err := os.Symlink(entry.Target, filepath.Join(root, filepath.FromSlash(entry.Path))); err != nil {
				return err
			}
		}
	}
	for _, entry := range manifest.Entries {
		if entry.Kind == "symlink" {
			target, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(entry.Path)))
			if err != nil || (target != root && !strings.HasPrefix(target, root+string(filepath.Separator))) {
				return errors.New("snapshot link escapes source or cannot be resolved")
			}
		}
	}
	// Children and links change directory mtimes. Apply restrictive modes and
	// nanosecond directory timestamps after the complete tree exists.
	for i := len(manifest.Entries) - 1; i >= 0; i-- {
		entry := manifest.Entries[i]
		if entry.Kind != "directory" {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(entry.Path))
		if err := os.Chmod(full, os.FileMode(entry.Mode)); err != nil {
			return err
		}
		modified := time.Unix(0, entry.Mtime)
		if err := os.Chtimes(full, modified, modified); err != nil {
			return err
		}
	}
	return nil
}

func restoreSourceFile(ctx context.Context, cfg Config, sourceURL *url.URL, root string, entry runnerclient.SourceEntry) error {
	u := *sourceURL
	u.Path = strings.TrimSuffix(u.Path, "/sources/"+filepath.Base(u.Path)) + "/blobs/" + entry.Digest
	u.RawPath = ""
	resp, err := cfg.Client.DownloadSource(ctx, u.String())
	if err != nil {
		return errors.New("snapshot blob download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("snapshot blob download answered HTTP %d", resp.StatusCode)
	}
	input := io.Reader(resp.Body)
	encoding := resp.Header.Get("Content-Encoding")
	if encoding == "zstd" {
		decoder, err := zstd.NewReader(resp.Body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(runnerclient.SourceLimit)))
		if err != nil {
			return errors.New("snapshot blob decoding failed")
		}
		defer decoder.Close()
		input = decoder
	} else if encoding != "" && encoding != "identity" {
		return errors.New("unsupported snapshot blob content encoding")
	}
	full := filepath.Join(root, filepath.FromSlash(entry.Path))
	f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(input, entry.Size+1))
	if err != nil {
		return errors.New("snapshot blob download interrupted")
	}
	if n != entry.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != entry.Digest {
		return errors.New("snapshot blob digest or size mismatch")
	}
	if err := f.Chmod(os.FileMode(entry.Mode)); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	modified := time.Unix(0, entry.Mtime)
	return os.Chtimes(full, modified, modified)
}
