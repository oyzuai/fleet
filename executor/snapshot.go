package executor

import (
	"archive/tar"
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
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

const maxSourceArchive int64 = 512 << 20
const maxSourceTree int64 = 10 << 30

// restoreSnapshot verifies compressed bytes before invoking zstd. The decoder
// receives no job credential; cancellation and every error reap the child.
func restoreSnapshot(ctx context.Context, cfg Config, source runnerclient.Source) error {
	u, err := url.Parse(source.URL)
	if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return errors.New("invalid snapshot download URL")
	}
	if len(source.Digest) != 71 || !strings.HasPrefix(source.Digest, "sha256:") {
		return errors.New("invalid snapshot digest")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(source.Digest, "sha256:")); err != nil {
		return errors.New("invalid snapshot digest")
	}
	resp, err := cfg.Client.DownloadSource(ctx, source.URL)
	if err != nil {
		return errors.New("snapshot download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("snapshot download answered HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Dir(cfg.WorkDir), ".source-*.tar.zst")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSourceArchive+1))
	if err != nil {
		return errors.New("snapshot download interrupted")
	}
	if n > maxSourceArchive {
		return errors.New("snapshot archive exceeds 512 MiB")
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != source.Digest {
		return errors.New("snapshot digest mismatch")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "zstd", "-d", "--stdout")
	cmd.Stdin = f
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start zstd: %w", err)
	}
	if err = extractSnapshot(cfg.WorkDir, stdout); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	// tar stops at its end marker. Drain so a truncated/corrupt zstd frame
	// cannot be accepted and the decoder cannot block on an unread pipe.
	_, drainErr := io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if drainErr != nil {
		return drainErr
	}
	if waitErr != nil {
		return errors.New("snapshot zstd decoding failed")
	}
	return nil
}

func sourceRelative(name string) bool {
	if name == "" || path.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".git" || part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

func extractSnapshot(root string, input io.Reader) error {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		return errors.New("snapshot destination must be empty")
	}
	type link struct {
		name, target string
		modified     time.Time
	}
	var links []link
	type directory struct {
		name     string
		mode     os.FileMode
		modified time.Time
	}
	var directories []directory
	seen := map[string]bool{}
	var size int64
	tr := tar.NewReader(input)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !sourceRelative(name) || seen[name] {
			return fmt.Errorf("unsafe or duplicate snapshot path %q", h.Name)
		}
		seen[name] = true
		full := filepath.Join(root, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return err
		}
		mode := os.FileMode(h.Mode) & 0777
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(full, 0700); err != nil {
				return err
			}
			directories = append(directories, directory{full, mode, h.ModTime})
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > maxSourceTree-size {
				return errors.New("snapshot tree exceeds 10 GiB")
			}
			size += h.Size
			f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, tr)
			if copyErr == nil {
				copyErr = f.Chmod(mode)
			}
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err = os.Chtimes(full, h.ModTime, h.ModTime); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if h.Linkname == "" || path.IsAbs(h.Linkname) || strings.ContainsAny(h.Linkname, "\\:\x00") {
				return errors.New("unsafe snapshot link")
			}
			resolved := path.Clean(path.Join(path.Dir(name), h.Linkname))
			if resolved != "." && !sourceRelative(resolved) {
				return errors.New("snapshot link escapes source")
			}
			links = append(links, link{name, h.Linkname, h.ModTime})
		default:
			return errors.New("unsupported snapshot entry type")
		}
	}
	// Links are created last so no archive entry can write through one.
	for _, l := range links {
		if err = os.Symlink(l.target, filepath.Join(root, filepath.FromSlash(l.name))); err != nil {
			return err
		}
		if err = snapshotLinkTime(filepath.Join(root, filepath.FromSlash(l.name)), l.modified); err != nil {
			return err
		}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for _, l := range links {
		target, err := filepath.EvalSymlinks(filepath.Join(abs, filepath.FromSlash(l.name)))
		if err != nil || (target != abs && !strings.HasPrefix(target, abs+string(filepath.Separator))) {
			return errors.New("snapshot link escapes source or cannot be resolved")
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		d := directories[i]
		if err = os.Chmod(d.name, d.mode); err != nil {
			return err
		}
		if err = os.Chtimes(d.name, d.modified, d.modified); err != nil {
			return err
		}
	}
	return nil
}
