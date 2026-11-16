package container

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/oyzuai/fleet/runnerclient"
)

func actionInputArchive(a runnerclient.ActionAssignment, in runnerclient.ActionInputs) ([]byte, error) {
	in, err := runnerclient.PrepareActionInputs(a, in)
	if err != nil {
		return nil, err
	}
	var b actionArchiveBuffer
	tw := tar.NewWriter(&b)
	for _, d := range append([]string{"."}, in.Directories...) {
		if err = tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0755, Uid: 1000, Gid: 1000}); err != nil {
			return nil, err
		}
	}
	for _, f := range in.Files {
		mode := int64(0644)
		if f.Executable {
			mode = 0755
		}
		if err = tw.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeReg, Mode: mode, Size: f.Size, Uid: 1000, Gid: 1000}); err != nil {
			return nil, err
		}
		if _, err = tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	// Links are always last, so Docker never extracts a physical entry through one.
	for _, l := range in.Symlinks {
		if err = tw.WriteHeader(&tar.Header{Name: l.Path, Linkname: l.Target, Typeflag: tar.TypeSymlink, Mode: 0777, Uid: 1000, Gid: 1000}); err != nil {
			return nil, err
		}
	}
	if err = tw.Close(); err != nil {
		return nil, err
	}
	return b.buffer.Bytes(), nil
}

type actionArchiveBuffer struct{ buffer bytes.Buffer }

func (b *actionArchiveBuffer) Write(p []byte) (int, error) {
	if len(p) > runnerclient.MaxActionWire-b.buffer.Len() {
		return 0, errors.New("action archive exceeds limit")
	}
	return b.buffer.Write(p)
}

func actionSnapshot(archive []byte, a runnerclient.ActionAssignment) (runnerclient.ActionCompletion, error) {
	var c runnerclient.ActionCompletion
	if len(archive) > runnerclient.MaxActionWire {
		return c, errors.New("workspace archive exceeds limit")
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	files := map[string]runnerclient.ActionFile{}
	total := int64(0)
	rootSeen := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return c, err
		}
		p := strings.TrimSuffix(h.Name, "/")
		if p == "work" && h.Typeflag == tar.TypeDir {
			if rootSeen {
				return c, errors.New("duplicate archive root")
			}
			rootSeen = true
			continue
		}
		p, ok := strings.CutPrefix(p, "work/")
		if !ok || !runnerclient.ActionPath(p) {
			return c, errors.New("invalid workspace archive path")
		}
		n := runnerclient.ActionNode{Path: p}
		switch h.Typeflag {
		case tar.TypeDir:
			n.Kind = "directory"
		case tar.TypeSymlink:
			n.Kind = "symlink"
			n.Target = h.Linkname
		case tar.TypeReg, tar.TypeRegA:
			n.Kind = "file"
			if h.Size < 0 || h.Size > runnerclient.MaxActionBytes-total {
				return c, errors.New("whole workspace data exceeds limit")
			}
			data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
			if err != nil || int64(len(data)) != h.Size {
				return c, errors.New("truncated workspace file")
			}
			total += h.Size
			sum := sha256.Sum256(data)
			files[p] = runnerclient.ActionFile{Path: p, Data: data, Size: h.Size, SHA256: hex.EncodeToString(sum[:]), Executable: h.Mode&0111 != 0}
		default:
			return c, errors.New("workspace hardlinks and special files are forbidden")
		}
		c.WorkspaceNodes = append(c.WorkspaceNodes, n)
		if len(c.WorkspaceNodes) >= runnerclient.MaxActionEntries {
			return c, errors.New("whole workspace entry limit exceeded")
		}
	}
	g, err := runnerclient.NewActionGraph(c.WorkspaceNodes)
	if err != nil {
		return runnerclient.ActionCompletion{}, err
	}
	selection, err := g.Select(a)
	if err != nil {
		return runnerclient.ActionCompletion{}, err
	}
	for _, s := range selection {
		switch s.Node.Kind {
		case "file":
			f := files[s.Node.Path]
			f.Path = s.Logical
			c.Files = append(c.Files, f)
		case "directory":
			c.Directories = append(c.Directories, s.Logical)
		case "symlink":
			c.Symlinks = append(c.Symlinks, runnerclient.ActionSymlink{Path: s.Logical, Target: s.Node.Target})
		}
	}
	if err = runnerclient.ValidateActionProjection(a, c); err != nil {
		return runnerclient.ActionCompletion{}, err
	}
	return c, nil
}

func actionOutputs(archive []byte, a runnerclient.ActionAssignment) ([]runnerclient.ActionFile, []string, error) {
	c, err := actionSnapshot(archive, a)
	return c.Files, c.Directories, err
}
