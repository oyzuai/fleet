package kindrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/oyzuai/fleet/kindprotocol"
)

// Plan files (IMPL-401). A plan or apply runs with a private directory,
// OYZU_PLAN_FILES_DIR, that the runner fills and empties. A plan writes there
// whatever its apply will need (a Terraform plan file); once the plan
// succeeds the runner sends the directory to runs, which seals it in the
// account's blob namespace. Before an apply of an approved plan the runner
// fetches that plan's files into the directory. The runner never reads the
// files: they go over as one tar of the directory's regular files.

// maxPlanFiles bounds what a plan may leave in the directory.
const maxPlanFiles = 64 << 20

// planDir is the plan files directory of one job.
type planDir struct{ path string }

func (p *planDir) remove() {
	if p != nil {
		_ = os.RemoveAll(p.path)
	}
}

// planFiles makes the directory for a plan or an apply, with the approved
// plan's files in it for an apply. Other operations get none.
func (r *run) planFiles(ctx context.Context, req *kindprotocol.Request) (*planDir, error) {
	if req.Operation != kindprotocol.OpPlan && req.Operation != kindprotocol.OpApply {
		return nil, nil
	}
	dir, err := os.MkdirTemp(r.cfg.SecretsDir, "oyzu-kind-plan-")
	if err != nil {
		return nil, err
	}
	p := &planDir{path: dir}
	if req.Operation != kindprotocol.OpApply || req.ApprovedPlan == nil {
		return p, nil
	}
	archive, found, err := r.cfg.Client.KindPlanFile(ctx, r.cfg.Token)
	if err != nil {
		p.remove()
		return nil, fmt.Errorf("fetch the approved plan's files: %w", err)
	}
	if !found {
		r.events.local("info", "runs keeps no plan files for the approved plan.")
		return p, nil
	}
	defer clear(archive)
	if err := untarFlat(archive, dir); err != nil {
		p.remove()
		return nil, fmt.Errorf("unpack the approved plan's files: %w", err)
	}
	return p, nil
}

// savePlanFiles sends what a succeeded plan left in its directory.
func (r *run) savePlanFiles(ctx context.Context, req *kindprotocol.Request, raw json.RawMessage, p *planDir) error {
	if p == nil || req.Operation != kindprotocol.OpPlan {
		return nil
	}
	var res kindprotocol.Result
	if err := json.Unmarshal(raw, &res); err != nil || res.Outcome != kindprotocol.Succeeded || res.Plan == nil {
		return nil
	}
	archive, n, err := tarFlat(p.path, maxPlanFiles)
	if err != nil {
		return fmt.Errorf("pack the plan files: %w", err)
	}
	defer clear(archive)
	if n == 0 {
		return nil
	}
	if err := r.cfg.Client.KindPlanFileSave(ctx, r.cfg.Token, res.Plan.Digest, archive); err != nil {
		return fmt.Errorf("send the plan files to runs: %w", err)
	}
	r.events.local("info", fmt.Sprintf("Kept %d plan file(s) for plan %s.", n, res.Plan.Digest))
	return nil
}

// tarFlat packs the regular files directly in dir, refusing more than max
// bytes of them. Files go in name order, so the same files pack the same.
func tarFlat(dir string, max int64) ([]byte, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	n := 0
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, 0, err
		}
		total += int64(len(b))
		if total > max {
			return nil, 0, fmt.Errorf("the files come to more than %d bytes", max)
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.Name(), Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return nil, 0, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, 0, err
		}
		clear(b)
		n++
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), n, nil
}

// untarFlat unpacks regular files with plain names into dir.
func untarFlat(archive []byte, dir string) error {
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || h.Name != filepath.Base(h.Name) || h.Name == "." || h.Name == ".." {
			return fmt.Errorf("unexpected entry %q", h.Name)
		}
		f, err := os.OpenFile(filepath.Join(dir, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, maxPlanFiles))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}
