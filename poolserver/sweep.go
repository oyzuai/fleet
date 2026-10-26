package poolserver

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type sourceFile struct {
	name     string
	size     int64
	modified time.Time
}

func sourceFiles(dir string) (map[string]sourceFile, int64, error) {
	out := map[string]sourceFile{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !hashRE.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, 0, err
		}
		out["sha256:"+entry.Name()] = sourceFile{filepath.Join(dir, entry.Name()), info.Size(), info.ModTime()}
		total += info.Size()
	}
	return out, total, nil
}

// sweepSources serializes publication/deletion with sourceMu. Metadata changes
// occur under mu, but scans and deletions never hold the server metadata lock.
func (s *Server) sweepSources() (result error) {
	manifests, blobs, freed := 0, 0, int64(0)
	defer func() {
		log.Printf("source sweep manifests=%d blobs=%d bytes_freed=%d error=%v", manifests, blobs, freed, result)
	}()
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	sources, sourceBytes, err := sourceFiles(filepath.Join(s.cfg.StateDir, "sources"))
	if err != nil {
		return err
	}
	files, blobBytes, err := sourceFiles(filepath.Join(s.cfg.StateDir, "blobs"))
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	d := s.state.clone()
	protected := map[string]bool{}
	for _, run := range d.Runs {
		if run.Run.Source != nil && (run.Run.State == "queued" || run.Run.State == "running") {
			protected[run.Run.Source.Digest] = true
		}
	}
	refs := map[string]int{}
	order := make([]string, 0, len(d.Meta.Sources))
	for digest, record := range d.Meta.Sources {
		order = append(order, digest)
		for blob := range record.Blobs {
			refs[blob]++
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := d.Meta.Sources[order[i]].LastUsed, d.Meta.Sources[order[j]].LastUsed
		if a.Equal(b) {
			return order[i] < order[j]
		}
		return a.Before(b)
	})
	projected := sourceBytes + blobBytes
	// Already orphaned old blobs are reclaimable without evicting a manifest.
	for digest, file := range files {
		if refs[digest] == 0 && !now.Before(file.modified.Add(time.Hour)) {
			projected -= file.size
		}
	}
	changed := false
	for _, digest := range order {
		record := d.Meta.Sources[digest]
		old := !now.Before(record.LastUsed.Add(s.cfg.sourceRetention))
		if protected[digest] || (!old && projected <= s.cfg.SourceQuota) {
			continue
		}
		delete(d.Meta.Sources, digest)
		delete(d.Meta.SourceOwners, digest)
		projected -= sources[digest].size
		for blob := range record.Blobs {
			refs[blob]--
			file := files[blob]
			if refs[blob] == 0 && !now.Before(file.modified.Add(time.Hour)) {
				projected -= file.size
			}
		}
		changed = true
	}
	if changed {
		err = s.commit(d)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	// Retry orphaned manifests left by interrupted publication/deletion as well.
	for digest, file := range sources {
		if _, keep := d.Meta.Sources[digest]; !keep {
			if err := os.Remove(file.name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			manifests++
			freed += file.size
		}
	}
	for digest, file := range files {
		if refs[digest] == 0 && !now.Before(file.modified.Add(time.Hour)) {
			if err := os.Remove(file.name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			blobs++
			freed += file.size
		}
	}
	return nil
}
