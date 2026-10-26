package poolserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/oyzuai/fleet/runnerclient"
)

const sourceMediaType = runnerclient.SourceMediaType
const sourceLimit = runnerclient.SourceLimit

type sourceRecord struct {
	LastUsed time.Time        `json:"last_used"`
	Size     int64            `json:"size"`
	Blobs    map[string]int64 `json:"blobs"`
}

type sourceDownload struct {
	Job       int64
	Digest    string
	Blobs     map[string]int64
	Expires   time.Time
	TokenHash string
}

func validSourceDigest(digest string) bool { return runnerclient.ValidSourceDigest(digest) }

func (s *Server) sourcePath(digest string) string {
	return filepath.Join(s.cfg.StateDir, "sources", strings.TrimPrefix(digest, "sha256:"))
}

func (s *Server) blobPath(digest string) string {
	return filepath.Join(s.cfg.StateDir, "blobs", strings.TrimPrefix(digest, "sha256:"))
}

// Grants cover precisely one manifest and its blobs for one live attempt.
// They expire after five minutes and disappear on server restart.
func (s *Server) snapshotDownload(j *jobRecord, digest string) runnerclient.Source {
	now := s.now()
	for token, grant := range s.downloads {
		if !now.Before(grant.Expires) {
			delete(s.downloads, token)
		}
	}
	token := randomToken()
	s.downloads[hash([]byte(token))] = sourceDownload{Job: j.Job.ID, Digest: digest, Blobs: s.state.Meta.Sources[digest].Blobs, Expires: now.Add(5 * time.Minute), TokenHash: j.TokenHash}
	return runnerclient.Source{Kind: "snapshot", Digest: digest, URL: s.cfg.PublicURL + "/api/v1alpha1/accounts/" + s.cfg.Account + "/sources/" + digest + "?download=" + url.QueryEscape(token)}
}

func (s *Server) sourceRoute(w http.ResponseWriter, r *http.Request) bool {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1alpha1/"), "/")
	if len(p) < 3 || p[0] != "accounts" || (p[2] != "sources" && p[2] != "blobs") {
		return false
	}
	missing := len(p) == 4 && p[2] == "sources" && p[3] == "missing"
	if len(p) != 4 || p[1] != s.cfg.Account || (!missing && !validSourceDigest(p[3])) {
		problem(w, 404, "SOURCE_UNAVAILABLE", "Source not found.")
		return true
	}
	// File operations share this lock with the sweeper, never the metadata lock.
	s.sourceMu.RLock()
	defer s.sourceMu.RUnlock()
	if r.Method == "GET" && !missing {
		s.downloadSource(w, r, p[2], p[3])
		return true
	}
	c, err := s.caller(r)
	if err != nil {
		problem(w, 401, "UNAUTHENTICATED", "A permitted caller is required.")
		return true
	}
	if missing && r.Method == "POST" {
		s.missingSources(w, r)
	} else if !missing && r.Method == "PUT" {
		s.putSource(w, r, c, p[2], p[3])
	} else {
		problem(w, 405, "REQUEST_INVALID", "Method not allowed.")
	}
	return true
}

func (s *Server) downloadSource(w http.ResponseWriter, r *http.Request, kind, digest string) {
	s.mu.Lock()
	grant, ok := s.downloads[hash([]byte(r.URL.Query().Get("download")))]
	j := s.state.Jobs[grant.Job]
	_, listed := grant.Blobs[digest]
	authorized := (kind == "sources" && grant.Digest == digest) || (kind == "blobs" && listed)
	valid := ok && authorized && s.now().Before(grant.Expires) && j != nil && j.TokenHash == grant.TokenHash && j.State == "running" && s.now().Before(j.Lease)
	s.mu.Unlock()
	if !valid {
		problem(w, 401, "UNAUTHENTICATED", "Source download credential expired or refused.")
		return
	}
	name, media := s.sourcePath(digest), sourceMediaType
	if kind == "blobs" {
		name, media = s.blobPath(digest), "application/octet-stream"
	}
	f, err := os.Open(name)
	if err != nil {
		problem(w, 404, "SOURCE_UNAVAILABLE", "Source not found.")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return
	}
	w.Header().Set("Content-Type", media)
	http.ServeContent(w, r, filepath.Base(name), info.ModTime(), f)
}

func (s *Server) missingSources(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Blobs []string `json:"blobs"`
	}
	if !parseBody(w, r, &in) {
		return
	}
	if in.Blobs == nil || len(in.Blobs) > 10000 {
		problem(w, 422, "REQUEST_INVALID", "Provide at most 10000 blob digests.")
		return
	}
	missing := []string{}
	seen := map[string]bool{}
	for _, digest := range in.Blobs {
		if !validSourceDigest(digest) {
			problem(w, 422, "REQUEST_INVALID", "Invalid blob digest.")
			return
		}
		_, err := os.Stat(s.blobPath(digest))
		if os.IsNotExist(err) && !seen[digest] {
			missing = append(missing, digest)
			seen[digest] = true
		} else if err != nil && !os.IsNotExist(err) {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
			return
		}
	}
	respond(w, 200, map[string]any{"missing": missing})
}

func (s *Server) putSource(w http.ResponseWriter, r *http.Request, c caller, kind, digest string) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	wanted := sourceMediaType
	if kind == "blobs" {
		wanted = "application/octet-stream"
	}
	if err != nil || media != wanted {
		problem(w, 422, "SOURCE_KIND_UNSUPPORTED", "Use the source manifest or raw blob media type.")
		return
	}
	input := io.Reader(r.Body)
	encoding := r.Header.Get("Content-Encoding")
	if kind == "blobs" && encoding == "zstd" {
		decoder, err := zstd.NewReader(r.Body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(sourceLimit)))
		if err != nil {
			problem(w, 400, "REQUEST_INVALID", "Could not decode blob.")
			return
		}
		defer decoder.Close()
		input = decoder
	} else if encoding != "" && encoding != "identity" {
		problem(w, 422, "SOURCE_KIND_UNSUPPORTED", "Unsupported source content encoding.")
		return
	}
	if r.ContentLength > sourceLimit && encoding != "zstd" {
		problem(w, 413, "SOURCE_TOO_LARGE", "Source exceeds 512 MiB.")
		return
	}
	dir := filepath.Join(s.cfg.StateDir, kind)
	if err := os.MkdirAll(dir, 0700); err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return
	}
	f, err := os.CreateTemp(dir, ".upload-")
	if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(input, sourceLimit+1))
	if n > sourceLimit {
		problem(w, 413, "SOURCE_TOO_LARGE", "Source exceeds 512 MiB.")
		return
	}
	if err != nil {
		problem(w, 400, "REQUEST_INVALID", "Could not read source content.")
		return
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		problem(w, 422, "SOURCE_DIGEST_MISMATCH", "Source content does not match its digest.")
		return
	}
	record := sourceRecord{LastUsed: s.now(), Size: n, Blobs: map[string]int64{}}
	if kind == "sources" {
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
			return
		}
		data, err := io.ReadAll(f)
		if err != nil {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
			return
		}
		manifest, err := runnerclient.ParseSourceManifest(data)
		if err != nil {
			problem(w, 422, "SOURCE_INVALID", "Invalid source manifest: "+err.Error())
			return
		}
		missing := []string{}
		for _, entry := range manifest.Entries {
			if entry.Kind != "file" {
				continue
			}
			if _, ok := record.Blobs[entry.Digest]; ok {
				continue
			}
			record.Blobs[entry.Digest] = entry.Size
			info, err := os.Stat(s.blobPath(entry.Digest))
			if os.IsNotExist(err) {
				missing = append(missing, entry.Digest)
			} else if err != nil {
				problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
				return
			} else if info.Size() != entry.Size {
				problem(w, 422, "SOURCE_INVALID", "Manifest size does not match stored blob.")
				return
			}
		}
		if len(missing) != 0 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(422)
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:oyzu:problem:source-blobs-missing", "title": "Source blobs missing", "status": 422, "code": "SOURCE_BLOBS_MISSING", "missing": missing, "request_id": w.Header().Get("X-Request-Id")})
			return
		}
	}
	if err = f.Sync(); err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Chtimes(f.Name(), record.LastUsed, record.LastUsed)
	}
	if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return
	}
	name := s.blobPath(digest)
	if kind == "sources" {
		name = s.sourcePath(digest)
	}
	err = os.Link(f.Name(), name)
	status := 201
	if os.IsExist(err) {
		status = 200
	} else if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return
	}
	if kind == "sources" {
		s.mu.Lock()
		defer s.mu.Unlock()
		d := s.state.clone()
		if d.Meta.SourceOwners == nil {
			d.Meta.SourceOwners = map[string]map[string]bool{}
		}
		if d.Meta.SourceOwners[digest] == nil {
			d.Meta.SourceOwners[digest] = map[string]bool{}
		}
		if d.Meta.Sources == nil {
			d.Meta.Sources = map[string]sourceRecord{}
		}
		d.Meta.SourceOwners[digest][s.cfg.Account+"\x00"+c.ID] = true
		d.Meta.Sources[digest] = record
		if !s.persist(w, d) {
			return
		}
	}
	w.WriteHeader(status)
}
