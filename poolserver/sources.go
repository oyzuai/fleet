package poolserver

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

const sourceMediaType = "application/vnd.oyzu.source.v1alpha1+tar+zstd"
const sourceLimit int64 = 512 << 20

type sourceDownload struct {
	Job       int64
	Digest    string
	Expires   time.Time
	TokenHash string
}

func validSourceDigest(digest string) bool {
	return strings.HasPrefix(digest, "sha256:") && hashRE.MatchString(strings.TrimPrefix(digest, "sha256:"))
}

func (s *Server) sourcePath(digest string) string {
	return filepath.Join(s.cfg.StateDir, "sources", strings.TrimPrefix(digest, "sha256:"))
}

// Source grants authorize only one archive for one live attempt, for five
// minutes. They are not job bearers and disappear on server restart.
func (s *Server) snapshotDownload(j *jobRecord, digest string) runnerclient.Source {
	now := s.now()
	for token, grant := range s.downloads {
		if !now.Before(grant.Expires) {
			delete(s.downloads, token)
		}
	}
	token := randomToken()
	s.downloads[hash([]byte(token))] = sourceDownload{Job: j.Job.ID, Digest: digest, Expires: now.Add(5 * time.Minute), TokenHash: j.TokenHash}
	return runnerclient.Source{Kind: "snapshot", Digest: digest, URL: s.cfg.PublicURL + "/api/v1alpha1/accounts/" + s.cfg.Account + "/sources/" + digest + "?download=" + url.QueryEscape(token)}
}

func (s *Server) sourceRoute(w http.ResponseWriter, r *http.Request) bool {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1alpha1/"), "/")
	if len(p) < 3 || p[0] != "accounts" || p[2] != "sources" {
		return false
	}
	if len(p) != 4 || p[1] != s.cfg.Account || !validSourceDigest(p[3]) {
		problem(w, 404, "SOURCE_UNAVAILABLE", "Source not found.")
		return true
	}
	digest := p[3]
	if r.Method == "GET" {
		s.mu.Lock()
		grant, ok := s.downloads[hash([]byte(r.URL.Query().Get("download")))]
		j := s.state.Jobs[grant.Job]
		valid := ok && grant.Digest == digest && s.now().Before(grant.Expires) && j != nil && j.TokenHash == grant.TokenHash && j.State == "running" && s.now().Before(j.Lease)
		s.mu.Unlock()
		if !valid {
			problem(w, 401, "UNAUTHENTICATED", "Source download credential expired or refused.")
			return true
		}
		f, err := os.Open(s.sourcePath(digest))
		if err != nil {
			problem(w, 404, "SOURCE_UNAVAILABLE", "Source not found.")
			return true
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
			return true
		}
		w.Header().Set("Content-Type", sourceMediaType)
		http.ServeContent(w, r, "source.tar.zst", info.ModTime(), f)
		return true
	}
	c, callerErr := s.caller(r)
	if callerErr != nil {
		problem(w, 401, "UNAUTHENTICATED", "A permitted caller is required.")
		return true
	}
	if r.Method != "PUT" {
		problem(w, 405, "REQUEST_INVALID", "Method not allowed.")
		return true
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != sourceMediaType {
		problem(w, 422, "SOURCE_KIND_UNSUPPORTED", "Use a tar+zstd source snapshot.")
		return true
	}
	if r.ContentLength > sourceLimit {
		problem(w, 413, "SOURCE_TOO_LARGE", "Source archive exceeds 512 MiB.")
		return true
	}
	if err := os.MkdirAll(filepath.Join(s.cfg.StateDir, "sources"), 0700); err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return true
	}
	f, err := os.CreateTemp(filepath.Join(s.cfg.StateDir, "sources"), ".upload-")
	if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return true
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, sourceLimit+1))
	if n > sourceLimit {
		problem(w, 413, "SOURCE_TOO_LARGE", "Source archive exceeds 512 MiB.")
		return true
	}
	if err != nil {
		problem(w, 400, "REQUEST_INVALID", "Could not read source archive.")
		return true
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		problem(w, 422, "SOURCE_DIGEST_MISMATCH", "Source archive does not match its digest.")
		return true
	}
	if err = f.Sync(); err == nil {
		err = f.Close()
	}
	if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return true
	}
	// A source name is immutable. Link publishes atomically without replacing
	// an existing archive when concurrent PUTs supply the same content.
	err = os.Link(f.Name(), s.sourcePath(digest))
	status := 201
	if os.IsExist(err) {
		status = 200
	} else if err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Source storage unavailable.")
		return true
	}
	// Deduplication shares bytes, never permission. A caller earns access only
	// after submitting the complete digest-verified body, even for an existing name.
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.state.clone()
	if d.Meta.SourceOwners == nil {
		d.Meta.SourceOwners = map[string]map[string]bool{}
	}
	if d.Meta.SourceOwners[digest] == nil {
		d.Meta.SourceOwners[digest] = map[string]bool{}
	}
	d.Meta.SourceOwners[digest][s.cfg.Account+"\x00"+c.ID] = true
	if !s.persist(w, d) {
		return true
	}
	w.WriteHeader(status)
	return true
}
