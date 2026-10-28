package poolserver

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

const maxChunkBytes = 1 << 20
const maxLogBytes = 512 << 20

func logConflict(w http.ResponseWriter, j *jobRecord) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(409)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:oyzu:problem:log-conflict", "title": "Log conflict", "status": 409, "code": "LOG_CONFLICT", "detail": "The log sequence or hash conflicts.", "next_seq": len(j.Logs.Chunks) + 1, "request_id": w.Header().Get("X-Request-Id")})
}
func (s *Server) uploadLogs(w http.ResponseWriter, r *http.Request, d diskState, j *jobRecord) {
	var in runnerclient.LogChunk
	if !parseBody(w, r, &in) {
		return
	}
	if in.Attempt != j.Job.Attempt || in.Seq < 1 || !hashRE.MatchString(in.Hash) || in.Entries < 1 || in.Entries > 1000 || in.First < 1 || in.Last-in.First != in.Entries-1 || len(in.Data) > maxChunkBytes {
		problem(w, 400, "REQUEST_INVALID", "Invalid log chunk.")
		return
	}
	if in.Seq <= int64(len(j.Logs.Chunks)) {
		if j.Logs.Chunks[in.Seq-1] == in.Hash {
			s.enqueueChecksLocked(jobRunID(d, j))
			respond(w, 200, runnerclient.LogAck{NextSeq: int64(len(j.Logs.Chunks) + 1), State: j.Logs.State})
		} else {
			logConflict(w, j)
		}
		return
	}
	if j.Logs.State != "open" || in.Seq != int64(len(j.Logs.Chunks)+1) || in.First != j.Logs.Entries+1 {
		logConflict(w, j)
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(in.Data))
	if e != nil {
		problem(w, 400, "REQUEST_INVALID", "Invalid compressed log.")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(z, maxChunkBytes+1))
	closeErr := z.Close()
	if e != nil || closeErr != nil || len(raw) > maxChunkBytes || len(raw) == 0 || raw[len(raw)-1] != '\n' || hash(raw) != in.Hash {
		problem(w, 400, "REQUEST_INVALID", "Invalid log bytes or hash.")
		return
	}
	if j.Logs.Bytes+int64(len(raw)) > maxLogBytes {
		problem(w, 413, "REQUEST_INVALID", "Attempt log limit exceeded.")
		return
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if int64(len(lines)) != in.Entries {
		problem(w, 400, "REQUEST_INVALID", "Invalid log entry count.")
		return
	}
	entries := make([]runnerclient.LogEntry, 0, len(lines))
	for i, line := range lines {
		var entry runnerclient.LogEntry
		if !utf8.Valid(line) || decodeJSON(bytes.NewReader(line), &entry) != nil || entry.Sequence != in.First+int64(i) || !contains([]string{"stdout", "stderr", "system"}, entry.Stream) || entry.Time.IsZero() || utf8.RuneCountInString(entry.Text) > 65536 || utf8.RuneCountInString(entry.Scope) > 512 || utf8.RuneCountInString(entry.ParentScope) > 512 || entry.Redacted < 0 || !validEvent(entry.Event) {
			problem(w, 400, "REQUEST_INVALID", "Invalid log entry.")
			return
		}
		entries = append(entries, entry)
	}
	f, e := os.OpenFile(logPath(s.cfg.StateDir, j), os.O_CREATE|os.O_WRONLY, 0600)
	if e == nil {
		e = f.Truncate(j.Logs.Bytes)
		if e == nil {
			_, e = f.Seek(j.Logs.Bytes, io.SeekStart)
		}
		if e == nil {
			_, e = f.Write(raw)
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e == nil {
		e = syncDir(filepath.Join(s.cfg.StateDir, "logs"))
	}
	if e != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "Log storage is unavailable.")
		return
	}
	// Commit metadata only after the bytes are durable. An interrupted write is
	// trimmed back to this committed prefix when the state is reopened.
	j.Logs.Bytes += int64(len(raw))
	j.Logs.Entries = in.Last
	j.Logs.Chunks = append(j.Logs.Chunks, in.Hash)
	runID := jobRunID(d, j)
	observeStageLogs(d.Runs[runID], entries)
	if s.persist(w, d) {
		s.enqueueChecksLocked(runID)
		respond(w, 200, runnerclient.LogAck{NextSeq: int64(len(j.Logs.Chunks) + 1), State: j.Logs.State})
	}
}
func validEvent(e *runnerclient.LogEvent) bool {
	if e == nil {
		return true
	}
	return contains([]string{"task", "finished"}, e.Kind) && (e.State == "" || contains([]string{"running", "blocked"}, e.State)) && (e.DurationMS == nil || *e.DurationMS >= 0)
}
func (s *Server) finishLogs(w http.ResponseWriter, r *http.Request, d diskState, j *jobRecord) {
	var in runnerclient.LogFinish
	if !parseBody(w, r, &in) {
		return
	}
	if in.Attempt != j.Job.Attempt || in.FinalSeq < 0 || in.TotalEntries < 0 || !hashRE.MatchString(in.Hash) {
		problem(w, 400, "REQUEST_INVALID", "Invalid log finish.")
		return
	}
	if j.Logs.Finish != nil {
		if *j.Logs.Finish != in {
			logConflict(w, j)
			return
		}
		respond(w, 200, runnerclient.LogAck{NextSeq: int64(len(j.Logs.Chunks) + 1), State: j.Logs.State})
		return
	}
	if j.Logs.State != "open" || in.FinalSeq != int64(len(j.Logs.Chunks)) || in.TotalEntries != j.Logs.Entries {
		logConflict(w, j)
		return
	}
	digest := sha256.New()
	if j.Logs.Bytes > 0 {
		f, e := os.Open(logPath(s.cfg.StateDir, j))
		if e != nil {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Log storage is unavailable.")
			return
		}
		n, e := io.Copy(digest, io.LimitReader(f, j.Logs.Bytes))
		_ = f.Close()
		if e != nil || n != j.Logs.Bytes {
			problem(w, 503, "SERVICE_UNAVAILABLE", "Log storage is unavailable.")
			return
		}
	}
	if hex.EncodeToString(digest.Sum(nil)) != in.Hash {
		logConflict(w, j)
		return
	}
	j.Logs.State = "complete"
	if in.Incomplete {
		j.Logs.State = "incomplete"
	}
	j.Logs.Finish = &in
	if s.persist(w, d) {
		respond(w, 200, runnerclient.LogAck{NextSeq: int64(len(j.Logs.Chunks) + 1), State: j.Logs.State})
	}
}
func readLogPage(dir string, j *jobRecord, cursor int64, limit int) ([]runnerclient.LogEntry, error) {
	entries := []runnerclient.LogEntry{}
	if j.Logs.Bytes == 0 {
		return entries, nil
	}
	f, e := os.Open(logPath(dir, j))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	scan := bufio.NewScanner(io.LimitReader(f, j.Logs.Bytes))
	scan.Buffer(make([]byte, 4096), maxChunkBytes)
	for scan.Scan() {
		var entry runnerclient.LogEntry
		if e = json.Unmarshal(scan.Bytes(), &entry); e != nil {
			return nil, e
		}
		if entry.Sequence > cursor {
			entries = append(entries, entry)
			if len(entries) == limit {
				return entries, nil
			}
		}
	}
	if e = scan.Err(); e != nil {
		return nil, e
	}
	if len(entries) == 0 && cursor < j.Logs.Entries {
		return nil, errors.New("log prefix missing")
	}
	return entries, nil
}
