package poolserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

type runRecord struct {
	Run         Run    `json:"run"`
	Owner       string `json:"owner"`
	BodyHash    string `json:"body_hash"`
	Idempotency string `json:"idempotency,omitempty"`
	JobID       int64  `json:"job_id"`
}
type jobRecord struct {
	Job            runnerclient.Job      `json:"job"`
	State          string                `json:"state"`
	Manager        int64                 `json:"manager"`
	StartupHash    string                `json:"startup_hash,omitempty"`
	StartupExpires time.Time             `json:"startup_expires"`
	TokenHash      string                `json:"token_hash,omitempty"`
	Lease          time.Time             `json:"lease"`
	DrainUntil     time.Time             `json:"drain_until"`
	Outputs        []runnerclient.Output `json:"outputs"`
	Logs           logRecord             `json:"logs"`
}
type logRecord struct {
	Bytes   int64                   `json:"bytes"`
	Entries int64                   `json:"entries"`
	Chunks  []string                `json:"chunks"`
	State   string                  `json:"state"`
	Finish  *runnerclient.LogFinish `json:"finish,omitempty"`
}
type managerRecord struct {
	ID     int64                       `json:"id"`
	Name   string                      `json:"name"`
	Keys   map[int64]ed25519.PublicKey `json:"keys"`
	Report runnerclient.Report         `json:"report"`
}
type accessRecord struct {
	Manager int64     `json:"manager"`
	Expires time.Time `json:"expires"`
}
type metadata struct {
	Version         int                      `json:"version"`
	NextID          int64                    `json:"next_id"`
	NextKey         int64                    `json:"next_key"`
	EnrollmentSpent bool                     `json:"enrollment_spent"`
	Managers        map[int64]*managerRecord `json:"managers"`
	Access          map[string]accessRecord  `json:"access"`
	Assertions      map[string]time.Time     `json:"assertions"`
}
type diskState struct {
	Meta metadata              `json:"meta"`
	Runs map[string]*runRecord `json:"runs"`
	Jobs map[int64]*jobRecord  `json:"jobs"`
}

func emptyState() diskState {
	return diskState{Meta: metadata{Version: 1, Managers: map[int64]*managerRecord{}, Access: map[string]accessRecord{}, Assertions: map[string]time.Time{}}, Runs: map[string]*runRecord{}, Jobs: map[int64]*jobRecord{}}
}
func (d diskState) clone() diskState {
	b, _ := json.Marshal(d)
	var out diskState
	_ = json.Unmarshal(b, &out)
	return out
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func atomicJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func readJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func loadState(dir string) (diskState, error) {
	d := emptyState()
	for _, p := range []string{dir, filepath.Join(dir, "runs"), filepath.Join(dir, "jobs"), filepath.Join(dir, "logs")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			return d, err
		}
	}
	// A durable transaction is the commit point. Replay it before serving anything.
	if err := readJSON(filepath.Join(dir, "transaction.json"), &d); err == nil {
		if err = writeState(dir, d); err != nil {
			return d, err
		}
		if err = os.Remove(filepath.Join(dir, "transaction.json")); err != nil {
			return d, err
		}
		if err = syncDir(dir); err != nil {
			return d, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return d, err
	}
	if err := readJSON(filepath.Join(dir, "state.json"), &d.Meta); err != nil && !errors.Is(err, os.ErrNotExist) {
		return d, err
	}
	if d.Meta.Version != 1 {
		return d, errors.New("unsupported state version")
	}
	for _, kind := range []string{"runs", "jobs"} {
		files, err := os.ReadDir(filepath.Join(dir, kind))
		if err != nil {
			return d, err
		}
		for _, f := range files {
			if filepath.Ext(f.Name()) != ".json" {
				continue
			}
			p := filepath.Join(dir, kind, f.Name())
			if kind == "runs" {
				var r runRecord
				if err = readJSON(p, &r); err != nil {
					return d, err
				}
				d.Runs[r.Run.ID] = &r
			} else {
				var j jobRecord
				if err = readJSON(p, &j); err != nil {
					return d, err
				}
				d.Jobs[j.Job.ID] = &j
			}
		}
	}
	for _, j := range d.Jobs {
		p := logPath(dir, j)
		info, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) && j.Logs.Bytes == 0 {
			continue
		}
		if err != nil {
			return d, err
		}
		if info.Size() < j.Logs.Bytes {
			return d, errors.New("log is shorter than committed state")
		}
		if err = os.Truncate(p, j.Logs.Bytes); err != nil {
			return d, err
		}
	}
	return d, nil
}
func writeState(dir string, d diskState) error {
	for id, r := range d.Runs {
		if err := atomicJSON(filepath.Join(dir, "runs", id+".json"), r); err != nil {
			return err
		}
	}
	for id, j := range d.Jobs {
		if err := atomicJSON(filepath.Join(dir, "jobs", strconv.FormatInt(id, 10)+".json"), j); err != nil {
			return err
		}
	}
	return atomicJSON(filepath.Join(dir, "state.json"), d.Meta)
}
func (s *Server) commit(d diskState) error {
	if s.storageErr != nil {
		return s.storageErr
	}
	err := atomicJSON(filepath.Join(s.cfg.StateDir, "transaction.json"), d)
	if err == nil {
		err = writeState(s.cfg.StateDir, d)
	}
	if err == nil {
		err = os.Remove(filepath.Join(s.cfg.StateDir, "transaction.json"))
	}
	if err == nil {
		err = syncDir(s.cfg.StateDir)
	}
	if err != nil {
		s.storageErr = fmt.Errorf("state persistence failed: %w", err)
		return s.storageErr
	}
	s.state = d
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}
func logPath(dir string, j *jobRecord) string {
	return filepath.Join(dir, "logs", fmt.Sprintf("%d-%d.ndjson", j.Job.ID, j.Job.Attempt))
}
func (s *Server) expire() error {
	now := s.now()
	d := s.state.clone()
	changed := false
	for _, j := range d.Jobs {
		r := d.Runs[jobRunID(d, j)]
		if r == nil {
			return errors.New("job has no run")
		}
		if j.State == "claimed" && !now.Before(j.StartupExpires) {
			j.State = "queued"
			j.StartupHash = ""
			j.Manager = 0
			j.Job.Attempt--
			r.Run.Attempt = j.Job.Attempt
			changed = true
		}
		if j.State == "running" && !now.Before(j.Lease) {
			j.State = "timed_out"
			j.TokenHash = ""
			j.Logs.State = "incomplete"
			r.Run.State = "timed_out"
			r.Run.FinishedAt = &now
			r.Run.Reason = &Reason{Code: "LEASE_EXPIRED", Message: "The executor lease expired."}
			changed = true
		}
		if finished(r.Run) && j.Logs.State == "open" && !now.Before(j.DrainUntil) {
			j.Logs.State = "incomplete"
			changed = true
		}
	}
	for k, a := range d.Meta.Access {
		if !now.Before(a.Expires) {
			delete(d.Meta.Access, k)
			changed = true
		}
	}
	for k, t := range d.Meta.Assertions {
		if now.After(t.Add(time.Minute)) {
			delete(d.Meta.Assertions, k)
			changed = true
		}
	}
	if changed {
		return s.commit(d)
	}
	return s.storageErr
}
func jobRunID(d diskState, j *jobRecord) string {
	for id, r := range d.Runs {
		if r.JobID == j.Job.ID {
			return id
		}
	}
	return ""
}
