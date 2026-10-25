package poolserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	c, err := s.caller(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		problem(w, 401, "UNAUTHENTICATED", "A permitted tailnet identity or GitHub Actions token is required.")
		return
	}
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1alpha1/"), "/")
	if len(p) < 3 || p[0] != "accounts" || p[2] != "runs" {
		problem(w, 404, "RUN_NOT_FOUND", "Run not found.")
		return
	}
	if p[1] != s.cfg.Account {
		problem(w, 404, "ACCOUNT_NOT_FOUND", "Account not found.")
		return
	}
	if len(p) == 3 {
		switch r.Method {
		case "POST":
			s.createRun(w, r, c)
		case "GET":
			s.listRuns(w, r, c)
		default:
			problem(w, 405, "REQUEST_INVALID", "Method not allowed.")
		}
		return
	}
	if len(p) > 6 || p[3] == "" {
		problem(w, 404, "RUN_NOT_FOUND", "Run not found.")
		return
	}
	action := ""
	if len(p) > 4 {
		action = p[4]
	}
	valid := r.Method == "GET" && ((len(p) == 4) || (len(p) == 5 && (action == "logs" || action == "result")) || (len(p) == 6 && action == "outputs"))
	valid = valid || (r.Method == "POST" && len(p) == 5 && action == "cancel")
	if !valid {
		problem(w, 404, "RUN_NOT_FOUND", "Route not found.")
		return
	}
	wait, ok := queryInt(w, r, "wait", 0, 0, 30)
	if !ok {
		return
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		s.mu.Lock()
		if s.expire() != nil {
			s.mu.Unlock()
			problem(w, 503, "SERVICE_UNAVAILABLE", "State storage is unavailable.")
			return
		}
		rr := s.state.Runs[p[3]]
		if rr == nil || rr.Owner != c.ID {
			s.mu.Unlock()
			problem(w, 404, "RUN_NOT_FOUND", "Run not found.")
			return
		}
		d := s.state.clone()
		rr = d.Runs[p[3]]
		j := d.Jobs[rr.JobID]
		changed := s.changed
		if action == "cancel" {
			if finished(rr.Run) && rr.Run.State != "cancelled" {
				s.mu.Unlock()
				problem(w, 409, "RUN_FINISHED", "The run already finished.")
				return
			}
			if rr.Run.CancelRequestedAt == nil {
				now := s.now()
				rr.Run.CancelRequestedAt = &now
				if rr.Run.State == "queued" {
					rr.Run.State = "cancelled"
					rr.Run.FinishedAt = &now
					rr.Run.Reason = &Reason{Code: "CANCELLED_BY_USER", Message: "Cancelled by the caller."}
					j.State = "cancelled"
					j.StartupHash = ""
					j.Logs.State = "complete"
				}
				if !s.persist(w, d) {
					s.mu.Unlock()
					return
				}
			}
			s.mu.Unlock()
			respond(w, 202, rr.Run)
			return
		}
		s.mu.Unlock()
		switch action {
		case "":
			b, _ := json.Marshal(rr.Run)
			etag := `"` + hash(b) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") != etag && r.Header.Get("If-None-Match") != "*" {
				respond(w, 200, rr.Run)
				return
			}
			if wait == 0 || !time.Now().Before(deadline) {
				w.WriteHeader(304)
				return
			}
		case "result":
			if !finished(rr.Run) {
				problem(w, 409, "RUN_NOT_FINISHED", "The run has not finished.")
				return
			}
			outputs := make([]Output, 0, len(j.Outputs))
			for _, o := range j.Outputs {
				outputs = append(outputs, Output{Path: o.Path, Kind: o.Kind, MediaType: o.MediaType, Digest: o.Digest, Size: o.Size})
			}
			respond(w, 200, struct {
				Run      string   `json:"run"`
				State    string   `json:"state"`
				ExitCode *int     `json:"exit_code,omitempty"`
				Reason   *Reason  `json:"reason,omitempty"`
				Outputs  []Output `json:"outputs"`
			}{rr.Run.ID, rr.Run.State, rr.Run.ExitCode, rr.Run.Reason, outputs})
			return
		case "outputs":
			problem(w, 404, "OUTPUT_NOT_FOUND", "Output bytes are not stored by this pool.")
			return
		case "logs":
			cursor, ok := parseCursor(w, r.URL.Query().Get("cursor"))
			if !ok {
				return
			}
			limit, ok := queryInt(w, r, "limit", 500, 1, 1000)
			if !ok {
				return
			}
			attempt, ok := queryInt(w, r, "attempt", max(1, j.Job.Attempt), 1, max(1, j.Job.Attempt))
			if !ok {
				return
			}
			if attempt != max(1, j.Job.Attempt) {
				problem(w, 400, "REQUEST_INVALID", "Unknown log attempt.")
				return
			}
			if cursor > j.Logs.Entries {
				problem(w, 400, "REQUEST_INVALID", "Cursor is beyond the log.")
				return
			}
			entries, e := readLogPage(s.cfg.StateDir, j, cursor, limit)
			if e != nil {
				problem(w, 503, "SERVICE_UNAVAILABLE", "Log storage is unavailable.")
				return
			}
			next := cursor
			if len(entries) > 0 {
				next = entries[len(entries)-1].Sequence
			}
			closed := finished(rr.Run) && j.Logs.State != "open"
			complete := closed && next == j.Logs.Entries
			if len(entries) > 0 || complete || wait == 0 || !time.Now().Before(deadline) {
				respond(w, 200, map[string]any{"run": rr.Run.ID, "entries": entries, "next_cursor": encodeCursor(next), "complete": complete, "log_state": j.Logs.State})
				return
			}
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func queryInt(w http.ResponseWriter, r *http.Request, name string, def, min, max int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < min || n > max {
		problem(w, 400, "REQUEST_INVALID", "Invalid "+name+" query parameter.")
		return 0, false
	}
	return n, true
}
func encodeCursor(n int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("seq:" + strconv.FormatInt(n, 10)))
}
func parseCursor(w http.ResponseWriter, v string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil || len(v) > 512 || !strings.HasPrefix(string(b), "seq:") {
		problem(w, 400, "REQUEST_INVALID", "Invalid cursor.")
		return 0, false
	}
	n, e := strconv.ParseInt(strings.TrimPrefix(string(b), "seq:"), 10, 64)
	if e != nil || n < 0 {
		problem(w, 400, "REQUEST_INVALID", "Invalid cursor.")
		return 0, false
	}
	return n, true
}

type fieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func validateCreate(in RunCreate, raw []byte) []fieldError {
	var failures []fieldError
	add := func(f, c string) { failures = append(failures, fieldError{f, c, "Invalid or conflicting field."}) }
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	check := func(prefix string, fields map[string]json.RawMessage, allowed, required []string) {
		for key, value := range fields {
			if !contains(allowed, key) {
				add(prefix+"/"+key, "UNKNOWN_FIELD")
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				add(prefix+"/"+key, "INVALID_FORMAT")
			}
		}
		for _, key := range required {
			if _, ok := fields[key]; !ok {
				add(prefix+"/"+key, "REQUIRED")
			}
		}
	}
	check("", top, []string{"repository", "commit", "ref", "operation"}, []string{"repository", "commit", "operation"})
	var repo, operation map[string]json.RawMessage
	_ = json.Unmarshal(top["repository"], &repo)
	_ = json.Unmarshal(top["operation"], &operation)
	check("/repository", repo, []string{"provider", "name"}, []string{"provider", "name"})
	check("/operation", operation, []string{"kind", "targets", "affected_base", "task"}, []string{"kind"})
	if in.Repository.Provider != "github" || !repositoryRE.MatchString(in.Repository.Name) {
		add("/repository", "INVALID_FORMAT")
	}
	if !commitRE.MatchString(in.Commit) {
		add("/commit", "INVALID_FORMAT")
	}
	if !utf8.ValidString(in.Ref) || utf8.RuneCountInString(in.Ref) > 255 || strings.ContainsAny(in.Ref, "\x00\r\n") {
		add("/ref", "INVALID_FORMAT")
	}
	var fields struct {
		Operation map[string]json.RawMessage `json:"operation"`
	}
	_ = json.Unmarshal(raw, &fields)
	op := in.Operation
	switch op.Kind {
	case "build":
		if _, yes := fields.Operation["task"]; yes {
			add("/operation/task", "UNKNOWN_FIELD")
		}
		_, targets := fields.Operation["targets"]
		_, affected := fields.Operation["affected_base"]
		if targets && affected {
			add("/operation/affected_base", "CONFLICTING_FIELDS")
		}
		if affected && !commitRE.MatchString(op.AffectedBase) {
			add("/operation/affected_base", "INVALID_FORMAT")
		}
		if len(op.Targets) > 100 {
			add("/operation/targets", "TOO_LONG")
		}
		seen := map[string]bool{}
		for _, t := range op.Targets {
			if !targetRE.MatchString(t) || seen[t] {
				add("/operation/targets", "INVALID_FORMAT")
				break
			}
			seen[t] = true
		}
	case "run":
		if !taskRE.MatchString(op.Task) {
			add("/operation/task", "INVALID_FORMAT")
		}
		for _, k := range []string{"targets", "affected_base"} {
			if _, yes := fields.Operation[k]; yes {
				add("/operation/"+k, "UNKNOWN_FIELD")
			}
		}
	default:
		add("/operation/kind", "INVALID_FORMAT")
	}
	return failures
}
func (s *Server) createRun(w http.ResponseWriter, r *http.Request, c caller) {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		problem(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Use application/json.")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if e != nil {
		problem(w, 400, "REQUEST_INVALID", "Request is too large.")
		return
	}
	var fields map[string]json.RawMessage
	if !utf8.Valid(raw) || json.Unmarshal(raw, &fields) != nil || fields == nil {
		problem(w, 400, "REQUEST_INVALID", "Expected one JSON request object.")
		return
	}
	var in RunCreate
	decodeErr := json.Unmarshal(raw, &in)
	errs := validateCreate(in, raw)
	if decodeErr != nil {
		errs = append(errs, fieldError{Field: "/", Code: "INVALID_FORMAT", Message: "A field has the wrong JSON type."})
	}
	if len(errs) > 0 {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(422)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:oyzu:problem:validation-failed", "title": "Request validation failed", "status": 422, "code": "VALIDATION_FAILED", "request_id": w.Header().Get("X-Request-Id"), "errors": errs})
		return
	}
	if !contains(s.cfg.Repositories, in.Repository.Name) {
		problem(w, 403, "PERMISSION_DENIED", "Repository is not allowed by this pool.")
		return
	}
	if c.Claims != nil && (c.Claims.Repository != in.Repository.Name || c.Claims.SHA != in.Commit || c.Claims.Ref != in.Ref) {
		problem(w, 403, "PERMISSION_DENIED", "Run source must equal the Actions token claims.")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) > 200 || (r.Header.Values("Idempotency-Key") != nil && key == "") {
		problem(w, 400, "REQUEST_INVALID", "Invalid idempotency key.")
		return
	}
	canonical, _ := json.Marshal(in)
	bodyHash := hash(canonical)
	s.mu.Lock()
	if s.idempotent(w, c.ID, key, bodyHash) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	exists, e := s.source.CommitExists(r.Context(), in.Repository.Name, in.Commit)
	if e != nil {
		w.Header().Set("Retry-After", "5")
		problem(w, 503, "SERVICE_UNAVAILABLE", "Repository source is unavailable.")
		return
	}
	if !exists {
		problem(w, 422, "COMMIT_NOT_FOUND", "The commit must be pushed before starting a run.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storageErr != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "State storage is unavailable.")
		return
	}
	if s.idempotent(w, c.ID, key, bodyHash) {
		return
	}
	d := s.state.clone()
	d.Meta.NextID++
	id := d.Meta.NextID
	rid := randomToken()[:32]
	now := s.now()
	self := "/api/v1alpha1/accounts/" + s.cfg.Account + "/runs/" + rid
	run := Run{ID: rid, Account: s.cfg.Account, Project: projectID(in.Repository.Name), Repository: in.Repository, Commit: in.Commit, Ref: in.Ref, Operation: in.Operation, Trigger: Trigger{Kind: "manual", Actor: c.Actor}, State: "queued", CreatedAt: now, Links: Links{Self: self, Logs: self + "/logs", Result: self + "/result"}}
	command := []string{"oyzu", "build", "--isolated", "--full"}
	if in.Operation.Kind == "run" {
		command = []string{"oyzu", "run", "--isolated", in.Operation.Task}
	} else if in.Operation.AffectedBase != "" {
		command = append(command, "--affected", in.Operation.AffectedBase)
	} else {
		command = append(command, in.Operation.Targets...)
	}
	job := runnerclient.Job{ID: id, RunID: id, Kind: "build", CorrelationID: rid, Repository: in.Repository.Name, HeadSHA: in.Commit, HeadBranch: in.Ref, Operation: in.Operation.Kind, Targets: in.Operation.Targets, Task: in.Operation.Task, AffectedBase: in.Operation.AffectedBase, Command: command, Secrets: []string{}}
	d.Runs[rid] = &runRecord{Run: run, Owner: c.ID, BodyHash: bodyHash, Idempotency: key, JobID: id}
	d.Jobs[id] = &jobRecord{Job: job, State: "queued", Logs: logRecord{State: "open"}, Outputs: []runnerclient.Output{}}
	if !s.persist(w, d) {
		return
	}
	w.Header().Set("Location", self)
	respond(w, 201, run)
}
func (s *Server) idempotent(w http.ResponseWriter, owner, key, bodyHash string) bool {
	if key == "" {
		return false
	}
	for _, rr := range s.state.Runs {
		if rr.Owner == owner && rr.Idempotency == key {
			if rr.BodyHash != bodyHash {
				problem(w, 409, "IDEMPOTENCY_KEY_REUSED", "The key was already used with another request.")
			} else {
				w.Header().Set("Location", rr.Run.Links.Self)
				respond(w, 200, rr.Run)
			}
			return true
		}
	}
	return false
}
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, c caller) {
	q := r.URL.Query()
	if v := q.Get("repository"); v != "" && (!strings.HasPrefix(v, "github:") || !repositoryRE.MatchString(strings.TrimPrefix(v, "github:"))) {
		problem(w, 400, "REQUEST_INVALID", "Invalid repository filter.")
		return
	}
	if v := q.Get("commit"); v != "" && !commitRE.MatchString(v) {
		problem(w, 400, "REQUEST_INVALID", "Invalid commit filter.")
		return
	}
	if v := q.Get("state"); v != "" {
		for _, state := range strings.Split(v, ",") {
			if !contains([]string{"queued", "running", "succeeded", "failed", "skipped", "cancelled", "timed_out"}, state) {
				problem(w, 400, "REQUEST_INVALID", "Invalid state filter.")
				return
			}
		}
	}
	size, ok := queryInt(w, r, "page_size", 25, 1, 100)
	if !ok {
		return
	}
	var beforeID string
	if v := r.URL.Query().Get("cursor"); v != "" {
		b, e := base64.RawURLEncoding.DecodeString(v)
		if e != nil || len(v) > 512 {
			problem(w, 400, "REQUEST_INVALID", "Invalid cursor.")
			return
		}
		beforeID = string(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expire() != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "State storage is unavailable.")
		return
	}
	items := []Run{}
	states := strings.Split(q.Get("state"), ",")
	for _, rr := range s.state.Runs {
		v := rr.Run
		if rr.Owner != c.ID {
			continue
		}
		if f := q.Get("repository"); f != "" && f != v.Repository.Provider+":"+v.Repository.Name {
			continue
		}
		if f := q.Get("commit"); f != "" && f != v.Commit {
			continue
		}
		if q.Get("state") != "" && !contains(states, v.State) {
			continue
		}
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if beforeID != "" {
		index := -1
		for i, v := range items {
			if v.ID == beforeID {
				index = i
				break
			}
		}
		if index < 0 {
			problem(w, 400, "REQUEST_INVALID", "Invalid cursor.")
			return
		}
		items = items[index+1:]
	}
	var next *string
	if len(items) > size {
		v := base64.RawURLEncoding.EncodeToString([]byte(items[size-1].ID))
		next = &v
		items = items[:size]
	}
	respond(w, 200, map[string]any{"items": items, "next_cursor": next})
}
