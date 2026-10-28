package poolserver

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

// stageCheck is private, durable delivery state. Revision changes with the
// desired result; Published and AnnotationsSent advance only after GitHub
// accepts a write. It is owned by a run and scope, not by a log chunk.
type stageCheck struct {
	ID              int64  `json:"id,omitempty"`
	Revision        int64  `json:"revision"`
	Published       int64  `json:"published,omitempty"`
	Conclusion      string `json:"conclusion,omitempty"`
	Missing         bool   `json:"missing,omitempty"`
	AnnotationsSent int    `json:"annotations_sent,omitempty"`
}

func stageScope(scope string) (string, string, bool) {
	parts := strings.Split(scope, ":")
	if len(parts) != 2 || !targetRE.MatchString(parts[0]) || !targetRE.MatchString(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func stageConclusion(status string) string {
	switch status {
	case "success":
		return "success"
	case "failed":
		return "failure"
	case "skipped":
		return "skipped"
	case "cancelled":
		return "cancelled"
	default:
		return "neutral"
	}
}

func observeStageLogs(rr *runRecord, entries []runnerclient.LogEntry) {
	if rr.Run.Source != nil {
		return
	}
	for _, entry := range entries {
		if _, _, ok := stageScope(entry.Scope); !ok {
			continue
		}
		if rr.Checks == nil {
			rr.Checks = map[string]*stageCheck{}
		}
		c := rr.Checks[entry.Scope]
		if c == nil {
			c = &stageCheck{Revision: 1}
			rr.Checks[entry.Scope] = c
		}
		if entry.Event != nil && entry.Event.Kind == "finished" {
			c.Conclusion = stageConclusion(entry.Event.Status)
			c.Missing = false
			c.Revision++
		}
	}
	// Logs can drain after job/finish. New scopes still need a terminal result;
	// a later finished event may replace this fallback with the real result.
	if finished(rr.Run) {
		finishStageChecks(rr)
	}
}

func finishStageChecks(rr *runRecord) {
	for _, c := range rr.Checks {
		if c.Conclusion == "" {
			c.Conclusion = "failure"
			c.Missing = true
			if rr.Run.State == "cancelled" {
				c.Conclusion = "cancelled"
				c.Missing = false
			}
		}
		// Finish can add JUnit failures even to already completed scopes.
		c.Revision++
	}
}

func validTestFailures(failures []runnerclient.TestFailure) bool {
	if len(failures) > 200 {
		return false
	}
	for _, f := range failures {
		if f.Scope == "" || len(f.Scope) > 512 || !utf8.ValidString(f.Scope) || f.Name == "" || len(f.Name) > 1024 || !utf8.ValidString(f.Name) || len(f.Classname) > 1024 || !utf8.ValidString(f.Classname) || f.Message == "" || len(f.Message) > 1024 || !utf8.ValidString(f.Message) || f.Line < 0 {
			return false
		}
		if f.Path != "" && (len(f.Path) > 1024 || !utf8.ValidString(f.Path) || strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\\:\x00\r\n") || contains(strings.Split(f.Path, "/"), "..")) {
			return false
		}
	}
	return true
}

type checkAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Title           string `json:"title"`
	Message         string `json:"message"`
}

type checkOutput struct {
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Annotations []checkAnnotation `json:"annotations,omitempty"`
}

func checkText(rr *runRecord, scope string, c *stageCheck) (checkOutput, []checkAnnotation) {
	target, stage, _ := stageScope(scope)
	out := checkOutput{Title: "oyzu / " + target + " / " + stage, Summary: "Stage in progress."}
	if c.Conclusion != "" {
		out.Summary = "Stage result: " + c.Conclusion + "."
	}
	if c.Missing {
		out.Summary = "stage did not report a result"
	}
	var annotations []checkAnnotation
	for _, f := range rr.TestFailures {
		if f.Scope != scope {
			continue
		}
		title := f.Name
		if f.Classname != "" {
			title = f.Classname + ": " + title
		}
		if f.Path == "" {
			out.Summary += "\n\n" + title + "\n" + f.Message
			continue
		}
		line := f.Line
		if line == 0 {
			line = 1
		}
		annotations = append(annotations, checkAnnotation{Path: f.Path, StartLine: line, EndLine: line, AnnotationLevel: "failure", Title: checkTruncate(title, 255), Message: f.Message})
	}
	out.Summary = checkTruncate(out.Summary, 60<<10)
	return out, annotations
}

func checkTruncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit-len("\n[truncated]")]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "\n[truncated]"
}

// enqueueChecksLocked is called with mu held after durable acceptance. Requests
// only mark a run dirty; the Reap-owned publisher handles all GitHub I/O.
func (s *Server) enqueueChecksLocked(runID string) {
	if s.checks == nil {
		return
	}
	s.dirtyChecks[runID] = struct{}{}
	select {
	case s.checkWake <- struct{}{}:
	default:
	}
}

func (s *Server) retryChecks() {
	if s.checks == nil {
		return
	}
	s.mu.Lock()
	if s.now().Before(s.nextChecks) {
		s.mu.Unlock()
		return
	}
	s.nextChecks = s.now().Add(30 * time.Second)
	for id, rr := range s.state.Runs {
		for _, c := range rr.Checks {
			if c.Published != c.Revision {
				s.enqueueChecksLocked(id)
				break
			}
		}
	}
	s.mu.Unlock()
}

func (s *Server) runCheckPublisher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.checkWake:
			s.flushChecks(ctx)
		}
	}
}

// flushChecks drains accepted work and serializes delivery. Tests can drain the
// same queue deterministically without starting a lifecycle goroutine.
func (s *Server) flushChecks(ctx context.Context) {
	s.checksMu.Lock()
	defer s.checksMu.Unlock()
	for ctx.Err() == nil {
		s.mu.Lock()
		var ids []string
		for id := range s.dirtyChecks {
			ids = append(ids, id)
		}
		s.mu.Unlock()
		if len(ids) == 0 {
			return
		}
		sort.Strings(ids)
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			delete(s.dirtyChecks, id)
			s.mu.Unlock()
			s.publishChecks(ctx, id)
		}
	}
}

func (s *Server) publishChecks(ctx context.Context, runID string) {
	s.mu.Lock()
	rr := s.state.clone().Runs[runID]
	s.mu.Unlock()
	if rr == nil || rr.Run.Source != nil || !commitRE.MatchString(rr.Run.Commit) {
		return
	}
	var scopes []string
	for scope, c := range rr.Checks {
		if c.Published != c.Revision {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		return
	}
	sort.Strings(scopes)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, scope := range scopes {
		c := rr.Checks[scope]
		if err := s.publishStageCheck(ctx, rr, scope, c); err != nil {
			// Deliberately omit response bodies, URLs, errors and tokens.
			log.Printf("pool checks: run %s scope %s: GitHub check delivery incomplete", runID, scope)
		}
	}
}

func (s *Server) publishStageCheck(ctx context.Context, rr *runRecord, scope string, c *stageCheck) error {
	out, annotations := checkText(rr, scope, c)
	if c.ID == 0 {
		id, err := s.checks.ensureCheck(ctx, rr, scope, out.Title)
		if err != nil {
			return err
		}
		c.ID = id
		if err = s.recordCheckDelivery(rr.Run.ID, scope, c); err != nil {
			return err
		}
	}
	for {
		end := c.AnnotationsSent + 50
		if end > len(annotations) {
			end = len(annotations)
		}
		out.Annotations = annotations[c.AnnotationsSent:end]
		body := map[string]any{"output": out, "status": "in_progress"}
		if c.Conclusion != "" {
			body["status"] = "completed"
			body["conclusion"] = c.Conclusion
		}
		err := s.checks.checkRequest(ctx, rr.Run.Repository.Name, "PATCH", fmt.Sprintf("/repos/%s/check-runs/%d", rr.Run.Repository.Name, c.ID), body, nil)
		if err != nil {
			return err
		}
		c.AnnotationsSent = end
		if end == len(annotations) {
			c.Published = c.Revision
		}
		if err = s.recordCheckDelivery(rr.Run.ID, scope, c); err != nil {
			return err
		}
		if c.Published == c.Revision {
			return nil
		}
	}
}

func (s *Server) recordCheckDelivery(runID, scope string, delivered *stageCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.state.clone()
	rr := d.Runs[runID]
	if rr == nil || rr.Checks[scope] == nil {
		return nil
	}
	c := rr.Checks[scope]
	c.ID = delivered.ID
	c.AnnotationsSent = delivered.AnnotationsSent
	c.Published = delivered.Published
	return s.commit(d)
}
