package executor

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

const maxLogText = 64 << 10

// logSink preserves the existing summary/plan sink and builds entries beside
// it, after masking. Capture errors never become command pipe errors.
type logSink struct {
	mu      sync.Mutex
	dst     io.Writer
	capture *logCapture
	stream  string
	part    []byte
	hits    []int
}

func (s *logSink) Write(p []byte) (int, error) { return len(p), s.WriteMasked(p, nil) }

func (s *logSink) WriteMasked(p []byte, hits []int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.dst.Write(p); err != nil {
		return err
	}
	for _, pos := range hits {
		s.hits = append(s.hits, len(s.part)+pos)
	}
	s.part = append(s.part, p...)
	s.flush(false)
	return nil
}

func (s *logSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flush(true)
}

func (s *logSink) flush(final bool) {
	for len(s.part) > 0 {
		n := strings.IndexByte(string(s.part), '\n') + 1
		if n == 0 && len(s.part) < maxLogText && !final {
			return
		}
		if n == 0 {
			n = len(s.part)
		}
		n = min(n, maxLogText)
		// Normalize incrementally so invalid bytes cannot expand an entry
		// beyond 64 KiB and a split never tears a valid UTF-8 rune.
		var text strings.Builder
		used := 0
		for used < n {
			if !final && !utf8.FullRune(s.part[used:]) {
				break
			}
			r, size := utf8.DecodeRune(s.part[used:])
			if text.Len()+utf8.RuneLen(r) > maxLogText {
				break
			}
			text.WriteRune(r)
			used += size
		}
		if used == 0 {
			return
		}
		redacted := 0
		var rest []int
		for _, pos := range s.hits {
			if pos < used {
				redacted++
			} else {
				rest = append(rest, pos-used)
			}
		}
		s.hits = rest
		s.part = s.part[used:]
		s.capture.line(s.stream, text.String(), redacted)
	}
}

type logScopes struct{ active map[string][]string }

func (s *logScopes) entry(stream, line string, redacted int) runnerclient.LogEntry {
	e := runnerclient.LogEntry{Stream: stream, Time: time.Now().UTC(), Text: line, Scope: "oyzu", Redacted: redacted}
	if len(s.active) == 1 {
		for scope, parents := range s.active {
			if len(parents) == 1 {
				e.Scope, e.ParentScope = scope, parents[0]
			}
		}
	}
	if stream != "stderr" {
		return e
	}
	var envelope struct {
		SchemaVersion string    `json:"schemaVersion"`
		Kind          string    `json:"kind"`
		Timestamp     time.Time `json:"timestamp"`
		Operation     string    `json:"operationId"`
		Parent        string    `json:"parentOperationId"`
		Target        string    `json:"target"`
		Duration      *int64    `json:"duration_ms"`
		Payload       struct {
			Type       string          `json:"type"`
			Action     json.RawMessage `json:"action"`
			Target     string          `json:"target"`
			Operation  string          `json:"operationId"`
			Parent     string          `json:"parentOperationId"`
			Status     string          `json:"status"`
			Reason     string          `json:"reason"`
			Phase      string          `json:"phase"`
			ExitCode   *int            `json:"exitCode"`
			Duration   *int64          `json:"duration_ms"`
			Diagnostic struct {
				Message string `json:"message"`
				Target  string `json:"target"`
				Action  string `json:"action"`
			} `json:"diagnostic"`
		} `json:"payload"`
	}
	if json.Unmarshal([]byte(line), &envelope) != nil || envelope.SchemaVersion != "v1alpha1" || envelope.Kind != "build-event" {
		return e
	}
	p := envelope.Payload
	switch p.Type {
	case "run-started", "phase-changed", "action-started", "action-finished", "diagnostic", "bundle-finalized", "run-finished":
	default:
		return e // additive, unknown events remain lossless text
	}
	var action string
	if json.Unmarshal(p.Action, &action) != nil {
		var a struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Target string `json:"target"`
		}
		_ = json.Unmarshal(p.Action, &a)
		action = firstString(a.ID, a.Name)
		p.Target = firstString(p.Target, a.Target)
	}
	e.Scope = firstString(envelope.Operation, p.Operation, action, p.Diagnostic.Action, envelope.Target, p.Target, p.Diagnostic.Target, "oyzu")
	e.ParentScope = firstString(envelope.Parent, p.Parent)
	target := firstString(envelope.Target, p.Target, p.Diagnostic.Target)
	if e.ParentScope == "" && (action != "" || p.Diagnostic.Action != "") && e.Scope != target {
		e.ParentScope = target
	}
	if !envelope.Timestamp.IsZero() {
		e.Time = envelope.Timestamp
	}
	if p.Type == "diagnostic" {
		e.Text = p.Diagnostic.Message
		if strings.HasSuffix(line, "\r\n") {
			e.Text += "\r\n"
		} else if strings.HasSuffix(line, "\n") {
			e.Text += "\n"
		}
		return e
	}
	e.Stream = "system"
	duration := envelope.Duration
	if duration == nil {
		duration = p.Duration
	}
	switch p.Type {
	case "run-started", "phase-changed":
		e.Event = &runnerclient.LogEvent{Kind: "task", State: "running", Reason: p.Phase}
	case "bundle-finalized":
		e.Event = &runnerclient.LogEvent{Kind: "finished", Status: p.Status, DurationMS: duration}
	case "action-started":
		if s.active == nil {
			s.active = map[string][]string{}
		}
		s.active[e.Scope] = append(s.active[e.Scope], e.ParentScope)
		e.Event = &runnerclient.LogEvent{Kind: "task", State: "running"}
	case "action-finished":
		if parents := s.active[e.Scope]; len(parents) > 1 {
			s.active[e.Scope] = parents[:len(parents)-1]
		} else {
			delete(s.active, e.Scope)
		}
		if p.Status == "blocked" {
			e.Event = &runnerclient.LogEvent{Kind: "task", State: "blocked", Reason: p.Reason}
		} else {
			e.Event = &runnerclient.LogEvent{Kind: "finished", Status: p.Status, ExitCode: p.ExitCode, DurationMS: duration}
		}
	case "run-finished":
		clear(s.active)
		e.Event = &runnerclient.LogEvent{Kind: "finished", Status: p.Status, ExitCode: p.ExitCode, DurationMS: duration}
	}
	return e
}

func firstString(values ...string) string {
	for _, s := range values {
		if s != "" {
			return s
		}
	}
	return ""
}
