package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

func eventLine(kind, operation, parent, action, status string) string {
	b, _ := json.Marshal(map[string]any{"schemaVersion": "v1alpha1", "kind": "build-event", "operationId": operation, "parentOperationId": parent,
		"payload": map[string]any{"type": kind, "action": action, "status": status, "reason": "dependency failed"}})
	return string(b) + "\n"
}

func TestLogScopesAndUnknownEvents(t *testing.T) {
	var scopes logScopes
	if e := scopes.entry("stderr", "before\n", 0); e.Scope != "oyzu" {
		t.Fatal(e)
	}
	e := scopes.entry("stderr", eventLine("action-started", "compile", "backend", "compile", ""), 0)
	if e.Stream != "system" || e.Event.Kind != "task" || e.Event.State != "running" || e.ParentScope != "backend" {
		t.Fatal(e)
	}
	if e := scopes.entry("stdout", "native\r\n", 0); e.Scope != "compile" || e.Text != "native\r\n" {
		t.Fatal(e)
	}
	scopes.entry("stderr", eventLine("action-started", "test", "backend", "test", ""), 0)
	if e := scopes.entry("stderr", "interleaved\n", 0); e.Scope != "oyzu" {
		t.Fatal(e)
	}
	e = scopes.entry("stderr", eventLine("action-finished", "test", "backend", "test", "blocked"), 0)
	if e.Event.State != "blocked" || e.Event.Reason != "dependency failed" {
		t.Fatal(e)
	}
	if e := scopes.entry("stderr", "native\n", 0); e.Scope != "compile" {
		t.Fatal(e)
	}
	for _, line := range []string{"{broken\n", eventLine("future-kind", "x", "", "", ""), `{"kind":"future","payload":{}}` + "\n"} {
		e := scopes.entry("stderr", line, 0)
		if e.Text != line || e.Event != nil || e.Stream != "stderr" {
			t.Fatal(e)
		}
	}
	e = scopes.entry("stderr", eventLine("action-finished", "compile", "backend", "compile", "succeeded"), 0)
	if e.Event.Kind != "finished" || e.Event.Status != "succeeded" {
		t.Fatal(e)
	}
	if e := scopes.entry("stderr", "after\n", 0); e.Scope != "oyzu" {
		t.Fatal(e)
	}
	diagnostic := `{"schemaVersion":"v1alpha1","kind":"build-event","operationId":"compile","extra":42,"payload":{"type":"diagnostic","diagnostic":{"message":"masked ***","severity":"warning"}}}` + "\n"
	if e := scopes.entry("stderr", diagnostic, 1); e.Text != "masked ***\n" || e.Scope != "compile" || e.Redacted != 1 {
		t.Fatal(e)
	}
}

type logReceiver struct {
	mu      sync.Mutex
	chunks  []runnerclient.LogChunk
	raw     []byte
	finish  *runnerclient.LogFinish
	calls   []int64
	loseAck bool
	gap     bool
	seen    chan struct{}
}

func (r *logReceiver) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.Header.Get("Authorization") != "Bearer job-token" {
		w.WriteHeader(401)
		return
	}
	if strings.HasSuffix(req.URL.Path, "/finish") {
		var in runnerclient.LogFinish
		_ = json.NewDecoder(req.Body).Decode(&in)
		r.finish = &in
		_ = json.NewEncoder(w).Encode(runnerclient.LogAck{NextSeq: int64(len(r.chunks) + 1), State: "complete"})
		return
	}
	var in runnerclient.LogChunk
	_ = json.NewDecoder(req.Body).Decode(&in)
	r.calls = append(r.calls, in.Seq)
	if r.gap && in.Seq == 2 {
		r.gap = false
		r.chunks = nil
		r.raw = nil
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"next_seq":1}`)
		return
	}
	if in.Seq == int64(len(r.chunks)+1) {
		gz, err := gzip.NewReader(bytes.NewReader(in.Data))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		b, err := io.ReadAll(gz)
		_ = gz.Close()
		h := sha256.Sum256(b)
		if err != nil || in.Hash != hex.EncodeToString(h[:]) {
			w.WriteHeader(400)
			return
		}
		r.chunks = append(r.chunks, in)
		r.raw = append(r.raw, b...)
		select {
		case r.seen <- struct{}{}:
		default:
		}
	} else if in.Seq < 1 || in.Seq > int64(len(r.chunks)) || r.chunks[in.Seq-1].Hash != in.Hash {
		w.WriteHeader(409)
		return
	}
	if r.loseAck {
		r.loseAck = false
		w.WriteHeader(503)
		return
	}
	_ = json.NewEncoder(w).Encode(runnerclient.LogAck{NextSeq: int64(len(r.chunks) + 1), State: "open"})
}

func captureForTest(t *testing.T, handler http.Handler) *logCapture {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := Config{Client: runnerclient.New(srv.URL, srv.Client()), WorkDir: filepath.Join(t.TempDir(), "checkout")}
	c := newLogCapture(context.Background(), cfg, "job-token", runnerclient.Job{Attempt: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		c.cancel()
		<-c.done
		<-c.tickDone
		if c.file != nil {
			_ = c.file.Close()
		}
		if c.tail != nil {
			_ = c.tail.file.Close()
		}
		if c.dir != "" {
			_ = os.RemoveAll(c.dir)
		}
	})
	return c
}

func logEntries(t *testing.T, r *logReceiver) []runnerclient.LogEntry {
	t.Helper()
	var out []runnerclient.LogEntry
	for _, line := range bytes.Split(bytes.TrimSpace(r.raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e runnerclient.LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.Sequence != int64(len(out)+1) {
			t.Fatalf("sequence %d after %d", e.Sequence, len(out))
		}
		out = append(out, e)
	}
	return out
}

func TestLogMaskingSpoolAndTail(t *testing.T) {
	r := &logReceiver{}
	c := captureForTest(t, http.HandlerFunc(r.serve))
	var tail tail
	sink := &logSink{dst: &tail, capture: c, stream: "stdout"}
	m := newMaskWriter(sink, maskForms("original-secret"))
	_, _ = m.Write([]byte("literal *** and original-"))
	_, _ = m.Write([]byte("secret\n"))
	m.Add("new-secret")
	_, _ = m.Write([]byte("new-"))
	_, _ = m.Write([]byte("secret\n"))
	_ = m.Flush()
	sink.close()
	c.mu.Lock()
	c.seal()
	c.mu.Unlock()
	b, err := os.ReadFile(c.file.Name())
	if err != nil || bytes.Contains(b, []byte("original-secret")) || bytes.Contains(b, []byte("new-secret")) {
		t.Fatal("spool contains unmasked output", err)
	}
	c.finish(time.Second)
	e := logEntries(t, r)
	if len(e) != 2 || e[0].Redacted != 1 || e[1].Redacted != 1 || tail.String() != "literal *** and ***\n***" {
		t.Fatalf("entries=%+v tail=%q", e, tail.String())
	}
	if r.finish == nil || r.finish.Hash != hexHash(r.raw) || r.finish.TotalEntries != 2 {
		t.Fatal(r.finish)
	}
}

func hexHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestLogChunkTriggersAndReplay(t *testing.T) {
	for _, trigger := range []string{"entries", "bytes", "time"} {
		t.Run(trigger, func(t *testing.T) {
			r := &logReceiver{loseAck: true, gap: trigger != "time", seen: make(chan struct{}, 16)}
			c := captureForTest(t, http.HandlerFunc(r.serve))
			switch trigger {
			case "entries":
				for range 2001 {
					c.line("stdout", "x\n", 0)
				}
			case "bytes":
				for range 12 {
					c.line("stdout", strings.Repeat("x", maxLogText), 0)
				}
			case "time":
				c.line("stdout", "tick\n", 0)
			}
			select {
			case <-r.seen:
			case <-time.After(3 * time.Second):
				t.Error("chunk did not upload while running")
			}
			c.finish(5 * time.Second)
			entries := logEntries(t, r)
			if len(entries) == 0 || r.finish == nil || r.finish.Hash != hexHash(r.raw) {
				t.Fatal("unfinished log")
			}
			if len(r.calls) < 2 || r.calls[0] != 1 || r.calls[1] != 1 {
				t.Fatalf("lost acknowledgement not retried: %v", r.calls)
			}
			if trigger != "time" && r.gap {
				t.Fatal("gap path was not reached")
			}
			for _, part := range r.chunks {
				if part.Entries > 1000 {
					t.Fatal("entry trigger exceeded")
				}
			}
		})
	}
}

func TestLogCapKeepsHeadAndTail(t *testing.T) {
	r := &logReceiver{}
	c := captureForTest(t, http.HandlerFunc(r.serve))
	c.capBytes = 32 << 10
	for i := range 1000 {
		text := "middle" + strings.Repeat("x", 200) + "\n"
		if i == 0 {
			text = "head\n"
		}
		if i == 999 {
			text = "tail\n"
		}
		c.line("stdout", text, 0)
	}
	c.finish(time.Second)
	e := logEntries(t, r)
	if len(r.raw) > 32<<10 || e[0].Text != "head\n" || e[len(e)-1].Text != "tail\n" {
		t.Fatal("cap did not preserve boundaries")
	}
	notices := 0
	for _, entry := range e {
		if strings.Contains(entry.Text, "dropped") {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("drop notices=%d", notices)
	}
}

func TestLogTextLimitsAndInvalidUTF8(t *testing.T) {
	r := &logReceiver{}
	c := captureForTest(t, http.HandlerFunc(r.serve))
	sink := &logSink{dst: io.Discard, capture: c, stream: "stderr"}
	in := strings.Repeat("世", 30000) + strings.Repeat("\xff", 30000) + "\r\nlast"
	_, _ = sink.Write([]byte(in))
	sink.close()
	c.finish(time.Second)
	var joined strings.Builder
	for _, e := range logEntries(t, r) {
		if !utf8.ValidString(e.Text) || len(e.Text) > maxLogText {
			t.Fatal("invalid text boundary")
		}
		joined.WriteString(e.Text)
	}
	// Each invalid byte is replaced with U+FFFD.
	want := strings.Repeat("世", 30000) + strings.Repeat("�", 30000) + "\r\nlast"
	if joined.String() != want {
		t.Fatal("text or line endings lost")
	}
}

func TestLogMaskAcrossEntryAndUploadBoundaries(t *testing.T) {
	r := &logReceiver{}
	c := captureForTest(t, http.HandlerFunc(r.serve))
	sink := &logSink{dst: io.Discard, capture: c, stream: "stdout"}
	m := newMaskWriter(sink, maskForms("original-secret"))
	_, _ = m.Write([]byte(strings.Repeat("x", logChunkBytes-3) + "original-"))
	_, _ = m.Write([]byte("secret\n"))
	m.Add("learned-mid-run")
	_, _ = m.Write([]byte(strings.Repeat("y", maxLogText-2) + "learned-mid-"))
	_, _ = m.Write([]byte("run\n"))
	_ = m.Flush()
	sink.close()
	c.finish(time.Second)
	var text strings.Builder
	redacted := 0
	for _, e := range logEntries(t, r) {
		text.WriteString(e.Text)
		redacted += e.Redacted
	}
	if len(r.chunks) < 2 || redacted != 2 || strings.Contains(text.String(), "original-secret") || strings.Contains(text.String(), "learned-mid-run") {
		t.Fatal("masking failed across entry/chunk boundaries")
	}
	if strings.Count(text.String(), "***") != 2 {
		t.Fatal("replacement markers were torn or lost")
	}
}

func TestLogDrainGivesUpAndSpoolFailure(t *testing.T) {
	c := captureForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	c.line("stdout", "still a successful build\n", 0)
	start := time.Now()
	c.finish(40 * time.Millisecond)
	if time.Since(start) > time.Second {
		t.Fatal("drain did not give up")
	}
	if _, err := os.Stat(c.dir); !os.IsNotExist(err) {
		t.Fatal("spool was not removed after closing files")
	}
	r := &logReceiver{}
	c = captureForTest(t, http.HandlerFunc(r.serve))
	_ = c.file.Close()
	c.line("stdout", "cannot spool\n", 0)
	c.finish(time.Second)
	if r.finish == nil || !r.finish.Incomplete {
		t.Fatal("spool failure not reported")
	}
}
