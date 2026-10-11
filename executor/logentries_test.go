package executor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

func lifecycleLine(payload string) string {
	return `{"schemaVersion":"v1alpha1","kind":"build-event","operationId":"cli:build","payload":` + payload + "}\n"
}

func TestLogLifecycleText(t *testing.T) {
	exit, duration := 1, int64(3200)
	for _, tc := range []struct {
		name, payload, text string
		event               runnerclient.LogEvent
	}{
		{"run", `{"type":"run-started","context":{}}`, "oyzu started.\n", runnerclient.LogEvent{Kind: "task", State: "running"}},
		{"run-phase", `{"type":"run-started","phase":"planning"}`, "oyzu started (phase: planning).\n", runnerclient.LogEvent{Kind: "task", State: "running"}},
		{"phase", `{"type":"phase-changed","phase":"execution"}`, "Phase: execution.\n", runnerclient.LogEvent{Kind: "task", State: "running"}},
		{"start", `{"type":"action-started","action":"cli:build"}`, "Started cli:build.\n", runnerclient.LogEvent{Kind: "task", State: "running"}},
		{"failed", `{"type":"action-finished","status":"failed","exitCode":1,"duration_ms":3200}`, "cli:build failed (exit 1, 3.2 s).\n", runnerclient.LogEvent{Kind: "finished", Status: "failed", ExitCode: &exit, DurationMS: &duration}},
		{"blocked", `{"type":"action-finished","status":"blocked","reason":"dependency failed"}`, "cli:build was blocked: dependency failed.\n", runnerclient.LogEvent{Kind: "task", State: "blocked", Reason: "dependency failed"}},
		{"blocked-no-reason", `{"type":"action-finished","status":"blocked"}`, "cli:build was blocked.\n", runnerclient.LogEvent{Kind: "task", State: "blocked"}},
		{"cached", `{"type":"action-finished","status":"cached","reason":"ignored"}`, "cli:build cached.\n", runnerclient.LogEvent{Kind: "finished", Status: "cached"}},
		{"bundle", `{"type":"bundle-finalized","status":"succeeded"}`, "Bundle finalized: succeeded.\n", runnerclient.LogEvent{Kind: "finished", Status: "succeeded"}},
		{"finish", `{"type":"run-finished","status":"failed","exitCode":1}`, "oyzu finished: failed (exit 1).\n", runnerclient.LogEvent{Kind: "finished", Status: "failed", ExitCode: &exit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var scopes logScopes
			e := scopes.entry("stderr", lifecycleLine(tc.payload), 0)
			if e.Text != tc.text || e.Stream != "system" || !reflect.DeepEqual(e.Event, &tc.event) {
				t.Fatalf("entry=%+v event=%+v; want text=%q event=%+v", e, e.Event, tc.text, tc.event)
			}
		})
	}
}

func TestRunLogSummaryReadableEvents(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build", "cli"))
	t.Setenv("FAKE_OYZU_EVENTS", lifecycleLine(`{"type":"run-started","context":{}}`)+
		lifecycleLine(`{"type":"phase-changed","phase":"execution"}`)+
		lifecycleLine(`{"type":"action-started","action":"cli:build"}`)+
		"native stderr\r\n"+
		lifecycleLine(`{"type":"diagnostic","diagnostic":{"severity":"info","message":"building cli"}}`)+
		lifecycleLine(`{"type":"diagnostic","diagnostic":{"severity":"warning","message":"check cache"}}`)+
		lifecycleLine(`{"type":"diagnostic","diagnostic":{"severity":"error","message":"source ghs_secret"}}`)+
		lifecycleLine(`{"type":"action-finished","status":"succeeded"}`)+
		lifecycleLine(`{"type":"bundle-finalized","status":"succeeded"}`)+
		lifecycleLine(`{"type":"run-finished","status":"succeeded","exitCode":0}`)+
		"{unparseable\n"+`{"kind":"future","payload":{}}`+"\nunterminated native line")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	summary := runs.finished.Summary
	for _, want := range []string{"oyzu started.\n", "Phase: execution.\n", "Started cli:build.\n", "native stderr\r\n", "native stdout\n",
		"building cli\n", "warning: check cache\n", "error: source ***\n", "cli:build succeeded.\n", "Bundle finalized: succeeded.\n",
		"oyzu finished: succeeded (exit 0).\n", "{unparseable\n", `{"kind":"future","payload":{}}`, "unterminated native line"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q: %s", want, summary)
		}
	}
	if strings.Contains(summary, `"schemaVersion"`) || strings.Contains(summary, "ghs_secret") {
		t.Fatalf("summary contains an event envelope or secret: %s", summary)
	}
}

func TestLogSinkPreservesPlanBytes(t *testing.T) {
	c := captureForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	var record bytes.Buffer
	sink := &logSink{dst: &capped{w: &record, n: 1000}, capture: c, stream: "stdout"}
	want := []byte(" \r\n" + lifecycleLine(`{"type":"run-finished","status":"succeeded"}`) + "\xffunterminated")
	for _, b := range want {
		if _, err := sink.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	sink.close()
	if !bytes.Equal(record.Bytes(), want) {
		t.Fatalf("plan bytes changed: %q", record.Bytes())
	}
}

func TestLogSinkPreservesUnknownLines(t *testing.T) {
	c := captureForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	var tail bytes.Buffer
	sink := &logSink{dst: &tail, capture: c, stream: "stderr"}
	want := "native\r\n" + lifecycleLine(`{"type":"future-kind","extra":42}`) + "{broken\n\xfflast"
	_, _ = io.WriteString(sink, want)
	sink.close()
	finishCaptureForTest(c, time.Second)
	if tail.String() != want {
		t.Fatalf("unknown/native lines changed: %q", tail.String())
	}
}
