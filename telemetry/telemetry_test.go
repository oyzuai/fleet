package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu     sync.Mutex
	bodies map[string][]string
	auth   []string
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	t.Helper()
	c := &collector{bodies: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies[r.URL.Path] = append(c.bodies[r.URL.Path], string(b))
		c.auth = append(c.auth, r.Header.Get("Authorization")+r.Header.Get("Cookie"))
		c.mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *collector) all(path string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies[path], "\n")
}

func setup(t *testing.T, endpoint string) *Provider {
	t.Helper()
	p := Setup(Config{Enabled: true, Endpoint: endpoint, Service: "oyzu-test", Environment: "test", Version: "v", Instance: "i"}, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { global.Store(nil) })
	return p
}

func shutdown(p *Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

func TestSpansAndMetricsExportAsOTLPJSON(t *testing.T) {
	c, srv := newCollector(t)
	p := setup(t, srv.URL)
	ctx, parent := Start(context.Background(), "fleet.manager.claim", Internal)
	_, child := Start(ctx, "fleet.client.claim", Client)
	child.Int("oyzu.fleet.job", 42)
	child.Str("oyzu.fleet.route", "claim")
	child.End(Challenge, "refused")
	parent.End(Success, "")
	Request("claim", Challenge, "refused", 20*time.Millisecond)
	LeaseHeadroom(90 * time.Second)
	Drain("upload", "post_finish", Success, "")
	shutdown(p)

	traces := c.all("/v1/traces")
	var doc struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					TraceID, SpanID, ParentSpanID, Name string
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(traces), &doc); err != nil {
		t.Fatalf("%v: %s", err, traces)
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 2 || spans[0].TraceID != spans[1].TraceID || spans[0].ParentSpanID != spans[1].SpanID {
		t.Fatalf("spans are not parent and child: %s", traces)
	}
	for _, want := range []string{`"oyzu.fleet.job"`, `"intValue":"42"`, `"oyzu.outcome"`, `"challenge"`, `"service.name"`} {
		if !strings.Contains(traces, want) {
			t.Errorf("traces lack %s: %s", want, traces)
		}
	}
	metrics := c.all("/v1/metrics")
	for _, want := range []string{NameRequests, NameDuration, NameHeadroom, NameDrain, `"isMonotonic":true`, `"bucketCounts"`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s: %s", want, metrics)
		}
	}
	for _, a := range c.auth {
		if a != "" {
			t.Fatalf("the exporter sent a credential-bearing header: %q", a)
		}
	}
}

// Invariant: no credential is ever a telemetry value, whatever key or form it
// arrives in; unknown keys and non-token values are dropped or replaced.
func TestNoCredentialReachesTelemetry(t *testing.T) {
	c, srv := newCollector(t)
	p := setup(t, srv.URL)
	secrets := []string{"oyzu_job_AbCdEfGhIjKlMnOp", "Bearer abc.def", "eyJhbGciOiJFZERTQSJ9.payload.sig", "-----BEGIN PRIVATE KEY-----", "https://u:p@host/x"}
	_, s := Start(context.Background(), "fleet.client.job", Client)
	for _, v := range secrets {
		s.Str("oyzu.fleet.route", v)
		s.Str("authorization", v) // not an allowlisted key
		s.Str("oyzu.fleet.pool", v)
	}
	s.End(Success, secrets[0])
	Request(secrets[0], Success, secrets[1], time.Millisecond)
	Drain(secrets[2], secrets[3], Success, secrets[4])
	shutdown(p)
	all := c.all("/v1/traces") + c.all("/v1/metrics")
	for _, v := range secrets {
		if strings.Contains(all, v) || strings.Contains(strings.ToLower(all), strings.ToLower(v)) {
			t.Fatalf("telemetry carries %q: %s", v, all)
		}
	}
	if strings.Contains(all, "authorization") {
		t.Fatalf("an unknown key was recorded: %s", all)
	}
}

// Invariant (FLEET-AUTH-05): an unreachable or hanging Collector never blocks
// recording or shutdown past its bound, and export failures are only counted.
func TestCollectorOutageNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer hang.Close()
	defer close(release)
	p := setup(t, hang.URL)
	start := time.Now()
	for range 5000 {
		_, s := Start(context.Background(), "fleet.client.job", Client)
		s.End(Success, "")
		Request("job/heartbeat", Success, "", time.Millisecond)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("recording took %s with the Collector hanging", d)
	}
	if p.Dropped() == 0 {
		t.Error("an overflowing queue dropped nothing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	p.Shutdown(ctx)
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("shutdown took %s", d)
	}

	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()
	q := setup(t, url)
	_, s := Start(context.Background(), "fleet.client.job", Client)
	s.End(Success, "")
	shutdown(q)
	if q.ExportFailures() == 0 {
		t.Error("a refused connection was not counted")
	}
}

func TestOffByDefaultAndEnvIsConsumed(t *testing.T) {
	t.Setenv(EnvEnabled, "true")
	t.Setenv(EnvEndpoint, "http://collector:4318")
	t.Setenv(EnvTraceparent, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer x")
	cfg, err := LoadConfig("oyzu-executor", true)
	if err != nil || !cfg.Enabled || cfg.Parent == "" {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	for _, n := range append([]string{"OTEL_EXPORTER_OTLP_HEADERS"}, Names...) {
		if v, ok := lookup(n); ok {
			t.Errorf("%s=%q is still in the environment", n, v)
		}
	}
	for _, bad := range []string{"http://user:pass@collector:4318", "ftp://collector", "http://collector:4318?token=x", ""} {
		t.Setenv(EnvEnabled, "true")
		t.Setenv(EnvEndpoint, bad)
		if cfg, err := LoadConfig("x", true); err == nil || cfg.Enabled {
			t.Errorf("endpoint %q was accepted", bad)
		}
	}
	t.Setenv(EnvEnabled, "")
	t.Setenv(EnvEndpoint, "")
	if cfg, err := LoadConfig("x", true); err != nil || cfg.Enabled {
		t.Errorf("default config = %+v, %v", cfg, err)
	}
	// Off, nothing is recorded or sent and a nil span is safe.
	Setup(Config{}, nil)
	ctx, s := Start(context.Background(), "fleet.x", Internal)
	s.Int("oyzu.fleet.job", 1)
	s.End(Success, "")
	Request("claim", Success, "", time.Second)
	if Traceparent(ctx) != "" {
		t.Error("a disabled provider produced a trace parent")
	}
}

func TestTraceparentRoundTrip(t *testing.T) {
	c, srv := newCollector(t)
	p := setup(t, srv.URL)
	_ = c
	ctx, s := Start(context.Background(), "fleet.manager.job", Internal)
	h := http.Header{}
	Inject(ctx, h)
	tp := h.Get("traceparent")
	if sc, ok := parseTraceparent(tp); !ok || tp != s.Traceparent() || sc.span != s.d.sc.span {
		t.Fatalf("traceparent = %q", tp)
	}
	child, cs := Start(WithParent(context.Background(), tp), "fleet.executor.job", Internal)
	_ = child
	if cs.d.sc.trace != s.d.sc.trace || cs.d.parent.span != s.d.sc.span {
		t.Fatal("the executor span is not a child of the manager's")
	}
	if got := WithParent(context.Background(), "garbage"); Traceparent(got) != "" {
		t.Error("a malformed traceparent was accepted")
	}
	s.End(Success, "")
	cs.End(Success, "")
	shutdown(p)
}
