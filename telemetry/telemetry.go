// Package telemetry is Fleet's safe, optional OpenTelemetry export for the
// pool manager and the executor: traces and metrics over OTLP/HTTP JSON, with
// the standard library only.
//
// It is built around what must never happen. Telemetry cannot carry a
// credential: attribute keys are an allowlist, string values must be short
// lowercase tokens, and anything shaped like an Oyzu credential is dropped.
// It cannot change what a job does: recording never blocks, a full queue
// drops the oldest data, and an unreachable Collector costs a counter, never
// a lease renewal (FLEET-AUTH-05). It cannot reach the build: the settings
// are read and removed from the process environment at startup, so no child
// process inherits an endpoint or a trace parent. It is off unless
// OYZU_OTEL_ENABLED=true.
//
// Fleet's spans correlate with runs by server-assigned job, attempt and
// manager numbers carried as attributes. The W3C traceparent a client sends
// to runs is optional correlation only: runs makes it a span link, never a
// parent, and no authentication field is ever used as trace context.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The settings, shared with the platform's services.
const (
	EnvEnabled     = "OYZU_OTEL_ENABLED"
	EnvEndpoint    = "OYZU_OTEL_ENDPOINT"
	EnvEnvironment = "OYZU_OTEL_ENVIRONMENT"
	EnvVersion     = "OYZU_OTEL_VERSION"
	EnvInstance    = "OYZU_OTEL_INSTANCE"
	// EnvTraceparent is how a manager hands its execution span to the
	// executor it starts. It is trace context only.
	EnvTraceparent = "TRACEPARENT"
)

// Names lists the variables that configure telemetry. None of them may reach a
// build, a kind or a child process.
var Names = []string{EnvEnabled, EnvEndpoint, EnvEnvironment, EnvVersion, EnvInstance, EnvTraceparent}

// IsTelemetryVar reports whether kv ("NAME=value") sets one of Names or any
// other OYZU_OTEL_ or OTEL_ variable.
func IsTelemetryVar(kv string) bool {
	name, _, _ := strings.Cut(kv, "=")
	up := strings.ToUpper(name)
	return strings.HasPrefix(up, "OYZU_OTEL_") || strings.HasPrefix(up, "OTEL_") || up == EnvTraceparent || up == "TRACESTATE"
}

// Config is the telemetry settings of one process.
type Config struct {
	Enabled     bool
	Endpoint    string
	Service     string
	Environment string
	Version     string
	Instance    string
	// Parent is a traceparent handed down by the manager, if any.
	Parent string
}

// LoadConfig reads the settings for service ("oyzu-pool-manager" or
// "oyzu-executor") and, when consume is set, removes every telemetry variable
// from the process environment so children cannot inherit them. An invalid
// endpoint disables telemetry and is reported as an error the caller logs;
// it never stops the job.
func LoadConfig(service string, consume bool) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	cfg := Config{Service: service, Environment: get(EnvEnvironment), Version: get(EnvVersion), Instance: get(EnvInstance), Parent: get(EnvTraceparent)}
	enabled, endpoint := strings.EqualFold(get(EnvEnabled), "true"), get(EnvEndpoint)
	if consume {
		for _, kv := range os.Environ() {
			if IsTelemetryVar(kv) {
				name, _, _ := strings.Cut(kv, "=")
				_ = os.Unsetenv(name)
			}
		}
	}
	if cfg.Environment == "" {
		cfg.Environment = "unknown"
	}
	if cfg.Version == "" {
		cfg.Version = "unknown"
	}
	if cfg.Instance == "" {
		cfg.Instance, _ = os.Hostname()
	}
	if !enabled {
		return cfg, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return cfg, errors.New("telemetry is off: " + EnvEndpoint + " must be an http or https URL without credentials, query or fragment")
	}
	cfg.Enabled, cfg.Endpoint = true, strings.TrimRight(u.String(), "/")
	return cfg, nil
}

// Env is the environment a manager hands an executor it starts: the same
// settings, and the manager's execution span as the trace parent. Nothing in
// it is a credential: the endpoint is checked to carry none.
func (c Config) Env(parent string) []string {
	if !c.Enabled {
		return nil
	}
	env := []string{EnvEnabled + "=true", EnvEndpoint + "=" + c.Endpoint, EnvEnvironment + "=" + c.Environment, EnvVersion + "=" + c.Version}
	if parent != "" {
		env = append(env, EnvTraceparent+"="+parent)
	}
	return env
}

// Provider records and exports spans and metrics.
type Provider struct {
	cfg    Config
	log    *slog.Logger
	start  time.Time
	http   exporter
	mu     sync.Mutex
	spans  []spanData
	counts map[string]*counter
	hists  map[string]*histogram
	// dropped and failed count data lost to a full queue or a failed export.
	dropped atomic.Int64
	failed  atomic.Int64
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	lastLog atomic.Int64
}

var global atomic.Pointer[Provider]

// Setup installs the process's provider. Disabled, it records nothing.
func Setup(cfg Config, log *slog.Logger) *Provider {
	if log == nil {
		log = slog.Default()
	}
	p := &Provider{cfg: cfg, log: log, start: time.Now(), counts: map[string]*counter{}, hists: map[string]*histogram{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	if !cfg.Enabled {
		close(p.done)
		global.Store(p)
		return p
	}
	p.http = newExporter(cfg.Endpoint)
	global.Store(p)
	go p.loop()
	return p
}

// Config is the provider's settings.
func (p *Provider) Config() Config { return p.cfg }

// Shutdown flushes what it can until ctx ends. It never blocks past ctx.
func (p *Provider) Shutdown(ctx context.Context) {
	if p == nil || !p.cfg.Enabled {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	select {
	case <-p.done:
	case <-ctx.Done():
	}
}

// Dropped and ExportFailures report data lost, for tests and diagnostics.
func (p *Provider) Dropped() int64        { return p.dropped.Load() }
func (p *Provider) ExportFailures() int64 { return p.failed.Load() }

func current() *Provider {
	p := global.Load()
	if p == nil || !p.cfg.Enabled {
		return nil
	}
	return p
}

const (
	maxQueuedSpans = 2048
	batchSpans     = 64
	traceEvery     = 2 * time.Second
	metricEvery    = 5 * time.Second
)

func (p *Provider) loop() {
	defer close(p.done)
	spanTick, metricTick := time.NewTicker(traceEvery), time.NewTicker(metricEvery)
	defer spanTick.Stop()
	defer metricTick.Stop()
	for {
		select {
		case <-p.stop:
			p.flush(true)
			return
		case <-p.wake:
			p.flushSpans()
		case <-spanTick.C:
			p.flushSpans()
		case <-metricTick.C:
			p.flushMetrics()
		}
	}
}

func (p *Provider) flush(metrics bool) {
	p.flushSpans()
	if metrics {
		p.flushMetrics()
	}
}

func (p *Provider) flushSpans() {
	p.mu.Lock()
	batch := p.spans
	p.spans = nil
	p.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if err := p.http.post("/v1/traces", p.tracesBody(batch)); err != nil {
		p.exportFailed(err)
	}
}

func (p *Provider) flushMetrics() {
	body := p.metricsBody()
	if body == nil {
		return
	}
	if err := p.http.post("/v1/metrics", body); err != nil {
		p.exportFailed(err)
	}
}

// exportFailed counts a lost export and says so at most once a minute. The
// message carries no URL and no response body.
func (p *Provider) exportFailed(err error) {
	p.failed.Add(1)
	now := time.Now().Unix()
	if last := p.lastLog.Load(); now-last >= 60 && p.lastLog.CompareAndSwap(last, now) {
		p.log.Warn("telemetry export failed; data is dropped and the job is not affected", "class", classify(err))
	}
}

// ---- identifiers and trace context

type ctxKey struct{}

// spanContext identifies a span in a trace.
type spanContext struct {
	trace [16]byte
	span  [8]byte
}

func (s spanContext) valid() bool { return s.trace != [16]byte{} && s.span != [8]byte{} }

func (s spanContext) traceparent() string {
	return "00-" + hex.EncodeToString(s.trace[:]) + "-" + hex.EncodeToString(s.span[:]) + "-01"
}

var traceparentRE = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$`)

func parseTraceparent(s string) (spanContext, bool) {
	m := traceparentRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return spanContext{}, false
	}
	var sc spanContext
	_, _ = hex.Decode(sc.trace[:], []byte(m[1]))
	_, _ = hex.Decode(sc.span[:], []byte(m[2]))
	return sc, sc.valid()
}

func newID(b []byte) {
	for {
		_, _ = rand.Read(b)
		for _, v := range b {
			if v != 0 {
				return
			}
		}
	}
}

// WithParent makes a traceparent the parent of spans started under ctx. A
// malformed value is ignored.
func WithParent(ctx context.Context, traceparent string) context.Context {
	if sc, ok := parseTraceparent(traceparent); ok {
		return context.WithValue(ctx, ctxKey{}, sc)
	}
	return ctx
}

// Traceparent is the W3C traceparent of the span in ctx, or "" when there is
// none (telemetry off).
func Traceparent(ctx context.Context) string {
	if sc, ok := ctx.Value(ctxKey{}).(spanContext); ok && sc.valid() {
		return sc.traceparent()
	}
	return ""
}

// Header is what Inject writes to.
type Header interface{ Set(key, value string) }

// Inject writes ctx's traceparent as the traceparent header. It is optional
// correlation: runs links to it and never trusts it.
func Inject(ctx context.Context, h Header) {
	if tp := Traceparent(ctx); tp != "" {
		h.Set("traceparent", tp)
	}
}
