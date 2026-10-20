package telemetry

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Outcome is the bounded result of an operation, the same vocabulary the
// platform uses.
type Outcome string

const (
	Success     Outcome = "success"
	Challenge   Outcome = "challenge" // runs refused the credential (401)
	Invalid     Outcome = "invalid"
	Denied      Outcome = "denied"
	Cancelled   Outcome = "cancelled"
	Unavailable Outcome = "unavailable"
	Fault       Outcome = "fault"
)

var outcomes = map[Outcome]bool{Success: true, Challenge: true, Invalid: true, Denied: true, Cancelled: true, Unavailable: true, Fault: true}

// Kind is the span kind.
type Kind int

const (
	Internal Kind = 1
	Server   Kind = 2
	Client   Kind = 3
)

// Attribute keys. Only these are recorded; every identifier is a number the
// server or the manager assigned, never anything a user or a build wrote.
var (
	intKeys = map[string]bool{
		"oyzu.fleet.job": true, "oyzu.fleet.attempt": true, "oyzu.fleet.manager": true, "oyzu.fleet.key": true,
		"http.response.status_code": true, "oyzu.fleet.exit_code": true, "oyzu.fleet.lease.headroom_ms": true,
		"oyzu.fleet.heartbeat_seconds": true, "oyzu.fleet.slots": true,
	}
	strKeys = map[string]bool{
		"oyzu.fleet.route": true, "oyzu.fleet.pool": true, "oyzu.fleet.operation": true, "oyzu.fleet.kind": true,
		"oyzu.fleet.state": true, "oyzu.fleet.phase": true, "oyzu.fleet.driver": true,
	}
	// A string value is a short lowercase token.
	tokenValue = regexp.MustCompile(`^[a-z0-9][a-z0-9_./:-]{0,63}$`)
	// Anything shaped like an Oyzu credential is refused, whatever its key.
	credentialShape = regexp.MustCompile(`(?i)oyzu_[a-z]+_|bearer |eyJ[A-Za-z0-9_-]{8,}|-----BEGIN`)
	spanName        = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
)

type attr struct {
	key   string
	str   string
	num   int64
	isNum bool
}

type spanData struct {
	sc, parent spanContext
	name       string
	kind       Kind
	start, end time.Time
	attrs      []attr
	errored    bool
}

// Span is one recorded operation. A nil *Span, which telemetry being off
// yields, accepts every call and does nothing.
type Span struct {
	p      *Provider
	d      spanData
	mu     sync.Mutex
	ended  bool
	parent bool
}

// Start begins a span named name under ctx's span or WithParent. With
// telemetry off it returns ctx and a nil span.
func Start(ctx context.Context, name string, kind Kind) (context.Context, *Span) {
	p := current()
	if p == nil || !spanName.MatchString(name) {
		return ctx, nil
	}
	s := &Span{p: p}
	s.d = spanData{name: name, kind: kind, start: time.Now()}
	if parent, ok := ctx.Value(ctxKey{}).(spanContext); ok && parent.valid() {
		s.d.sc.trace, s.d.parent = parent.trace, parent
	} else {
		newID(s.d.sc.trace[:])
	}
	newID(s.d.sc.span[:])
	return context.WithValue(ctx, ctxKey{}, s.d.sc), s
}

// Int records a server-assigned number under an allowlisted key.
func (s *Span) Int(key string, v int64) {
	if s == nil || !intKeys[key] {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.d.attrs = append(s.d.attrs, attr{key: key, num: v, isNum: true})
	}
}

// Str records a short lowercase token under an allowlisted key. A value that
// is not one, or looks like a credential, is replaced by "invalid".
func (s *Span) Str(key, v string) {
	if s == nil || !strKeys[key] {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.d.attrs = append(s.d.attrs, attr{key: key, str: safeToken(v)})
	}
}

func safeToken(v string) string {
	v = strings.ToLower(v)
	if !tokenValue.MatchString(v) || credentialShape.MatchString(v) {
		return "invalid"
	}
	return v
}

// TraceparentOf is the traceparent naming this span, for a child process.
func (s *Span) Traceparent() string {
	if s == nil {
		return ""
	}
	return s.d.sc.traceparent()
}

// End finishes the span with its outcome and a bounded reason.
func (s *Span) End(o Outcome, reason string) {
	if s == nil {
		return
	}
	if !outcomes[o] {
		o = Fault
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.d.end = time.Now()
	s.d.attrs = append(s.d.attrs, attr{key: "oyzu.outcome", str: string(o)})
	if r := safeReason(reason); r != "" {
		s.d.attrs = append(s.d.attrs, attr{key: "oyzu.reason", str: r})
	}
	s.d.errored = o == Unavailable || o == Fault
	d := s.d
	s.mu.Unlock()
	s.p.enqueue(d)
}

func safeReason(r string) string {
	if r == "" {
		return ""
	}
	return safeToken(r)
}

func (p *Provider) enqueue(d spanData) {
	p.mu.Lock()
	if len(p.spans) >= maxQueuedSpans {
		p.spans = p.spans[1:]
		p.dropped.Add(1)
	}
	p.spans = append(p.spans, d)
	full := len(p.spans) >= batchSpans
	p.mu.Unlock()
	if full {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}
