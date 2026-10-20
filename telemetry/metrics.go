package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Instrument names, the catalog in docs/telemetry.md.
const (
	NameRequests  = "oyzu.fleet.client.requests"
	NameDuration  = "oyzu.fleet.client.duration"
	NameHeadroom  = "oyzu.fleet.lease.headroom"
	NameDrain     = "oyzu.fleet.log_drain.operations"
	NameExecution = "oyzu.fleet.executions"
)

var (
	durationBounds = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	headroomBounds = []float64{1, 5, 10, 20, 30, 45, 60, 75, 90, 105, 120}
)

// routes is the closed set of runner API routes a client call is counted
// under; anything else is "other". A route name is a path suffix, never a URL.
var routes = map[string]bool{
	"enroll": true, "token": true, "keys": true, "claim": true, "demand": true, "report": true, "release": true,
	"job/start": true, "job/heartbeat": true, "job/source": true, "job/id-token": true, "job/secrets": true,
	"job/egress": true, "job/write-token": true, "job/finish": true, "job/logs": true, "job/logs/finish": true,
	"job/kind/heartbeat": true, "job/kind/events": true, "job/kind/secrets": true, "job/kind/connectors": true,
	"job/kind/finish": true, "job/kind/plan-file": true, "job/kind/plan-file/fetch": true,
	"job/kind/ledger": true, "job/kind/ledger/fetch": true,
}

// Route names a runner API path for telemetry.
func Route(path string) string {
	if routes[path] {
		return path
	}
	return "other"
}

type counter struct {
	name  string
	attrs [][2]string
	n     int64
}

type histogram struct {
	name   string
	attrs  [][2]string
	bounds []float64
	counts []int64
	sum    float64
	n      int64
}

func attrKey(name string, kv []string) (string, [][2]string) {
	pairs := make([][2]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		pairs = append(pairs, [2]string{kv[i], safeToken(kv[i+1])})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	var b strings.Builder
	b.WriteString(name)
	for _, p := range pairs {
		b.WriteString("|" + p[0] + "=" + p[1])
	}
	return b.String(), pairs
}

func (p *Provider) add(name string, kv ...string) {
	key, pairs := attrKey(name, kv)
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.counts[key]
	if c == nil {
		if len(p.counts) >= 512 {
			p.dropped.Add(1)
			return
		}
		c = &counter{name: name, attrs: pairs}
		p.counts[key] = c
	}
	c.n++
}

func (p *Provider) observe(name string, bounds []float64, v float64, kv ...string) {
	key, pairs := attrKey(name, kv)
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.hists[key]
	if h == nil {
		if len(p.hists) >= 512 {
			p.dropped.Add(1)
			return
		}
		h = &histogram{name: name, attrs: pairs, bounds: bounds, counts: make([]int64, len(bounds)+1)}
		p.hists[key] = h
	}
	i := sort.SearchFloat64s(bounds, v)
	h.counts[i]++
	h.sum += v
	h.n++
}

// Request counts one runner API call by route, outcome and bounded reason and
// records how long it took.
func Request(route string, o Outcome, reason string, d time.Duration) {
	p := current()
	if p == nil {
		return
	}
	if !outcomes[o] {
		o = Fault
	}
	kv := []string{"oyzu.fleet.route", Route(route), "oyzu.outcome", string(o), "oyzu.reason", reasonOrNone(reason)}
	p.add(NameRequests, kv...)
	p.observe(NameDuration, durationBounds, d.Seconds(), "oyzu.fleet.route", Route(route), "oyzu.outcome", string(o))
}

func reasonOrNone(r string) string {
	if r == "" {
		return "none"
	}
	return r
}

// LeaseHeadroom records how much of the lease was left when a heartbeat was
// confirmed (an executor) or how far from expiry it is when it is missed.
func LeaseHeadroom(left time.Duration) {
	if p := current(); p != nil {
		p.observe(NameHeadroom, headroomBounds, max(left, 0).Seconds())
	}
}

// Drain counts one log-drain call. phase is "live" while the job runs and
// "post_finish" under the finishing token's bounded exception.
func Drain(route, phase string, o Outcome, reason string) {
	if p := current(); p != nil {
		if route != "upload" && route != "finish" {
			route = "other"
		}
		if phase != "live" && phase != "post_finish" {
			phase = "other"
		}
		p.add(NameDrain, "oyzu.fleet.route", route, "oyzu.fleet.phase", phase, "oyzu.outcome", string(o), "oyzu.reason", reasonOrNone(reason))
	}
}

// Execution counts one finished job by the outcome the executor reported.
func Execution(state string) {
	if p := current(); p != nil {
		p.add(NameExecution, "oyzu.fleet.state", state)
	}
}

// Classify maps a call's error and status to the bounded outcome and reason.
// refused is true for the credential refusal (401); status is the HTTP status
// when one was received.
func Classify(ctx context.Context, err error, status int, refused bool) (Outcome, string) {
	switch {
	case err == nil:
		return Success, ""
	case refused:
		return Challenge, "refused"
	case errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled:
		return Cancelled, "cancelled"
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded:
		return Unavailable, "timeout"
	case status == http.StatusConflict:
		return Denied, "conflict"
	case status == http.StatusNotFound || status == http.StatusForbidden:
		return Denied, "not_found"
	case status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests:
		return Unavailable, "server_busy"
	case status >= 500:
		return Fault, "server_error"
	case status >= 400:
		return Invalid, "bad_request"
	}
	var ne net.Error
	if errors.As(err, &ne) || status == 0 {
		return Unavailable, "network"
	}
	return Fault, "error"
}

func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &ne):
		return "network"
	}
	return "status"
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
