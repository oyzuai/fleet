package telemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// exportTimeout bounds one export. It runs off the job's path.
const exportTimeout = 3 * time.Second

type exporter struct {
	base string
	hc   *http.Client
}

func newExporter(base string) exporter {
	return exporter{base: base, hc: &http.Client{Timeout: exportTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

// post sends one OTLP/HTTP JSON request. It sends no Authorization header and
// no cookie: the exporter has no credential to leak, and an endpoint that
// needs one is out of scope.
func (e exporter) post(path string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("collector answered " + strconv.Itoa(resp.StatusCode))
	}
	return nil
}

// ---- OTLP/HTTP JSON encoding (identifiers are hex, 64-bit values strings)

type jsonAttr struct {
	Key   string    `json:"key"`
	Value jsonValue `json:"value"`
}

type jsonValue struct {
	String *string `json:"stringValue,omitempty"`
	Int    *string `json:"intValue,omitempty"`
}

func strAttr(k, v string) jsonAttr { return jsonAttr{Key: k, Value: jsonValue{String: &v}} }
func intAttr(k string, v int64) jsonAttr {
	s := strconv.FormatInt(v, 10)
	return jsonAttr{Key: k, Value: jsonValue{Int: &s}}
}

func (p *Provider) resource() map[string]any {
	return map[string]any{"attributes": []jsonAttr{
		strAttr("service.name", p.cfg.Service), strAttr("service.version", p.cfg.Version),
		strAttr("service.instance.id", p.cfg.Instance), strAttr("deployment.environment.name", p.cfg.Environment),
	}}
}

func nano(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

func (p *Provider) tracesBody(batch []spanData) []byte {
	spans := make([]map[string]any, 0, len(batch))
	for _, d := range batch {
		attrs := make([]jsonAttr, 0, len(d.attrs))
		for _, a := range d.attrs {
			if a.isNum {
				attrs = append(attrs, intAttr(a.key, a.num))
			} else {
				attrs = append(attrs, strAttr(a.key, a.str))
			}
		}
		s := map[string]any{
			"traceId": fmt.Sprintf("%x", d.sc.trace[:]), "spanId": fmt.Sprintf("%x", d.sc.span[:]), "name": d.name,
			"kind": int(d.kind), "startTimeUnixNano": nano(d.start), "endTimeUnixNano": nano(d.end), "attributes": attrs,
		}
		if d.parent.valid() {
			s["parentSpanId"] = fmt.Sprintf("%x", d.parent.span[:])
		}
		if d.errored {
			s["status"] = map[string]any{"code": 2}
		}
		spans = append(spans, s)
	}
	return mustJSON(map[string]any{"resourceSpans": []any{map[string]any{
		"resource":   p.resource(),
		"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": "oyzu.fleet"}, "spans": spans}},
	}}})
}

func pairsJSON(pairs [][2]string) []jsonAttr {
	out := make([]jsonAttr, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, strAttr(p[0], p[1]))
	}
	return out
}

// metricsBody is the cumulative state of every instrument, or nil when nothing
// was recorded.
func (p *Provider) metricsBody() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.counts) == 0 && len(p.hists) == 0 {
		return nil
	}
	now := time.Now()
	byName := map[string][]map[string]any{}
	kind := map[string]string{}
	for _, c := range p.counts {
		kind[c.name] = "sum"
		byName[c.name] = append(byName[c.name], map[string]any{
			"attributes": pairsJSON(c.attrs), "startTimeUnixNano": nano(p.start), "timeUnixNano": nano(now), "asInt": strconv.FormatInt(c.n, 10),
		})
	}
	for _, h := range p.hists {
		kind[h.name] = "histogram"
		counts := make([]string, len(h.counts))
		for i, n := range h.counts {
			counts[i] = strconv.FormatInt(n, 10)
		}
		byName[h.name] = append(byName[h.name], map[string]any{
			"attributes": pairsJSON(h.attrs), "startTimeUnixNano": nano(p.start), "timeUnixNano": nano(now),
			"count": strconv.FormatInt(h.n, 10), "sum": h.sum, "bucketCounts": counts, "explicitBounds": h.bounds,
		})
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	metrics := make([]map[string]any, 0, len(names))
	for _, n := range names {
		m := map[string]any{"name": n}
		if kind[n] == "sum" {
			m["unit"] = "{call}"
			m["sum"] = map[string]any{"dataPoints": byName[n], "aggregationTemporality": 2, "isMonotonic": true}
		} else {
			m["unit"] = "s"
			m["histogram"] = map[string]any{"dataPoints": byName[n], "aggregationTemporality": 2}
		}
		metrics = append(metrics, m)
	}
	return mustJSON(map[string]any{"resourceMetrics": []any{map[string]any{
		"resource":     p.resource(),
		"scopeMetrics": []any{map[string]any{"scope": map[string]any{"name": "oyzu.fleet"}, "metrics": metrics}},
	}}})
}

func mustJSON(v any) []byte {
	b, err := jsonMarshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
