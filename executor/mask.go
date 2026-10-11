package executor

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const (
	// maskMin is the shortest value masked; masking shorter ones would shred
	// the log (Buildkite uses the same floor).
	maskMin = 6
	// masked replaces every match and never reveals the value's length.
	masked = "***"
)

// maskForms returns every form of the values the masker looks for: each value
// and each line of a multi-line one, as written, base64 (standard and URL-safe,
// at all three byte alignments so a value inside a larger blob is still
// found), percent-encoded and JSON-escaped (with and without escaped slashes). Forms shorter than maskMin are
// left out. Longest first, so a longer form wins over one it contains.
func maskForms(values ...string) []string {
	seen := map[string]bool{}
	add := func(s string) {
		if len(s) >= maskMin {
			seen[s] = true
		}
	}
	for _, v := range values {
		parts := []string{v}
		if strings.Contains(v, "\n") {
			parts = append(parts, strings.Split(v, "\n")...)
		}
		for _, p := range parts {
			p = strings.TrimRight(p, "\r")
			if len(p) < maskMin {
				continue
			}
			add(p)
			add(url.QueryEscape(p))
			add(url.PathEscape(p))
			if b, err := json.Marshal(p); err == nil {
				j := string(b[1 : len(b)-1])
				add(j)
				add(strings.ReplaceAll(j, "/", `\/`))
			}
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				for align := 0; align < 3; align++ {
					add(base64Core(enc, p, align))
				}
			}
		}
	}
	forms := make([]string, 0, len(seen))
	for f := range seen {
		forms = append(forms, f)
	}
	sort.Slice(forms, func(i, j int) bool {
		if len(forms[i]) != len(forms[j]) {
			return len(forms[i]) > len(forms[j])
		}
		return forms[i] < forms[j]
	})
	return forms
}

// base64Core is the part of v's base64 encoding that stays the same wherever
// v sits in a larger blob, when align bytes come before it in its 3-byte
// group: the characters that mix in neighbouring bytes are dropped.
func base64Core(enc *base64.Encoding, v string, align int) string {
	n := align + len(v)
	s := enc.EncodeToString(append(make([]byte, align), v...))
	s = s[:n*4/3]
	return s[[]int{0, 2, 3}[align]:]
}

// maskWriter replaces every form of the job's credentials in a stream before
// passing it on. A suffix that could still be the start of a form is held
// back until the next write shows whether it is one, so a value split across
// writes is still caught; Flush releases what is left.
type maskWriter struct {
	mu    sync.Mutex
	dst   io.Writer
	forms []string
	buf   string
	hits  []int
}

func newMaskWriter(dst io.Writer, forms []string) *maskWriter {
	return &maskWriter{dst: dst, forms: forms}
}

func (m *maskWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, hits := replaceFormsTracked(m.buf+string(p), m.forms, m.hits)
	hold := heldSuffix(s, m.forms)
	cut := len(s) - hold
	m.buf = s[len(s)-hold:]
	m.hits = nil
	var sent []int
	for _, pos := range hits {
		if pos < cut {
			sent = append(sent, pos)
		} else {
			m.hits = append(m.hits, pos-cut)
		}
	}
	if out := s[:len(s)-hold]; out != "" {
		if err := m.write(out, sent); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Add masks more values from now on, such as an ID token handed to the
// build mid-job.
func (m *maskWriter) Add(values ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forms = mergeForms(m.forms, maskForms(values...))
}

// mergeForms joins two form lists, longest first as maskForms orders them.
func mergeForms(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, f := range append(append([]string{}, a...), b...) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// Flush writes what was held back. At the end of the stream a partial match
// is not a value, so it goes out as written.
func (m *maskWriter) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.buf
	hits := m.hits
	m.buf = ""
	m.hits = nil
	if s == "" {
		return nil
	}
	return m.write(s, hits)
}

// A capture sink gets exact replacement positions; literal "***" output is
// not counted as a redaction. Other sinks retain the existing byte stream.
func (m *maskWriter) write(s string, hits []int) error {
	if dst, ok := m.dst.(interface{ WriteMasked([]byte, []int) error }); ok {
		return dst.WriteMasked([]byte(s), hits)
	}
	_, err := io.WriteString(m.dst, s)
	return err
}

// replaceForms masks every form in s, leftmost match first and the longest
// form at a position. The forms are a job's few credentials, so a scan per
// form is cheap; a multi-pattern automaton comes with build secrets.
func replaceForms(s string, forms []string) string {
	out, _ := replaceFormsTracked(s, forms, nil)
	return out
}

func replaceFormsTracked(s string, forms []string, prior []int) (string, []int) {
	var b strings.Builder
	var hits []int
	consumed := 0
	copyHits := func(n int) {
		for _, pos := range prior {
			if pos >= consumed && pos < consumed+n {
				hits = append(hits, b.Len()+pos-consumed)
			}
		}
	}
	for {
		at, size := -1, 0
		for _, f := range forms {
			if i := strings.Index(s, f); i >= 0 && (at < 0 || i < at || (i == at && len(f) > size)) {
				at, size = i, len(f)
			}
		}
		if at < 0 {
			copyHits(len(s))
			if b.Len() == 0 {
				return s, hits
			}
			b.WriteString(s)
			return b.String(), hits
		}
		copyHits(at)
		b.WriteString(s[:at])
		hits = append(hits, b.Len())
		b.WriteString(masked)
		consumed += at + size
		s = s[at+size:]
	}
}

// heldSuffix is the length of the longest suffix of s that is a proper
// prefix of some form.
func heldSuffix(s string, forms []string) int {
	longest := 0
	for _, f := range forms {
		for k := min(len(f)-1, len(s)); k > longest; k-- {
			if strings.HasSuffix(s, f[:k]) {
				longest = k
				break
			}
		}
	}
	return longest
}
