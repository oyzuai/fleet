package kindprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrDigestMismatch means a plan's digest does not match its content.
var ErrDigestMismatch = errors.New("kindprotocol: plan digest does not match its content")

// Seal fills in the plan's fixed members and its digest: "sha256:" and the hex
// SHA-256 of the RFC 8785 canonical JSON of the plan without its digest
// member. Nil slices become empty ones, as the schema requires arrays.
func (p *Plan) Seal() error {
	p.SchemaVersion, p.Type = SchemaVersion, TypePlan
	if p.Changes == nil {
		p.Changes = []Change{}
	}
	if p.RiskFlags == nil {
		p.RiskFlags = []RiskFlag{}
	}
	d, err := p.computeDigest()
	if err != nil {
		return err
	}
	p.Digest = d
	return nil
}

// Verify reports ErrDigestMismatch when the digest does not recompute.
func (p *Plan) Verify() error {
	d, err := p.computeDigest()
	if err != nil {
		return err
	}
	if d != p.Digest {
		return fmt.Errorf("%w: has %s, content gives %s", ErrDigestMismatch, p.Digest, d)
	}
	return nil
}

func (p *Plan) computeDigest() (string, error) {
	body := *p
	body.Digest = ""
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return "", err
	}
	delete(v, "digest")
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalJSON returns the RFC 8785 canonical form of a JSON document.
func CanonicalJSON(raw []byte) ([]byte, error) {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return Canonical(v)
}

// Canonical encodes a decoded JSON value (from encoding/json, with or without
// UseNumber) as RFC 8785 canonical JSON: object members sorted by UTF-16 code
// units, no whitespace, minimal string escapes, and numbers as ECMAScript
// formats an IEEE 754 double.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := canon(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func canon(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		canonString(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return err
		}
		return canonNumber(b, f)
	case float64:
		return canonNumber(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonString(b, k)
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("kindprotocol: cannot canonicalize %T", v)
	}
	return nil
}

func canonNumber(b *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("kindprotocol: number is not finite")
	}
	if f == 0 {
		b.WriteByte('0') // also -0
		return nil
	}
	// encoding/json formats float64 as ECMAScript's Number.prototype.toString.
	out, err := json.Marshal(f)
	if err != nil {
		return err
	}
	b.Write(out)
	return nil
}

func canonString(b *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[r>>4])
			b.WriteByte(hexDigits[r&0xf])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
