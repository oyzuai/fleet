package readiness

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func echo(ctx context.Context, origin, nonce, proxy string) error {
	tr := &http.Transport{}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(origin, "/")+"/probe/"+nonce, nil)
	if err != nil {
		return err
	}
	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 256))
	if err != nil || r.StatusCode != 200 || string(b) != "oyzu-readiness:"+nonce {
		return errors.New("diagnostic echo unavailable")
	}
	return nil
}

func dnsQuestion(name string) ([]byte, error) {
	b := []byte{0x72, 0x64, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return nil, errors.New("invalid diagnostic name")
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b, nil
}

func dnsExchange(ctx context.Context, network, address, name string) ([]byte, error) {
	q, err := dnsQuestion(name)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(dctx, network, address)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := dctx.Deadline()
	_ = c.SetDeadline(deadline)
	if network == "tcp" {
		prefix := []byte{byte(len(q) >> 8), byte(len(q))}
		q = append(prefix, q...)
	}
	if _, err = c.Write(q); err != nil {
		return nil, err
	}
	b := make([]byte, 512)
	if network == "tcp" {
		var h [2]byte
		if _, err = io.ReadFull(c, h[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n < 12 || n > 512 {
			return nil, errors.New("invalid diagnostic DNS response")
		}
		b = b[:n]
		_, err = io.ReadFull(c, b)
	} else {
		var n int
		n, err = c.Read(b)
		b = b[:n]
	}
	if err != nil || len(b) < 12 || b[0] != 0x72 || b[1] != 0x64 || b[2]&0x80 == 0 {
		return nil, errors.New("invalid diagnostic DNS response")
	}
	return b, nil
}

// Control validates both positive fixtures from the manager's management path.
// It never follows redirects or uses a caller-provided destination.
func Control(ctx context.Context, d Descriptor, nonce string) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := echo(ctx, d.URL, nonce, ""); err != nil {
		return err
	}
	for _, network := range []string{"udp", "tcp"} {
		b, err := dnsExchange(ctx, network, d.DNSAddress, d.DNSName)
		if err != nil || b[3]&15 != 0 || binary.BigEndian.Uint16(b[6:8]) < 1 {
			return errors.New("diagnostic DNS control unavailable")
		}
	}
	return nil
}

func AllowedEcho(ctx context.Context, d Descriptor, nonce, proxy string) error {
	return echo(ctx, d.URL, nonce, proxy)
}

func DNSRefused(ctx context.Context, address, name string) bool {
	b, err := dnsExchange(ctx, "udp", address, name)
	return err == nil && b[3]&15 == 5
}

func DNSResponds(ctx context.Context, network, address, name string) bool {
	_, err := dnsExchange(ctx, network, address, name)
	return err == nil
}

// Outcome derives the aggregate; a definitive violation takes precedence over
// missing prerequisites. Cleanup is reported by the owning driver.
func (r *Result) Aggregate() {
	r.Outcome = "passed"
	seen := map[string]bool{}
	failed := false
	for _, c := range r.Checks {
		seen[c.Name] = true
		failed = failed || c.Outcome == "failed"
		if c.Outcome != "passed" {
			r.Outcome = "inconclusive"
		}
	}
	for _, n := range requiredChecks {
		if !seen[n] {
			r.Outcome = "inconclusive"
		}
	}
	if failed {
		r.Outcome = "failed"
	}
}
