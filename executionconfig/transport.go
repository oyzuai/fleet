package executionconfig

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// Transport gives the job credential proxy system plus corporate trust and the
// configured upstream proxy. It never consults ambient proxy settings when a
// typed proxy is present.
func Transport(c *runnerclient.ExecutionConfig) (*http.Transport, error) {
	corporate, err := Validate(c)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, failure(ProjectionFailed, "could not load system roots")
	}
	if len(corporate) > 0 && !roots.AppendCertsFromPEM(corporate) {
		return nil, failure(Invalid, "could not load corporate roots")
	}
	proxy := http.ProxyFromEnvironment
	if c != nil && c.Proxy != nil {
		p := *c.Proxy
		p.Bypass = append([]string{}, p.Bypass...)
		proxy = func(r *http.Request) (*url.URL, error) {
			if bypassed(r.URL, p.Bypass) {
				return nil, nil
			}
			raw := p.HTTP
			if r.URL.Scheme == "https" {
				raw = p.HTTPS
			}
			if raw == "" {
				return nil, nil
			}
			return proxyURL(raw)
		}
	}
	return &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}, nil
}

func validBypass(entry string) bool {
	if entry == "*" {
		return true
	}
	if entry == "" || strings.TrimSpace(entry) != entry || strings.ContainsAny(entry, "\r\n\t ,@?#") {
		return false
	}
	if _, err := netip.ParsePrefix(entry); err == nil {
		return true
	}
	host := entry
	if h, port, err := net.SplitHostPort(entry); err == nil {
		if port == "" {
			return false
		}
		host = h
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return true
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "*."), ".")
	if host == "" {
		return false
	}
	for _, ch := range host {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

func bypassed(u *url.URL, entries []string) bool {
	host := strings.ToLower(u.Hostname())
	ip, _ := netip.ParseAddr(host)
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	for _, entry := range entries {
		if entry == "*" {
			return true
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if ip.IsValid() && prefix.Contains(ip) {
				return true
			}
			continue
		}
		if h, p, err := net.SplitHostPort(entry); err == nil {
			if p != port {
				continue
			}
			entry = h
		}
		entry = strings.ToLower(strings.Trim(entry, "[]"))
		if parsed, err := netip.ParseAddr(entry); err == nil {
			if parsed == ip {
				return true
			}
			continue
		}
		onlyChildren := strings.HasPrefix(entry, ".") || strings.HasPrefix(entry, "*.")
		entry = strings.TrimPrefix(strings.TrimPrefix(entry, "*."), ".")
		if (!onlyChildren && host == entry) || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

// TunnelDialer connects opaque HTTPS tunnels through the same corporate proxy
// and bypass rules as intercepted requests. A failed CONNECT never falls back
// to a direct connection.
func TunnelDialer(t *http.Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		target := &url.URL{Scheme: "https", Host: addr}
		proxy, err := t.Proxy(&http.Request{URL: target})
		if err != nil {
			return nil, err
		}
		if proxy == nil {
			return t.DialContext(ctx, network, addr)
		}
		endpoint := proxy.Host
		if proxy.Port() == "" {
			port := "80"
			if proxy.Scheme == "https" {
				port = "443"
			}
			endpoint = net.JoinHostPort(proxy.Hostname(), port)
		}
		conn, err := t.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, err
		}
		ok := false
		defer func() {
			if !ok {
				conn.Close()
			}
		}()
		deadline := time.Now().Add(30 * time.Second)
		if d, exists := ctx.Deadline(); exists && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		rawConn := conn
		stop := context.AfterFunc(ctx, func() { rawConn.Close() })
		defer stop()
		if proxy.Scheme == "https" {
			cfg := t.TLSClientConfig.Clone()
			cfg.ServerName = proxy.Hostname()
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			conn = tc
		}
		req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("corporate proxy refused CONNECT (HTTP %d)", resp.StatusCode)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		ok = true
		return &bufferedTunnel{Conn: conn, reader: reader}, nil
	}
}

type bufferedTunnel struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedTunnel) Read(p []byte) (int, error) { return c.reader.Read(p) }
