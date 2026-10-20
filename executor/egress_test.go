package executor

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// upstreams are the hosts the build reaches in these tests: example.com
// over TLS and plain HTTP, and other.test, an echo server only reachable
// through a tunnel.
type upstreams struct {
	tls, plain *httptest.Server
	echo       net.Listener
	mu         sync.Mutex
	seen       []http.Header
}

func newUpstreams(t *testing.T) *upstreams {
	t.Helper()
	u := &upstreams{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		hdr := r.Header.Clone()
		hdr.Set("X-Seen-Host", r.Host)
		u.seen = append(u.seen, hdr)
		u.mu.Unlock()
		fmt.Fprint(w, "ok")
	})
	u.tls = httptest.NewTLSServer(h)
	u.plain = httptest.NewServer(h)
	t.Cleanup(u.tls.Close)
	t.Cleanup(u.plain.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	u.echo = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return u
}

func (u *upstreams) last() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen[len(u.seen)-1]
}

// dial sends each host:port to the server standing in for it.
func (u *upstreams) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	to := map[string]string{
		"example.com:443": u.tls.Listener.Addr().String(),
		"example.com:80":  u.plain.Listener.Addr().String(),
		"other.test:443":  u.echo.Addr().String(),
	}[addr]
	if to == "" {
		return nil, fmt.Errorf("no such host %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}

type maskLog struct {
	mu     sync.Mutex
	values []string
}

func (m *maskLog) add(v ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values = append(m.values, v...)
}

func (m *maskLog) has(v string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.values, v)
}

func grant(host, auth string, expires time.Time) runnerclient.Egress {
	return runnerclient.Egress{Grants: []runnerclient.EgressGrant{{Host: host, Authorization: auth, Expires: expires}}}
}

func startTestEgress(t *testing.T, u *upstreams, first runnerclient.Egress, refresh func(context.Context) (runnerclient.Egress, error)) (*egressProxy, *maskLog) {
	t.Helper()
	masks := &maskLog{}
	p, err := startEgress(first, refresh, masks.add, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.stop)
	tr := u.tls.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = u.dial
	tr.Proxy = nil
	p.upstream, p.dial = tr, u.dial
	return p, masks
}

// buildClient is a tool in the build: it uses the proxy from the
// environment and trusts the job CA.
func buildClient(t *testing.T, p *egressProxy) *http.Client {
	t.Helper()
	pemCA, err := os.ReadFile(p.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCA) {
		t.Fatal("the CA file holds no certificate")
	}
	proxyURL, _ := url.Parse(p.url)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: tlsConfig(roots)}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func get(t *testing.T, c *http.Client, rawURL, auth string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("GET %s = %d %s", rawURL, resp.StatusCode, b)
	}
}

func TestEgressAddsTheCredentialOnlyForGrantedHostsOverTLS(t *testing.T) {
	u := newUpstreams(t)
	p, masks := startTestEgress(t, u, grant("Example.com", "Bearer ghs_read", time.Now().Add(time.Hour)), nil)
	c := buildClient(t, p)

	get(t, c, "https://example.com/oyzuai/oyzu.git/info/refs", "")
	h := u.last()
	if h.Get("Authorization") != "Bearer ghs_read" || h.Get("Proxy-Authorization") != "" || h.Get("X-Seen-Host") != "example.com" {
		t.Fatalf("upstream saw %v", h)
	}
	// The build's own credential wins, so a registry's token exchange works.
	get(t, c, "https://example.com/v2/", "Bearer scoped")
	if got := u.last().Get("Authorization"); got != "Bearer scoped" {
		t.Fatalf("upstream saw %q, want the build's own", got)
	}
	// Plain HTTP to the same host never carries it.
	get(t, c, "http://example.com/plain", "")
	if got := u.last().Get("Authorization"); got != "" || u.last().Get("Proxy-Authorization") != "" {
		t.Fatalf("plain HTTP carried %q", got)
	}
	if !masks.has("Bearer ghs_read") || !masks.has("ghs_read") || !masks.has(p.secret) {
		t.Fatalf("masked %v", masks.values)
	}
	if r := p.report(); !strings.Contains(r, "with the job's read credential: `example.com`") || !strings.Contains(r, "passed through: `example.com:80`") {
		t.Fatalf("report = %q", r)
	}
	if !slices.Equal(p.ca.PermittedDNSDomains, []string{"example.com"}) || !p.ca.PermittedDNSDomainsCritical || p.ca.MaxPathLen != 0 {
		t.Fatalf("CA constraints = %v", p.ca.PermittedDNSDomains)
	}
}

// connect opens a CONNECT tunnel by hand and returns the proxy's answer.
func connect(t *testing.T, p *egressProxy, target, auth string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	u, _ := url.Parse(p.url)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(c, "Proxy-Authorization: %s\r\n", auth)
	}
	fmt.Fprint(c, "\r\n")
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, r, resp.StatusCode
}

func TestEgressTunnelsOtherHostsUntouched(t *testing.T) {
	u := newUpstreams(t)
	p, _ := startTestEgress(t, u, grant("example.com", "Bearer ghs_read", time.Time{}), nil)
	pass, _ := url.Parse(p.url)
	secret, _ := pass.User.Password()
	auth := "Basic " + basicAuth(egressProxyUser, secret)

	c, r, status := connect(t, p, "other.test:443", auth)
	if status != 200 {
		t.Fatalf("CONNECT = %d", status)
	}
	fmt.Fprint(c, "ping\n")
	line, err := r.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
	if r := p.report(); !strings.Contains(r, "passed through: `other.test:443`") {
		t.Fatalf("report = %q", r)
	}
	// A granted host on another port is not intercepted either.
	if _, _, status := connect(t, p, "example.com:8443", auth); status != http.StatusBadGateway {
		t.Fatalf("unreachable port = %d", status)
	}
}

func TestEgressNeedsTheProxyPassword(t *testing.T) {
	u := newUpstreams(t)
	p, _ := startTestEgress(t, u, grant("example.com", "Bearer ghs_read", time.Time{}), nil)
	for _, auth := range []string{"", "Basic " + basicAuth(egressProxyUser, "wrong"), "Bearer " + p.secret} {
		if _, _, status := connect(t, p, "example.com:443", auth); status != http.StatusProxyAuthRequired {
			t.Fatalf("auth %q: CONNECT = %d", auth, status)
		}
	}
}

func TestEgressRenewsAGrantBeforeItExpires(t *testing.T) {
	u := newUpstreams(t)
	var calls int
	refresh := func(context.Context) (runnerclient.Egress, error) {
		calls++
		return grant("example.com", "Bearer ghs_new", time.Now().Add(time.Hour)), nil
	}
	p, masks := startTestEgress(t, u, grant("example.com", "Bearer ghs_old", time.Now().Add(time.Minute)), refresh)
	c := buildClient(t, p)
	get(t, c, "https://example.com/a", "")
	get(t, c, "https://example.com/b", "")
	if got := u.last().Get("Authorization"); got != "Bearer ghs_new" || calls != 1 || !masks.has("ghs_new") {
		t.Fatalf("upstream saw %q after %d renewals", got, calls)
	}
}

func TestEgressRefusesUnusableGrants(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, g := range []runnerclient.EgressGrant{
		{Host: "github.com:443", Authorization: "Bearer x"},
		{Host: "127.0.0.1", Authorization: "Bearer x"},
		{Host: "*.github.com", Authorization: "Bearer x"},
		{Host: "github.com", Authorization: ""},
		{Host: "github.com", Authorization: "Bearer x\r\nX-Evil: 1"},
	} {
		if p, err := startEgress(runnerclient.Egress{Grants: []runnerclient.EgressGrant{g}}, nil, func(...string) {}, log, ""); err == nil {
			p.stop()
			t.Fatalf("accepted %+v", g)
		}
	}
	if _, err := startEgress(runnerclient.Egress{}, nil, func(...string) {}, log, ""); err == nil {
		t.Fatal("started with no grants")
	}
}

func TestEgressEnvPointsTheBuildAtTheProxy(t *testing.T) {
	u := newUpstreams(t)
	p, _ := startTestEgress(t, u, grant("example.com", "Bearer ghs_read", time.Time{}), nil)
	env := p.env([]string{"HTTPS_PROXY=http://corp:3128", "NO_PROXY=corp.internal", "PATH=/bin", "NODE_EXTRA_CA_CERTS=/old.pem"})
	got := map[string][]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for _, k := range proxyVars {
		if !slices.Equal(got[k], []string{p.url}) {
			t.Fatalf("%s = %v", k, got[k])
		}
	}
	if !slices.Equal(got["NO_PROXY"], []string{"corp.internal,localhost,127.0.0.1,::1"}) || !slices.Equal(got["PATH"], []string{"/bin"}) ||
		!slices.Equal(got["NODE_EXTRA_CA_CERTS"], []string{p.caFile}) || !slices.Equal(got[EnvEgressCAFile], []string{p.caFile}) {
		t.Fatalf("env = %v", got)
	}
	if p.bundleFile != "" {
		b, _ := os.ReadFile(p.bundleFile)
		ca, _ := os.ReadFile(p.caFile)
		if !strings.HasSuffix(string(b), string(ca)) || !slices.Equal(got["SSL_CERT_FILE"], []string{p.bundleFile}) {
			t.Fatal("the bundle does not end with the job CA")
		}
	}
	p.stop()
	if _, err := os.Stat(p.dir); !os.IsNotExist(err) {
		t.Fatalf("CA directory left behind: %v", err)
	}
}

func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
