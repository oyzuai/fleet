package executor

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// The build reaches hosts that need credentials through a proxy the runner
// runs on loopback, the way the design keeps registry credentials out of
// builds: the build keeps the original hostnames (so lockfiles that record
// resolved URLs still match), trusts a CA made for this job alone, and the
// proxy adds the job's short-lived, read-only credential to requests for
// the hosts runs granted. The credential never reaches the build's
// environment, files or arguments. Other hosts pass through untouched, and
// plain HTTP never gets a credential.
const (
	// EnvEgressCAFile names the job CA's certificate, for tools that take
	// one extra CA.
	EnvEgressCAFile = "OYZU_EGRESS_CA_FILE"
	// egressCAValidity bounds the CA and every certificate it signs. The CA
	// key lives only in the runner's memory and dies with the job.
	egressCAValidity = 7 * 24 * time.Hour
	// egressRefreshBefore is how close to expiry a grant is renewed.
	egressRefreshBefore = 2 * time.Minute
	egressDialTimeout   = 30 * time.Second
	egressProxyUser     = "oyzu"
)

// caBundleVars point a tool at a whole trust store, so they get the
// system roots plus the job CA. NODE_EXTRA_CA_CERTS adds to Node's own
// roots, so it gets the job CA alone.
var caBundleVars = []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "CARGO_HTTP_CAINFO"}

// proxyVars are the proxy settings tools read, in both spellings.
var proxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}

// systemBundles are where Linux and macOS keep the system roots as PEM, as
// Go's own crypto/x509 looks for them.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// egressProxy is one job's credential-injecting proxy.
type egressProxy struct {
	refresh func(context.Context) (runnerclient.Egress, error)
	// issued is told every credential and secret, so the log masks them.
	issued func(...string)
	log    *slog.Logger
	// dial reaches a tunnelled host; upstream sends credentialed and plain
	// HTTP requests. Tests replace both.
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	upstream http.RoundTripper

	secret string
	url    string
	dir    string
	caFile string
	// bundleFile is the system roots plus the job CA, or empty when the
	// system keeps no PEM bundle (Windows).
	bundleFile string
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	leafKey    *ecdsa.PrivateKey
	// hosts are the only hosts the proxy intercepts: the grants it started
	// with, which the CA's name constraints also name.
	hosts map[string]bool

	srv     *http.Server
	inner   *http.Server
	pending *connQueue

	mu      sync.Mutex
	grants  map[string]runnerclient.EgressGrant
	certs   map[string]*tls.Certificate
	seen    map[string]string
	tunnels map[net.Conn]bool
}

// startEgress starts the proxy for first's grants on an ephemeral loopback
// port. refresh mints them again as they near expiry.
func startEgress(first runnerclient.Egress, refresh func(context.Context) (runnerclient.Egress, error), issued func(...string), log *slog.Logger) (*egressProxy, error) {
	hosts := map[string]bool{}
	for _, g := range first.Grants {
		h := strings.ToLower(g.Host)
		if !validGrantHost(h) || g.Authorization == "" || strings.ContainsAny(g.Authorization, "\r\n") {
			return nil, fmt.Errorf("runs sent an unusable egress grant for %q", g.Host)
		}
		hosts[h] = true
	}
	if len(hosts) == 0 {
		return nil, errors.New("runs sent no egress grants")
	}
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	p := &egressProxy{
		refresh: refresh, issued: issued, log: log, secret: hex.EncodeToString(raw[:]), hosts: hosts,
		certs: map[string]*tls.Certificate{}, seen: map[string]string{}, tunnels: map[net.Conn]bool{},
	}
	p.dial = (&net.Dialer{Timeout: egressDialTimeout}).DialContext
	p.upstream = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: egressDialTimeout}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	issued(p.secret)
	p.setGrants(first)
	if err := p.makeCA(); err != nil {
		return nil, fmt.Errorf("make the job CA: %w", err)
	}
	if err := p.writeCA(); err != nil {
		p.removeFiles()
		return nil, fmt.Errorf("write the job CA: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		p.removeFiles()
		return nil, err
	}
	p.url = (&url.URL{Scheme: "http", User: url.UserPassword(egressProxyUser, p.secret), Host: ln.Addr().String()}).String()
	p.pending = newConnQueue(ln.Addr())
	p.inner = &http.Server{
		// Built per request, like plain, so it always uses p.upstream.
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.intercepted().ServeHTTP(w, r) }),
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if m, ok := c.(*interceptedConn); ok {
				return context.WithValue(ctx, hostKey{}, m.host)
			}
			return ctx
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	go func() { _ = p.inner.Serve(p.pending) }()
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// validGrantHost accepts a DNS name without a port, the only thing a grant
// can name.
func validGrantHost(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil || strings.Trim(h, ".") != h {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "-") != label {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// setGrants replaces the grants for the hosts the proxy intercepts and
// masks their credentials. A grant for any other host is ignored: the CA
// cannot sign for it.
func (p *egressProxy) setGrants(e runnerclient.Egress) {
	grants := map[string]runnerclient.EgressGrant{}
	for _, g := range e.Grants {
		h := strings.ToLower(g.Host)
		if !p.hosts[h] || g.Authorization == "" || strings.ContainsAny(g.Authorization, "\r\n") {
			continue
		}
		grants[h] = g
		_, cred, _ := strings.Cut(g.Authorization, " ")
		p.issued(g.Authorization, cred)
	}
	p.grants = grants
}

// authorization is the credential for host, renewed first when it is about
// to expire.
func (p *egressProxy) authorization(ctx context.Context, host string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.grants[host]
	if ok && p.refresh != nil && !g.Expires.IsZero() && time.Until(g.Expires) < egressRefreshBefore {
		e, err := p.refresh(ctx)
		if err != nil {
			p.log.Warn("egress grants not renewed", "error", err)
		} else {
			p.setGrants(e)
			g, ok = p.grants[host]
		}
	}
	return g.Authorization, ok
}

// env is what the build is given to use the proxy and trust its CA.
func (p *egressProxy) env(environ []string) []string {
	noProxy := "localhost,127.0.0.1,::1"
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if (k == "NO_PROXY" || k == "no_proxy") && v != "" {
			noProxy = v + "," + noProxy
			break
		}
	}
	set := map[string]string{"NO_PROXY": noProxy, "no_proxy": noProxy, EnvEgressCAFile: p.caFile, "NODE_EXTRA_CA_CERTS": p.caFile}
	for _, k := range proxyVars {
		set[k] = p.url
	}
	if p.bundleFile != "" {
		for _, k := range caBundleVars {
			set[k] = p.bundleFile
		}
	}
	out := make([]string, 0, len(environ)+len(set))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; !ok {
			out = append(out, kv)
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	return out
}

// stop closes the proxy and every connection through it, and deletes the
// CA files.
func (p *egressProxy) stop() {
	_ = p.srv.Close()
	_ = p.inner.Close()
	p.mu.Lock()
	for c := range p.tunnels {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.removeFiles()
}

func (p *egressProxy) removeFiles() {
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

// report says where the build went through the proxy, for the summary.
func (p *egressProxy) report() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		return ""
	}
	var with, other []string
	for dest, how := range p.seen {
		if how == "credential" {
			with = append(with, "`"+dest+"`")
		} else {
			other = append(other, "`"+dest+"`")
		}
	}
	slices.Sort(with)
	slices.Sort(other)
	var parts []string
	if len(with) > 0 {
		parts = append(parts, "with the job's read credential: "+strings.Join(with, ", "))
	}
	if len(other) > 0 {
		parts = append(parts, "passed through: "+strings.Join(other, ", "))
	}
	return "Egress proxy, " + strings.Join(parts, "; ") + "."
}

func (p *egressProxy) record(dest, how string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[dest] != "credential" {
		p.seen[dest] = how
	}
}

// ServeHTTP is the proxy's front door: CONNECT for HTTPS, absolute URLs
// for plain HTTP, each only with the job's proxy password.
func (p *egressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="oyzu egress"`)
		http.Error(w, "Use the proxy URL in HTTPS_PROXY, with its password.", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "The proxy forwards absolute http:// URLs and CONNECT.", http.StatusBadRequest)
		return
	}
	dest := r.URL.Host
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "80")
	}
	p.record(dest, "http")
	p.plain().ServeHTTP(w, r)
}

func (p *egressProxy) authorized(r *http.Request) bool {
	scheme, cred, _ := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(cred)
	if err != nil {
		return false
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	return user == egressProxyUser && subtle.ConstantTimeCompare([]byte(pass), []byte(p.secret)) == 1
}

// connect intercepts a granted host on 443 and tunnels anything else.
func (p *egressProxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT needs host:port.", http.StatusBadRequest)
		return
	}
	host = strings.ToLower(host)
	if port == "443" && p.hosts[host] {
		p.intercept(w, host)
		return
	}
	p.tunnel(r.Context(), w, net.JoinHostPort(host, port))
}

// hijack takes the client connection over after answering the CONNECT.
func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("the connection cannot be taken over")
	}
	c, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	if buf.Reader.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: buf.Reader}, nil
	}
	return c, nil
}

func (p *egressProxy) tunnel(ctx context.Context, w http.ResponseWriter, addr string) {
	up, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		http.Error(w, "Could not reach "+addr+".", http.StatusBadGateway)
		return
	}
	c, err := hijack(w)
	if err != nil {
		up.Close()
		return
	}
	p.record(addr, "tunnel")
	p.mu.Lock()
	p.tunnels[c], p.tunnels[up] = true, true
	p.mu.Unlock()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	go func() {
		<-done
		<-done
		c.Close()
		up.Close()
		p.mu.Lock()
		delete(p.tunnels, c)
		delete(p.tunnels, up)
		p.mu.Unlock()
	}()
}

func (p *egressProxy) intercept(w http.ResponseWriter, host string) {
	c, err := hijack(w)
	if err != nil {
		return
	}
	tc := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// The certificate is for the CONNECT host whatever the SNI says, so
		// the credential only ever goes where the build asked to connect.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return p.leaf(host) },
	})
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		p.log.Debug("egress TLS handshake failed", "host", host, "error", err)
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	if !p.pending.push(&interceptedConn{Conn: tc, host: host}) {
		tc.Close()
	}
}

type hostKey struct{}

// intercepted forwards a request from inside an intercepted tunnel to its
// host over verified TLS, adding the grant's credential when the build sent
// none. The build's own Authorization is kept, so a registry's token
// exchange still works: the proxy's credential gets the build a scoped
// token, which the build then sends itself.
func (p *egressProxy) intercepted() http.Handler {
	return &httputil.ReverseProxy{
		Transport: p.upstream,
		Rewrite: func(pr *httputil.ProxyRequest) {
			host, _ := pr.In.Context().Value(hostKey{}).(string)
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "https", host, host
			pr.Out.Header.Del("Proxy-Authorization")
			p.record(host, "credential")
			if pr.Out.Header.Get("Authorization") != "" {
				return
			}
			if auth, ok := p.authorization(pr.In.Context(), host); ok {
				pr.Out.Header.Set("Authorization", auth)
			}
		},
		ErrorHandler: p.upstreamError,
	}
}

// plain forwards plain HTTP as is: never with a credential.
func (p *egressProxy) plain() http.Handler {
	return &httputil.ReverseProxy{
		Transport: p.upstream,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.Host = pr.In.URL.Host
			pr.Out.Header.Del("Proxy-Authorization")
		},
		ErrorHandler: p.upstreamError,
	}
}

func (p *egressProxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	p.log.Debug("egress upstream failed", "host", r.Host, "error", err)
	http.Error(w, "The egress proxy could not reach "+r.Host+".", http.StatusBadGateway)
}

// makeCA makes the job's CA, constrained to the granted hosts so nothing
// it signs is good anywhere else.
func (p *egressProxy) makeCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	permitted := make([]string, 0, len(p.hosts))
	for h := range p.hosts {
		permitted = append(permitted, h)
	}
	slices.Sort(permitted)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "Oyzu job egress CA", Organization: []string{"Oyzu"}},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(egressCAValidity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	p.ca, p.caKey, p.leafKey = ca, key, leafKey
	return nil
}

// writeCA writes the CA certificate, and the system roots with it when the
// system keeps them in a PEM file.
func (p *egressProxy) writeCA() error {
	dir, err := os.MkdirTemp("", "oyzu-egress-")
	if err != nil {
		return err
	}
	p.dir = dir
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw})
	p.caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p.caFile, caPEM, 0o644); err != nil {
		return err
	}
	roots := systemRoots()
	if roots == nil {
		p.log.Warn("no system CA bundle found: only Node and tools given " + EnvEgressCAFile + " will trust the egress proxy")
		return nil
	}
	if len(roots) > 0 && roots[len(roots)-1] != '\n' {
		roots = append(roots, '\n')
	}
	p.bundleFile = filepath.Join(dir, "bundle.pem")
	return os.WriteFile(p.bundleFile, append(roots, caPEM...), 0o644)
}

// systemRoots reads the runner's trust store as PEM: the file SSL_CERT_FILE
// names, else the first system bundle found.
func systemRoots() []byte {
	paths := systemBundles
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		paths = append([]string{f}, paths...)
	}
	for _, f := range paths {
		if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

// leaf returns the certificate the proxy shows the build for host.
func (p *egressProxy) leaf(host string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.certs[host]; ok {
		return c, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     p.ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &p.leafKey.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: p.leafKey}
	p.certs[host] = c
	return c, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// interceptedConn is a decrypted tunnel and the host it was opened to.
type interceptedConn struct {
	net.Conn
	host string
}

// bufferedConn reads what the server had already buffered first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// connQueue is a listener the inner server accepts intercepted tunnels
// from.
type connQueue struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnQueue(addr net.Addr) *connQueue {
	return &connQueue{addr: addr, conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (q *connQueue) push(c net.Conn) bool {
	select {
	case q.conns <- c:
		return true
	case <-q.closed:
		return false
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.closed:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.closed) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }
