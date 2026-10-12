package egressgate

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu    sync.Mutex
	names map[string][]string
	calls int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	ips, ok := r.names[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

// rig is a gateway whose outside world is one local server: every dial,
// whatever address was checked, reaches it, and dialed records what the
// gateway asked for.
type rig struct {
	g      *Gateway
	proxy  *httptest.Server
	res    *fakeResolver
	mu     sync.Mutex
	dialed []string
	origin net.Listener
}

func newRig(t *testing.T, mode Mode, allow ...Allow) *rig {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				// Plain HTTP request, or an echo for a tunnel.
				if peek, _ := br.Peek(4); string(peek) == "GET " || string(peek) == "POST" {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					if strings.HasPrefix(req.URL.Path, "/redirect") {
						fmt.Fprint(c, "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\n\r\n")
						return
					}
					fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
					return
				}
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	r := &rig{res: &fakeResolver{names: map[string][]string{
		"registry.npmjs.org": {"104.16.1.1"},
		"cdn.example.com":    {"104.16.2.2"},
		"internal.corp":      {"10.1.2.3"},
		"sneaky.example.com": {"169.254.169.254"},
		"v6only.example.com": {"2606:4700::1"},
		"mixed.example.com":  {"10.0.0.1", "104.16.3.3"},
	}}, origin: ln}
	r.g = New(Config{Mode: mode, Pool: "linux", Resolver: r.res, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			r.mu.Lock()
			r.dialed = append(r.dialed, addr)
			r.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
		}})
	r.proxy = httptest.NewServer(r.g.ProxyHandler())
	t.Cleanup(r.proxy.Close)
	t.Cleanup(r.g.Close)
	if err := r.g.Register(Registration{Job: "7", Sources: []string{"127.0.0.0/8"}, Allow: allow}); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) addr() string { return strings.TrimPrefix(r.proxy.URL, "http://") }

// connect sends CONNECT by hand and returns the status line's code.
func (r *rig) connect(t *testing.T, dest string) (int, net.Conn, string) {
	t.Helper()
	c, err := net.Dial("tcp", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	if resp.StatusCode != 200 {
		body, _ = io.ReadAll(resp.Body)
	}
	return resp.StatusCode, c, string(body)
}

func (r *rig) get(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	u := strings.TrimPrefix(rawURL, "http://")
	host, _, _ := strings.Cut(u, "/")
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", rawURL, host)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b) + "|" + resp.Header.Get("Location")
}

func (r *rig) denials() []Denial {
	d, _, _ := r.g.Denials("7", 0)
	return d
}

func TestConnectAllowedHostIsTunnelledToTheCheckedAddress(t *testing.T) {
	r := newRig(t, ModeEnforce, Allow{Host: "registry.npmjs.org"})
	code, c, _ := r.connect(t, "registry.npmjs.org:443")
	if code != 200 {
		t.Fatalf("CONNECT = %d", code)
	}
	fmt.Fprint(c, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("tunnel echoed %q, %v", buf, err)
	}
	if len(r.dialed) != 1 || r.dialed[0] != "104.16.1.1:443" {
		t.Fatalf("dialed %v; the gateway must dial the address it checked", r.dialed)
	}
	if r.res.calls != 1 {
		t.Fatalf("the name was resolved %d times; the checked answer is the one to dial", r.res.calls)
	}
	if len(r.denials()) != 0 {
		t.Fatalf("denials = %+v", r.denials())
	}
}

func TestConnectRefusesWhatIsNotOnTheList(t *testing.T) {
	r := newRig(t, ModeEnforce, Allow{Host: "registry.npmjs.org"}, Allow{Host: "*.example.com"})
	for _, dest := range []string{
		"evil.test:443",
		"registry.npmjs.org:8443", // right host, wrong port
		"example.com:443",         // *.example.com is not the apex
		"notexample.com:443",
	} {
		code, _, body := r.connect(t, dest)
		if code != 403 {
			t.Errorf("CONNECT %s = %d, want 403", dest, code)
		}
		host, port, _ := strings.Cut(dest, ":")
		want := "Blocked network request to " + dest + ": not on this job's allow list. A pool admin can allow it with `runs admin pool egress allow linux " + host + "`."
		if !strings.Contains(body, want) {
			t.Errorf("CONNECT %s body = %q, want %q", dest, body, want)
		}
		_ = port
	}
	if len(r.dialed) != 0 {
		t.Fatalf("dialed %v for refused hosts", r.dialed)
	}
	d := r.denials()
	if len(d) != 4 || d[0].Host != "evil.test" || d[0].Port != 443 || d[0].Method != "CONNECT" || d[0].Time.IsZero() {
		t.Fatalf("denials = %+v", d)
	}
}

func TestWildcardMatchesSubdomains(t *testing.T) {
	r := newRig(t, ModeEnforce, Allow{Host: "*.example.com", Port: 443})
	if code, _, _ := r.connect(t, "cdn.example.com:443"); code != 200 {
		t.Fatalf("subdomain = %d", code)
	}
}

func TestPrivateAndMetadataAddressesAreRefused(t *testing.T) {
	r := newRig(t, ModeEnforce,
		Allow{Host: "internal.corp"}, Allow{Host: "*.example.com"}, Allow{Host: "127.0.0.1"},
		Allow{Host: "169.254.169.254", Port: 80}, Allow{Host: "100.64.1.1"}, Allow{Host: "fd00:ec2::254"})
	// Wildcards and names that resolve into the private ranges never get through.
	for _, dest := range []string{"sneaky.example.com:443"} {
		if code, _, body := r.connect(t, dest); code != 403 || !strings.Contains(body, "metadata") {
			t.Errorf("CONNECT %s = %d %q", dest, code, body)
		}
	}
	// A name matched exactly may point into a private range: the admin said so.
	if code, _, _ := r.connect(t, "internal.corp:443"); code != 200 {
		t.Errorf("exactly allowed internal.corp = %d", code)
	}
	// A wildcard resolving to a mix gets only the public address.
	r.dialed = nil
	if code, _, _ := r.connect(t, "mixed.example.com:443"); code != 200 || len(r.dialed) != 1 || r.dialed[0] != "104.16.3.3:443" {
		t.Errorf("mixed answer dialed %v", r.dialed)
	}
	// Literal addresses are held to the same rules, unlocked only by an exact entry.
	r2 := newRig(t, ModeEnforce, Allow{Host: "*.example.com"})
	for _, dest := range []string{"127.0.0.1:443", "10.0.0.5:443", "169.254.169.254:443", "100.64.0.1:443", "[fd00:ec2::254]:443", "[::1]:443"} {
		if code, _, _ := r2.connect(t, dest); code != 403 {
			t.Errorf("CONNECT %s = %d, want 403", dest, code)
		}
	}
}

func TestRestrictedRanges(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.1.1": true, "172.16.0.1": true, "192.168.1.1": true, "169.254.169.254": true,
		"169.254.1.1": true, "100.64.0.1": true, "100.127.255.255": true, "0.0.0.0": true, "224.0.0.1": true,
		"fd00:ec2::254": true, "fe80::1": true, "::1": true, "::ffff:10.0.0.1": true, "64:ff9b::a00:1": true,
		"8.8.8.8": false, "104.16.1.1": false, "100.128.0.1": false, "2606:4700::1": false,
	} {
		if got := restricted(netip.MustParseAddr(ip)); got != want {
			t.Errorf("restricted(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestIPv6IsRefusedUnlessTheAddressItselfIsAllowed(t *testing.T) {
	r := newRig(t, ModeEnforce, Allow{Host: "v6only.example.com"}, Allow{Host: "2606:4700::1"}, Allow{Host: "*.example.com"})
	if code, _, body := r.connect(t, "v6only.example.com:443"); code != 403 || !strings.Contains(body, "IPv6") {
		t.Errorf("a name with only AAAA records = %d %q", code, body)
	}
	if code, _, _ := r.connect(t, "[2606:4700::1]:443"); code != 200 {
		t.Errorf("an allowed IPv6 literal = %d", code)
	}
	if code, _, _ := r.connect(t, "[2606:4700::2]:443"); code != 403 {
		t.Errorf("an IPv6 literal that is not allowed = %d", code)
	}
}

func TestPlainHTTPIsCheckedAndRedirectsAreNotFollowed(t *testing.T) {
	r := newRig(t, ModeEnforce, Allow{Host: "cdn.example.com", Port: 80})
	if code, body := r.get(t, "http://cdn.example.com/x"); code != 200 || !strings.HasPrefix(body, "ok") {
		t.Fatalf("allowed GET = %d %q", code, body)
	}
	if len(r.dialed) != 1 || r.dialed[0] != "104.16.2.2:80" {
		t.Fatalf("dialed %v", r.dialed)
	}
	// The redirect to the metadata address comes back as it is; following it
	// is the client's next request, which is checked on its own.
	if code, body := r.get(t, "http://cdn.example.com/redirect"); code != 302 || !strings.Contains(body, "169.254.169.254") {
		t.Fatalf("redirect = %d %q", code, body)
	}
	if code, body := r.get(t, "http://169.254.169.254/latest"); code != 403 || !strings.Contains(body, "Blocked network request to 169.254.169.254:80") {
		t.Fatalf("following the redirect = %d %q", code, body)
	}
	if code, _ := r.get(t, "http://other.test/"); code != 403 {
		t.Fatalf("GET to a host not on the list = %d", code)
	}
	if d := r.denials(); len(d) != 2 || d[1].Method != "GET" || d[1].Port != 80 {
		t.Fatalf("denials = %+v", d)
	}
}

func TestReportModeAllowsAndRecordsWouldBlock(t *testing.T) {
	r := newRig(t, ModeReport, Allow{Host: "registry.npmjs.org"})
	code, c, _ := r.connect(t, "cdn.example.com:443")
	if code != 200 {
		t.Fatalf("report mode refused: %d", code)
	}
	fmt.Fprint(c, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := r.connect(t, "registry.npmjs.org:443"); code != 200 {
		t.Fatalf("allowed host = %d", code)
	}
	d := r.denials()
	if len(d) != 1 || !d[0].WouldBlock || d[0].Host != "cdn.example.com" {
		t.Fatalf("denials = %+v", d)
	}
	if line := DenialLine(d[0], "linux"); !strings.Contains(line, "would be blocked once egress is enforced") ||
		strings.HasPrefix(line, "Blocked") {
		t.Fatalf("report line = %q", line)
	}
}

func TestReportModeStillRefusesRestrictedRanges(t *testing.T) {
	r := newRig(t, ModeReport)
	for _, target := range []string{"sneaky.example.com:443", "internal.corp:443", "127.0.0.1:443", "169.254.169.254:80"} {
		if code, _, _ := r.connect(t, target); code != 403 {
			t.Fatalf("report mode let CONNECT %s through: %d", target, code)
		}
	}
	for _, d := range r.denials() {
		if d.WouldBlock {
			t.Fatalf("a restricted range was recorded as would-block: %+v", d)
		}
	}
}

func TestUnknownSourcesAreRefused(t *testing.T) {
	r := newRig(t, ModeReport, Allow{Host: "registry.npmjs.org"})
	r.g.Unregister("7")
	if code, _, _ := r.connect(t, "registry.npmjs.org:443"); code != 403 {
		t.Fatalf("CONNECT from an unregistered source = %d; even report mode fails closed", code)
	}
}

func TestDenialLineWording(t *testing.T) {
	got := DenialLine(Denial{Host: "registry.npmjs.org", Port: 443, Method: "CONNECT"}, "linux")
	want := "Blocked network request to registry.npmjs.org:443: not on this job's allow list. " +
		"A pool admin can allow it with `runs admin pool egress allow linux registry.npmjs.org`."
	if got != want {
		t.Fatalf("line = %q", got)
	}
	if got := DenialLine(Denial{Host: "x.test", Port: 443}, ""); !strings.Contains(got, "egress allow <pool> x.test`") {
		t.Fatalf("line without a pool = %q", got)
	}
}

func TestJobsReadOnlyTheirOwnDenials(t *testing.T) {
	r := newRig(t, ModeEnforce)
	if err := r.g.Register(Registration{Job: "8", Sources: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	r.connect(t, "evil.test:443")
	jc := NewJobClient(r.proxy.URL)
	if ok, err := jc.Ready(context.Background()); !ok || err != nil {
		t.Fatalf("Ready = %v, %v", ok, err)
	}
	reply, err := jc.Denials(context.Background(), 0)
	if err != nil || len(reply.Denials) != 1 || len(reply.Lines) != 1 || reply.Next != 1 ||
		!strings.HasPrefix(reply.Lines[0], "Blocked network request to evil.test:443") {
		t.Fatalf("Denials = %+v, %v", reply, err)
	}
	if reply, _ := jc.Denials(context.Background(), reply.Next); len(reply.Denials) != 0 {
		t.Fatalf("a later read repeated %+v", reply)
	}
	if d, _, ok := r.g.Denials("8", 0); !ok || len(d) != 0 {
		t.Fatalf("job 8 saw %+v", d)
	}
	r.g.Unregister("7")
	if ok, _ := jc.Ready(context.Background()); ok {
		t.Fatal("an unregistered job is ready")
	}
}

func TestRegisterValidatesAndKeepsJobsApart(t *testing.T) {
	g := New(Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ok := Registration{Job: "1", Sources: []string{"172.20.0.0/16"}, Allow: []Allow{{Host: "Runs.Example.", Port: 0}}}
	if err := g.Register(ok); err != nil {
		t.Fatal(err)
	}
	if g.jobs["1"].allow[0] != (Allow{Host: "runs.example", Port: 443}) {
		t.Fatalf("allow = %+v", g.jobs["1"].allow)
	}
	for name, r := range map[string]Registration{
		"overlap":     {Job: "2", Sources: []string{"172.20.1.0/24"}},
		"no sources":  {Job: "3"},
		"bad source":  {Job: "3", Sources: []string{"nope"}},
		"bad wild":    {Job: "3", Sources: []string{"10.9.0.1"}, Allow: []Allow{{Host: "*"}}},
		"bad wild 2":  {Job: "3", Sources: []string{"10.9.0.1"}, Allow: []Allow{{Host: "a.*.com"}}},
		"bad port":    {Job: "3", Sources: []string{"10.9.0.1"}, Allow: []Allow{{Host: "a.com", Port: 70000}}},
		"empty job":   {Sources: []string{"10.9.0.1"}},
		"empty allow": {Job: "3", Sources: []string{"10.9.0.1"}, Allow: []Allow{{Host: ""}}},
	} {
		if err := g.Register(r); err == nil {
			t.Errorf("%s: Register accepted %+v", name, r)
		}
	}
	// Re-registering the same job replaces it and keeps its denials.
	g.record(g.jobs["1"], Denial{Host: "x"})
	if err := g.Register(Registration{Job: "1", Sources: []string{"172.20.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := g.Denials("1", 0); len(d) != 1 {
		t.Fatalf("denials after re-register = %+v", d)
	}
}

func TestControlAPI(t *testing.T) {
	g := New(Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv := httptest.NewServer(g.ControlHandler("s3cret"))
	defer srv.Close()
	ctx := context.Background()
	c := NewClient(srv.URL, "s3cret")
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := NewClient(srv.URL, "wrong").Health(ctx); err == nil {
		t.Fatal("a wrong token was accepted")
	}
	if err := NewClient(srv.URL, "").Health(ctx); err == nil {
		t.Fatal("no token was accepted")
	}
	reg := Registration{Job: "42", Sources: []string{"172.30.0.0/16"}, Allow: []Allow{{Host: "runs.example", Port: 443}}}
	if err := c.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := g.Denials("42", 0); !ok {
		t.Fatal("not registered")
	}
	g.record(g.jobs["42"], Denial{Host: "a.test", Port: 443, Method: "CONNECT"})
	if r, err := c.Denials(ctx, "42", 0); err != nil || len(r.Denials) != 1 {
		t.Fatalf("Denials = %+v, %v", r, err)
	}
	if err := c.Register(ctx, Registration{Job: "43", Sources: []string{"172.30.1.0/24"}}); err == nil {
		t.Fatal("an overlapping source was accepted")
	}
	if err := c.Unregister(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if err := c.Unregister(ctx, "42"); err != nil {
		t.Fatalf("unregistering twice = %v", err)
	}
	if _, err := c.Denials(ctx, "42", 0); !NotFound(err) {
		t.Fatalf("Denials of an unregistered job = %v", err)
	}
	// A caller that is itself a job is refused, token or not.
	if err := g.Register(Registration{Job: "loop", Sources: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Health(ctx); err == nil {
		t.Fatal("a job reached the control API")
	}
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q, id)
	q[2] = 0x01 // RD
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

func TestDNSSinkholeRefusesAndRecords(t *testing.T) {
	g := New(Config{Pool: "linux", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := g.Register(Registration{Job: "9", Sources: []string{"127.0.0.1"}, Allow: []Allow{{Host: "registry.npmjs.org"}}}); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.ServeDNS(pc) }()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, name := range []string{"Evil.Test", "registry.npmjs.org"} {
		q := dnsQuery(0xBEEF, name, 1)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(q); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		resp := buf[:n]
		if binary.BigEndian.Uint16(resp) != 0xBEEF || resp[2]&0x80 == 0 || resp[3]&0x0F != dnsRefused ||
			binary.BigEndian.Uint16(resp[6:]) != 0 || string(resp[12:]) != string(q[12:]) {
			t.Fatalf("response to %s = % x", name, resp)
		}
	}
	// Garbage gets no answer and no panic.
	_, _ = c.Write([]byte{1, 2, 3})
	d, _, _ := g.Denials("9", 0)
	if len(d) != 2 || d[0].Host != "evil.test" || d[0].Method != "DNS" || d[0].Reason != "" || d[0].Port != 443 {
		t.Fatalf("denials = %+v", d)
	}
	if !strings.Contains(g.Line(d[0]), "Blocked network request to evil.test:443: not on this job's allow list.") {
		t.Fatalf("line = %q", g.Line(d[0]))
	}
	if d[1].Host != "registry.npmjs.org" || !strings.Contains(g.Line(d[1]), "instead of using the HTTPS_PROXY") {
		t.Fatalf("a direct lookup of an allowed host = %+v / %q", d[1], g.Line(d[1]))
	}
	pc.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProbePassesOnlyThroughAnEnforcingGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A closed port stands in for an address with no route.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	r := newRig(t, ModeEnforce, Allow{Host: "registry.npmjs.org"})
	if err := Probe(ctx, ProbeOptions{Proxy: r.proxy.URL, Direct: []string{deadAddr}}); err != nil {
		t.Fatalf("enforcing gateway: %v", err)
	}
	if d := r.denials(); len(d) != 1 || d[0].Host != "probe.invalid" || d[0].Method != "CONNECT" {
		t.Fatalf("the gateway recorded %+v", d)
	}
	// A direct connection that gets out fails the probe.
	if err := Probe(ctx, ProbeOptions{Proxy: r.proxy.URL, Direct: []string{r.origin.Addr().String()}}); err == nil ||
		!strings.Contains(err.Error(), "route out") {
		t.Fatalf("a reachable direct address = %v", err)
	}
	// A gateway that lets the denied host through fails it too.
	rr := newRig(t, ModeReport)
	rr.res.names["probe.invalid"] = []string{"104.16.9.9"}
	if err := Probe(ctx, ProbeOptions{Proxy: rr.proxy.URL}); err == nil {
		t.Fatal("the probe passed against a gateway that allows the denied host")
	}
}
