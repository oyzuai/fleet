package executor

import (
	"bufio"
	"context"
	"encoding/base64"
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

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/runnerclient"
)

type staticResolver map[string]string

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if ip, ok := r[host]; ok {
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

// gatewayRig is a real gateway, with an echo server standing in for the
// outside, that registers the loopback network as one job.
func gatewayRig(t *testing.T, allow ...egressgate.Allow) (url string, g *egressgate.Gateway) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	g = egressgate.New(egressgate.Config{
		Pool: "linux", Resolver: staticResolver{"example.com": "93.184.216.34"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
		},
	})
	t.Cleanup(g.Close)
	srv := httptest.NewServer(g.ProxyHandler())
	t.Cleanup(srv.Close)
	if err := g.Register(egressgate.Registration{Job: "1", Sources: []string{"127.0.0.0/8"}, Allow: allow}); err != nil {
		t.Fatal(err)
	}
	return srv.URL, g
}

func connectVia(t *testing.T, p *egressProxy, dest string) (*http.Response, net.Conn) {
	t.Helper()
	u := strings.TrimPrefix(p.url, "http://")
	cred, host, _ := strings.Cut(u, "@")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", dest, dest, base64.StdEncoding.EncodeToString([]byte(cred)))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return resp, c
}

func TestProxyWithAGatewayChainsAndNeedsNoGrants(t *testing.T) {
	gw, _ := gatewayRig(t, egressgate.Allow{Host: "example.com"})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := startEgress(runnerclient.Egress{}, nil, func(...string) {}, log, gw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	if p.caFile != "" || p.bundleFile != "" {
		t.Fatalf("a proxy with nothing to intercept made a CA: %q", p.caFile)
	}
	for _, kv := range p.env(nil) {
		if strings.HasPrefix(kv, EnvEgressCAFile+"=") || strings.HasPrefix(kv, "NODE_EXTRA_CA_CERTS=") {
			t.Fatalf("env asks the build to trust a CA: %s", kv)
		}
	}
	resp, c := connectVia(t, p, "example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("allowed CONNECT = %s", resp.Status)
	}
	fmt.Fprint(c, "ping!")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping!" {
		t.Fatalf("tunnel through the gateway: %q, %v", buf, err)
	}
	resp, _ = connectVia(t, p, "evil.test:443")
	body, _ := io.ReadAll(resp.Body)
	want := "Blocked network request to evil.test:443: not on this job's allow list. A pool admin can allow it with `runs admin pool egress allow linux evil.test`."
	if resp.StatusCode != 403 || !strings.Contains(string(body), want) {
		t.Fatalf("denied CONNECT = %s %q", resp.Status, body)
	}
	if _, err := startEgress(runnerclient.Egress{}, nil, func(...string) {}, log, "https://gw"); err == nil {
		t.Fatal("startEgress accepted a gateway that is not an http:// URL")
	}
}

func TestDenialWatcherLogsAndSummarisesBlockedDestinations(t *testing.T) {
	gw, g := gatewayRig(t, egressgate.Allow{Host: "example.com"})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := startEgress(runnerclient.Egress{}, nil, func(...string) {}, log, gw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	var mu sync.Mutex
	var lines []string
	w := newDenialWatcher(gw, func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }, log)
	connectVia(t, p, "evil.test:443")
	connectVia(t, p, "evil.test:443")
	w.poll(context.Background())
	w.poll(context.Background())
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "Blocked network request to evil.test:443") {
		t.Fatalf("log lines = %q", lines)
	}
	if got := w.report(); got != "Network blocked (not on this job's allow list): `evil.test:443`." {
		t.Fatalf("report = %q", got)
	}
	if d, _, _ := g.Denials("1", 0); len(d) != 2 {
		t.Fatalf("gateway denials = %+v", d)
	}
}

func TestWaitGatewayWaitsForRegistration(t *testing.T) {
	gw, g := gatewayRig(t)
	if err := waitGateway(context.Background(), gw); err != nil {
		t.Fatal(err)
	}
	g.Unregister("1")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := waitGateway(ctx, gw); err == nil {
		t.Fatal("an unregistered job was ready")
	}
}
