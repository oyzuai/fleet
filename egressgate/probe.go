package egressgate

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProbeOptions say what the self-test job checks.
type ProbeOptions struct {
	// Proxy is the gateway's proxy URL on the job's network.
	Proxy string
	// Deny is a host:port the job's allow list does not hold; the gateway
	// must refuse a CONNECT to it.
	Deny string
	// Direct are addresses the probe dials without the proxy; none may
	// connect.
	Direct []string
}

// Probe is the startup self-test, run as a job would run: through the same
// network, proxy and DNS. It fails if the gateway does not know the job, if
// a denied destination is not refused, if a name resolves, or if any direct
// connection gets out.
func Probe(ctx context.Context, o ProbeOptions) error {
	u, err := url.Parse(o.Proxy)
	if err != nil || u.Host == "" {
		return fmt.Errorf("probe: %q is not a proxy URL", o.Proxy)
	}
	jc := NewJobClient(o.Proxy)
	if err := waitReady(ctx, jc); err != nil {
		return err
	}
	deny := o.Deny
	if deny == "" {
		deny = "probe.invalid:443"
	}
	if err := probeConnect(ctx, u.Host, deny); err != nil {
		return err
	}
	if addrs, err := net.DefaultResolver.LookupHost(ctx, "probe.invalid"); err == nil {
		return fmt.Errorf("probe: a lookup answered %v; the DNS sinkhole is not in the path", addrs)
	}
	for _, d := range o.Direct {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := (&net.Dialer{}).DialContext(dctx, "tcp", d)
		cancel()
		if err == nil {
			c.Close()
			return fmt.Errorf("probe: connected directly to %s; the job network has a route out", d)
		}
	}
	return nil
}

func waitReady(ctx context.Context, jc *JobClient) error {
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) && ctx.Err() == nil {
		ok, err := jc.Ready(ctx)
		if ok {
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("the gateway does not know this job")
	}
	return fmt.Errorf("probe: the gateway is not ready: %w", last)
}

var errProbeUnexpected = errors.New("proxy answered without refusing")

// probeConnect sends CONNECT to the proxy by hand and wants the gateway's
// refusal.
func probeConnect(ctx context.Context, proxyHost, dest string) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(dctx, "tcp", proxyHost)
	if err != nil {
		return fmt.Errorf("probe: reach the proxy: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get(DeniedHeader) == "denied" {
		return nil
	}
	return fmt.Errorf("%w: CONNECT to %s was answered %s", errProbeUnexpected, dest, resp.Status)
}

func probeCommand(args []string) error {
	fs := flag.NewFlagSet("oyzu-executor gateway probe", flag.ContinueOnError)
	proxy := fs.String("proxy", "", "the gateway's proxy URL on this network")
	deny := fs.String("deny", "probe.invalid:443", "a host:port that must be refused")
	direct := fs.String("direct", "", "comma-separated addresses that must be unreachable without the proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := notifyContext()
	defer stop()
	var addrs []string
	for _, a := range strings.Split(*direct, ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	return Probe(ctx, ProbeOptions{Proxy: *proxy, Deny: *deny, Direct: addrs})
}
