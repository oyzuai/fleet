package egressgate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oyzuai/fleet/readiness"
)

func readinessProbeCommand(args []string) error {
	fs := flag.NewFlagSet("gateway probe-readiness", flag.ContinueOnError)
	raw := fs.String("challenge", "", "server-selected diagnostic challenge")
	proxy := fs.String("proxy", "", "actual job gateway")
	control := fs.String("control", "", "gateway data-interface control address that must be unreachable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(*raw) > 8192 {
		return errors.New("oversized readiness challenge")
	}
	var c readiness.Challenge
	d := json.NewDecoder(strings.NewReader(*raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return err
	}
	if c.Descriptor.Validate() != nil || len(c.Nonce) != 32 || strings.Trim(c.Nonce, "0123456789abcdef") != "" || c.Suite != readiness.Suite {
		return errors.New("invalid readiness challenge")
	}
	ctx, cancel := context.WithDeadline(context.Background(), c.Deadline)
	defer cancel()
	r := readiness.Result{Challenge: c.ID, Session: c.Session, Generation: c.Generation, Fingerprint: c.Fingerprint, Suite: c.Suite}
	add := func(name, outcome, reason string) {
		r.Checks = append(r.Checks, readiness.Subcheck{Name: name, Outcome: outcome, Reason: reason})
	}
	if err := readiness.AllowedEcho(ctx, c.Descriptor, c.Nonce, *proxy); err != nil {
		add("allowed-path", "inconclusive", "ALLOWED_PATH_UNAVAILABLE")
	} else {
		add("allowed-path", "passed", "ALLOWED_PATH_REACHED")
	}
	u, err := url.Parse(*proxy)
	if err != nil || u.Host == "" {
		return errors.New("invalid probe gateway")
	}
	if err := probeConnect(ctx, u.Host, "probe.invalid:443"); err != nil {
		add("proxy-refusal", "failed", "PROXY_REFUSAL_NOT_OBSERVED")
	} else {
		add("proxy-refusal", "passed", "GATEWAY_REFUSED")
	}
	target, _ := url.Parse(c.Descriptor.URL)
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	connected := func(address string) bool {
		cctx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		conn, err := (&net.Dialer{}).DialContext(cctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return true
		}
		return false
	}
	if connected(net.JoinHostPort(target.Hostname(), port)) {
		add("direct-egress", "failed", "DIRECT_BYPASS_SUCCEEDED")
	} else {
		add("direct-egress", "passed", "DIRECT_PATH_BLOCKED")
	}
	dnsOK := true
	resolv, readErr := os.ReadFile("/etc/resolv.conf")
	if readErr != nil {
		dnsOK = false
	}
	var servers []string
	for _, line := range strings.Split(string(resolv), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "nameserver" {
			servers = append(servers, parts[1])
		}
	}
	if len(servers) != 1 || servers[0] != u.Hostname() {
		dnsOK = false
	}
	if !readiness.DNSRefused(ctx, net.JoinHostPort(u.Hostname(), "53"), c.Descriptor.DNSName) {
		dnsOK = false
	}
	for _, network := range []string{"udp", "tcp"} {
		if readiness.DNSResponds(ctx, network, c.Descriptor.DNSAddress, c.Descriptor.DNSName) {
			dnsOK = false
		}
	}
	if dnsOK {
		add("dns-confinement", "passed", "DNS_PATH_CONFINED")
	} else {
		add("dns-confinement", "failed", "DNS_BOUNDARY_NOT_CONFIRMED")
	}
	if *control == "" {
		add("control-isolation", "inconclusive", "CONTROL_ADDRESS_MISSING")
	} else if connected(*control) {
		add("control-isolation", "failed", "CONTROL_PORT_REACHABLE")
	} else {
		add("control-isolation", "passed", "CONTROL_PORT_BLOCKED")
	}
	// The manager supplies the positive controls and cleanup results from
	// outside the sandbox; the child cannot certify either for itself.
	add("cleanup", "inconclusive", "CLEANUP_PENDING")
	r.Aggregate()
	return json.NewEncoder(os.Stdout).Encode(r)
}

func canaryCommand(args []string) error {
	fs := flag.NewFlagSet("gateway readiness-canary", flag.ContinueOnError)
	h := fs.String("http", ":8080", "diagnostic HTTP address")
	d := fs.String("dns", ":53", "diagnostic UDP/TCP DNS address")
	n := fs.String("dns-name", "readiness.oyzu.test", "fixed diagnostic DNS name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := notifyContext()
	defer stop()
	return readiness.ServeCanary(ctx, *h, *d, *n)
}

func controlInterface(address, iface string) (string, error) {
	if iface == "" {
		return address, nil
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}
	as, err := i.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range as {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.To4() != nil && !ip.IsLoopback() {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", errors.New("control interface has no management IPv4 address")
}
