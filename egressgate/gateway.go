// Package egressgate is the enforcing network gateway between jobs and the
// network. A job's own proxy settings cannot enforce anything, because the
// build shares its network namespace and can open any socket it likes, so
// the gateway runs outside the job: a manager gives each job a network with
// no route out and connects only the gateway to it. The gateway tells jobs
// apart by the address they connect from, and holds each one to the allow
// list runs sent with its claim.
//
// It speaks three protocols: an HTTP proxy (CONNECT and plain HTTP) that
// refuses hosts outside the job's list, a DNS responder that answers nothing
// and records the lookup, and a control API the manager uses to register
// and unregister jobs. The proxy resolves each allowed host itself, refuses
// addresses a job should never reach (loopback, private, link-local,
// carrier-grade NAT, cloud metadata) unless that exact host is allowed, and
// dials the address it checked, so a name cannot change its answer between
// the check and the connection.
package egressgate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Mode is what the gateway does with a request outside a job's allow list.
type Mode string

const (
	// ModeEnforce refuses the request.
	ModeEnforce Mode = "enforce"
	// ModeReport allows the request and records that it would have been
	// refused, so an operator can see what enforcing would break.
	ModeReport Mode = "report"
)

// Valid reports whether m is a mode the gateway runs in.
func (m Mode) Valid() bool { return m == ModeEnforce || m == ModeReport }

const (
	// HTTPSPort is the port an allow entry with port 0 means.
	HTTPSPort = 443
	// maxDenials bounds the denials kept per job; later ones are counted
	// but not kept.
	maxDenials  = 1000
	maxAllow    = 1000
	lookupLimit = 10 * time.Second
	dialTimeout = 30 * time.Second
)

// Allow is one destination a job may reach: an exact host, an IP literal or
// "*.suffix", and a port, where 0 means 443.
type Allow struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Registration is a job's identity and allow list. Sources are the
// addresses or networks the job connects from: its network's subnet for a
// container, its pod's IP for Kubernetes.
type Registration struct {
	Job     string   `json:"job"`
	Sources []string `json:"sources"`
	Allow   []Allow  `json:"allow"`
}

// Denial is one refused request, or in report mode one that would have been.
type Denial struct {
	Time time.Time `json:"time"`
	Host string    `json:"host"`
	// Port is 0 for a DNS lookup.
	Port int `json:"port"`
	// Method is CONNECT, the HTTP method, or DNS.
	Method string `json:"method"`
	// WouldBlock is set in report mode, where the request went through.
	WouldBlock bool `json:"would_block,omitempty"`
	// Reason is empty for a host that is simply not on the list, and says
	// why otherwise: an address range, IPv6, a direct connection.
	Reason string `json:"reason,omitempty"`
}

// Resolver looks names up; *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config configures a Gateway.
type Config struct {
	Mode Mode
	// Pool names the pool in the hint every denial carries; "<pool>" when
	// empty.
	Pool string
	// Resolver and Dial reach the outside; the system's by default. Tests
	// replace both.
	Resolver Resolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Log      *slog.Logger
	Now      func() time.Time
}

// Gateway holds the registered jobs and decides every request.
type Gateway struct {
	cfg Config

	mu   sync.RWMutex
	jobs map[string]*jobState

	tunnelMu sync.Mutex
	tunnels  map[net.Conn]bool
	closed   bool
}

type jobState struct {
	id      string
	sources []netip.Prefix
	allow   []Allow

	mu      sync.Mutex
	denials []Denial
	dropped int
}

// New returns a Gateway. A zero Mode is enforce.
func New(cfg Config) *Gateway {
	if cfg.Mode == "" {
		cfg.Mode = ModeEnforce
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gateway{cfg: cfg, jobs: map[string]*jobState{}, tunnels: map[net.Conn]bool{}}
}

// Mode is the mode the gateway runs in.
func (g *Gateway) Mode() Mode { return g.cfg.Mode }

// Register adds a job, or replaces its sources and allow list and keeps its
// denials. Two jobs cannot share a source.
func (g *Gateway) Register(r Registration) error {
	if r.Job == "" || len(r.Job) > 200 {
		return errors.New("a job id is required")
	}
	if len(r.Sources) == 0 {
		return errors.New("a job needs at least one source address or network")
	}
	if len(r.Allow) > maxAllow {
		return fmt.Errorf("an allow list holds at most %d entries", maxAllow)
	}
	j := &jobState{id: r.Job}
	for _, s := range r.Sources {
		p, err := parseSource(s)
		if err != nil {
			return err
		}
		j.sources = append(j.sources, p)
	}
	for _, a := range r.Allow {
		a, err := normalizeAllow(a)
		if err != nil {
			return err
		}
		j.allow = append(j.allow, a)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, other := range g.jobs {
		if id == r.Job {
			continue
		}
		for _, p := range j.sources {
			for _, q := range other.sources {
				if p.Overlaps(q) {
					return fmt.Errorf("source %s overlaps job %s", p, id)
				}
			}
		}
	}
	if old, ok := g.jobs[r.Job]; ok {
		j.denials, j.dropped = old.denials, old.dropped
	}
	g.jobs[r.Job] = j
	return nil
}

// Unregister forgets a job and its denials; an unknown job is not an error.
func (g *Gateway) Unregister(job string) {
	g.mu.Lock()
	delete(g.jobs, job)
	g.mu.Unlock()
}

// Denials returns the job's denials from index after on, and the index to
// ask for next. ok is false for a job that is not registered.
func (g *Gateway) Denials(job string, after int) (out []Denial, next int, ok bool) {
	g.mu.RLock()
	j := g.jobs[job]
	g.mu.RUnlock()
	if j == nil {
		return nil, after, false
	}
	return j.since(after)
}

func (j *jobState) since(after int) ([]Denial, int, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	after = max(0, min(after, len(j.denials)))
	return slices.Clone(j.denials[after:]), len(j.denials), true
}

func parseSource(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("source %q is not an address or a network", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normalizeAllow(a Allow) (Allow, error) {
	h := normalizeHost(a.Host)
	if h == "" || len(h) > 253 {
		return a, fmt.Errorf("allow entry %q has no usable host", a.Host)
	}
	if rest, ok := strings.CutPrefix(h, "*."); ok {
		if rest == "" || strings.ContainsAny(rest, "*/:") || net.ParseIP(rest) != nil {
			return a, fmt.Errorf("allow entry %q: a wildcard is *.suffix", a.Host)
		}
	} else if strings.ContainsAny(h, "*/") {
		return a, fmt.Errorf("allow entry %q: a wildcard is *.suffix", a.Host)
	}
	if a.Port < 0 || a.Port > 65535 {
		return a, fmt.Errorf("allow entry %q has port %d", a.Host, a.Port)
	}
	if a.Port == 0 {
		a.Port = HTTPSPort
	}
	a.Host = h
	return a, nil
}

// normalizeHost lowercases a host and drops a trailing dot and the brackets
// of an IPv6 literal.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return h
}

// match reports whether the entry covers host:port, and whether it names
// the host exactly rather than by wildcard.
func (a Allow) match(host string, port int) (ok, exact bool) {
	if a.Port != port {
		return false, false
	}
	if suffix, wild := strings.CutPrefix(a.Host, "*"); wild {
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix), false
	}
	return a.Host == host, true
}

// find returns the registered job a source address belongs to, preferring
// the narrowest network.
func (g *Gateway) find(ip netip.Addr) *jobState {
	ip = ip.Unmap()
	g.mu.RLock()
	defer g.mu.RUnlock()
	var best *jobState
	bestBits := -1
	for _, j := range g.jobs {
		for _, p := range j.sources {
			if p.Contains(ip) && p.Bits() > bestBits {
				best, bestBits = j, p.Bits()
			}
		}
	}
	return best
}

// addrOf is the IP part of a network address.
func addrOf(a net.Addr) (netip.Addr, bool) {
	var ap netip.AddrPort
	switch v := a.(type) {
	case *net.TCPAddr:
		ap = v.AddrPort()
	case *net.UDPAddr:
		ap = v.AddrPort()
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.Addr{}, false
		}
	}
	return ap.Addr().Unmap(), ap.Addr().IsValid()
}

// record keeps a denial for the job and logs it.
func (g *Gateway) record(j *jobState, d Denial) {
	d.Time = g.cfg.Now()
	j.mu.Lock()
	if len(j.denials) < maxDenials {
		j.denials = append(j.denials, d)
	} else {
		j.dropped++
	}
	j.mu.Unlock()
	msg := "blocked a network request"
	if d.WouldBlock {
		msg = "would block a network request"
	}
	g.cfg.Log.Info(msg, "job", j.id, "host", d.Host, "port", d.Port, "method", d.Method, "reason", d.Reason)
}

// Line is the sentence a job's log carries for a denial.
func (g *Gateway) Line(d Denial) string { return DenialLine(d, g.cfg.Pool) }

// DenialLine is the log line for a denial. pool may be empty.
func DenialLine(d Denial, pool string) string {
	if pool == "" {
		pool = "<pool>"
	}
	dest := d.Host
	if d.Port != 0 {
		dest = net.JoinHostPort(d.Host, fmt.Sprint(d.Port))
	}
	allow := fmt.Sprintf("A pool admin can allow it with `runs admin pool egress allow %s %s`.", pool, d.Host)
	prefix := "Blocked network request to "
	if d.WouldBlock {
		prefix = "Network request to "
	}
	var why string
	switch {
	case d.Reason == "" && d.WouldBlock:
		why = "would be blocked once egress is enforced: not on this job's allow list."
	case d.Reason == "":
		why = "not on this job's allow list."
	case d.WouldBlock:
		why = "would be blocked once egress is enforced: " + d.Reason + "."
	case d.Method == "DNS":
		// Allowing the host would not help: nothing in the job can connect
		// without the proxy.
		return prefix + dest + ": " + d.Reason + "."
	default:
		why = d.Reason + "."
	}
	return prefix + dest + ": " + why + " " + allow
}

// Why a request was refused, beyond a host that is not on the list.
const (
	reasonRange  = "it resolves to a loopback, private, link-local, carrier-grade NAT or cloud metadata address, which only an exact allow-list entry for the host permits"
	reasonIPv6   = "IPv6 destinations are refused unless the IPv6 address itself is allowed"
	reasonNoIP   = "the name did not resolve to an address that can be used"
	reasonDirect = "this tool looked the name up directly instead of using the HTTPS_PROXY setting, and jobs have no route out except through the proxy"
)

// authorize decides a request for host:port from job j. It returns the
// addresses to dial, or a reason (empty for a host that is simply not on
// the list) when the request is refused; refused is true then.
func (g *Gateway) authorize(ctx context.Context, j *jobState, host string, port int) (addrs []netip.Addr, reason string, refused bool) {
	host = normalizeHost(host)
	matched, exact := false, false
	for _, a := range j.allow {
		if ok, ex := a.match(host, port); ok {
			matched, exact = true, exact || ex
		}
	}
	if !matched {
		return nil, "", true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		switch {
		case isV6(ip) && !exact:
			return nil, reasonIPv6, true
		case restricted(ip) && !exact:
			return nil, reasonRange, true
		}
		return []netip.Addr{ip}, "", false
	}
	found, err := g.resolve(ctx, host)
	if err != nil {
		return nil, reasonNoIP, true
	}
	var v4 []netip.Addr
	sawRestricted, sawV6 := false, false
	for _, ip := range found {
		switch {
		case isV6(ip):
			// A name never unlocks IPv6: only an allowed IPv6 literal does.
			sawV6 = true
		case restricted(ip) && !exact:
			sawRestricted = true
		default:
			v4 = append(v4, ip)
		}
	}
	switch {
	case len(v4) > 0:
		return v4, "", false
	case sawRestricted:
		return nil, reasonRange, true
	case sawV6:
		return nil, reasonIPv6, true
	}
	return nil, reasonNoIP, true
}

func (g *Gateway) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupLimit)
	defer cancel()
	ips, err := g.cfg.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for i := range ips {
		ips[i] = ips[i].Unmap().WithZone("")
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses")
	}
	return ips, nil
}

func isV6(ip netip.Addr) bool { return ip.Is6() }

// Ranges a job must never reach by name or wildcard.
var restrictedNets = mustPrefixes(
	"0.0.0.0/8",      // this network
	"100.64.0.0/10",  // carrier-grade NAT
	"192.0.0.0/24",   // IETF protocol assignments
	"198.18.0.0/15",  // benchmarking
	"240.0.0.0/4",    // reserved
	"169.254.0.0/16", // link-local, and the cloud metadata address 169.254.169.254
	"fd00:ec2::/32",  // AWS IPv6 metadata, fd00:ec2::254
	"64:ff9b::/96",   // NAT64 can embed any IPv4 address
	"2002::/16",      // 6to4 embeds one too
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// restricted reports whether ip is an address no job should reach unless
// its host is allowed by name: this host, the local network, or the cloud
// provider's metadata service.
func restricted(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, p := range restrictedNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// dialAny connects to the first address that answers, on port.
func (g *Gateway) dialAny(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	var errs []error
	for _, ip := range addrs {
		c, err := g.cfg.Dial(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// Close closes every open tunnel.
func (g *Gateway) Close() {
	g.tunnelMu.Lock()
	g.closed = true
	for c := range g.tunnels {
		_ = c.Close()
	}
	g.tunnelMu.Unlock()
}

func (g *Gateway) track(cs ...net.Conn) bool {
	g.tunnelMu.Lock()
	defer g.tunnelMu.Unlock()
	if g.closed {
		return false
	}
	for _, c := range cs {
		g.tunnels[c] = true
	}
	return true
}

func (g *Gateway) untrack(cs ...net.Conn) {
	g.tunnelMu.Lock()
	for _, c := range cs {
		delete(g.tunnels, c)
	}
	g.tunnelMu.Unlock()
}
