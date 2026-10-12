package egressgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Paths the proxy port answers to a job asking about itself, as origin-form
// requests rather than proxied ones. A job reads only its own state: the
// gateway finds it by the address the request came from.
const (
	PathReady   = "/oyzu/egress/ready"
	PathDenials = "/oyzu/egress/denials"
)

// DeniedHeader marks a response as the gateway's refusal, as opposed to
// anything a destination said.
const DeniedHeader = "X-Oyzu-Egress"

type dialKey struct{}

// ProxyHandler is the HTTP proxy: CONNECT for HTTPS and absolute http://
// URLs for plain HTTP. Redirects are not followed here: the client gets them
// as they are and asks the proxy again, so each hop is checked.
func (g *Gateway) ProxyHandler() http.Handler {
	tr := &http.Transport{
		// Only the address the gateway checked is ever dialed.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			t, _ := ctx.Value(dialKey{}).(dialTarget)
			if len(t.addrs) == 0 {
				return nil, errors.New("egressgate: no checked address for this request")
			}
			return g.dialAny(ctx, t.addrs, t.port)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.Host = pr.In.URL.Host
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.cfg.Log.Debug("egress upstream failed", "host", r.Host, "error", err)
			http.Error(w, "The egress gateway could not reach "+r.Host+".", http.StatusBadGateway)
		},
	}
	return &proxy{g: g, rp: rp}
}

type dialTarget struct {
	addrs []netip.Addr
	port  int
}

type proxy struct {
	g  *Gateway
	rp *httputil.ReverseProxy
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	src, ok := addrOf(addrString(r.RemoteAddr))
	var j *jobState
	if ok {
		j = p.g.find(src)
	}
	if r.Method != http.MethodConnect && r.URL.Host == "" {
		p.self(w, r, j)
		return
	}
	if j == nil {
		deny(w, "Blocked network request: this connection does not belong to a job the gateway knows.")
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r, j)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "The proxy forwards absolute http:// URLs and CONNECT.", http.StatusBadRequest)
		return
	}
	host, port, err := splitHostPort(r.URL.Host, 80)
	if err != nil {
		http.Error(w, "The URL needs a valid host and port.", http.StatusBadRequest)
		return
	}
	addrs, ok := p.check(w, r, j, host, port, r.Method)
	if !ok {
		return
	}
	ctx := context.WithValue(r.Context(), dialKey{}, dialTarget{addrs: addrs, port: port})
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

// check applies the allow list; it answers the client and returns false when
// the request is refused. In report mode a refusal is recorded and the
// request goes ahead to wherever the name resolves.
func (p *proxy) check(w http.ResponseWriter, r *http.Request, j *jobState, host string, port int, method string) ([]netip.Addr, bool) {
	g := p.g
	addrs, reason, refused := g.authorize(r.Context(), j, host, port)
	if !refused {
		return addrs, true
	}
	d := Denial{Host: normalizeHost(host), Port: port, Method: method, Reason: reason}
	if g.cfg.Mode == ModeReport {
		d.WouldBlock = true
		g.record(j, d)
		var err error
		if ip, perr := netip.ParseAddr(d.Host); perr == nil {
			addrs = []netip.Addr{ip.Unmap()}
		} else if addrs, err = g.resolve(r.Context(), d.Host); err != nil {
			http.Error(w, "The egress gateway could not resolve "+d.Host+".", http.StatusBadGateway)
			return nil, false
		}
		return addrs, true
	}
	g.record(j, d)
	deny(w, g.Line(d))
	return nil, false
}

func deny(w http.ResponseWriter, line string) {
	w.Header().Set(DeniedHeader, "denied")
	http.Error(w, line, http.StatusForbidden)
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request, j *jobState) {
	host, port, err := splitHostPort(r.Host, 0)
	if err != nil || port == 0 {
		http.Error(w, "CONNECT needs host:port.", http.StatusBadRequest)
		return
	}
	addrs, ok := p.check(w, r, j, host, port, http.MethodConnect)
	if !ok {
		return
	}
	g := p.g
	up, err := g.dialAny(r.Context(), addrs, port)
	if err != nil {
		http.Error(w, "The egress gateway could not reach "+net.JoinHostPort(host, strconv.Itoa(port))+".", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "The connection cannot be taken over.", http.StatusInternalServerError)
		return
	}
	c, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil || !g.track(c, up) {
		c.Close()
		up.Close()
		return
	}
	// A client that sent its first bytes with the CONNECT has them buffered.
	var client io.Reader = c
	if buf.Reader.Buffered() > 0 {
		client = io.MultiReader(io.LimitReader(buf.Reader, int64(buf.Reader.Buffered())), c)
	}
	done := make(chan struct{}, 2)
	pipe := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, client)
	go pipe(c, up)
	go func() {
		<-done
		<-done
		c.Close()
		up.Close()
		g.untrack(c, up)
	}()
}

// self answers a job's questions about its own registration.
func (p *proxy) self(w http.ResponseWriter, r *http.Request, j *jobState) {
	switch r.URL.Path {
	case PathReady:
		if j == nil {
			http.Error(w, "not registered", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case PathDenials:
		if j == nil {
			http.Error(w, "not registered", http.StatusNotFound)
			return
		}
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		out, next, _ := j.since(after)
		reply := DenialsReply{Denials: out, Next: next, Mode: p.g.cfg.Mode, Pool: p.g.cfg.Pool}
		for _, d := range out {
			reply.Lines = append(reply.Lines, p.g.Line(d))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	default:
		http.Error(w, "This is an egress proxy: set HTTPS_PROXY to it.", http.StatusBadRequest)
	}
}

// DenialsReply is what the gateway tells a job about its refused requests.
type DenialsReply struct {
	Denials []Denial `json:"denials"`
	// Lines are the log lines for Denials, in order.
	Lines []string `json:"lines"`
	// Next is the index to pass as after to get only later denials.
	Next int    `json:"next"`
	Mode Mode   `json:"mode"`
	Pool string `json:"pool,omitempty"`
}

type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

// splitHostPort splits host[:port]; def is the port when there is none.
func splitHostPort(hostport string, def int) (string, int, error) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") && def != 0 {
			return normalizeHost(hostport), def, nil
		}
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return "", 0, errors.New("bad port")
	}
	if h == "" {
		return "", 0, errors.New("no host")
	}
	return normalizeHost(h), n, nil
}
