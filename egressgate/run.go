package egressgate

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Default ports of the gateway process.
const (
	DefaultProxyPort   = 3128
	DefaultControlPort = 9091
	DefaultDNSPort     = 53
	// TokenEnv names the variable a gateway reads its control token from.
	TokenEnv = "OYZU_GATEWAY_TOKEN"
)

// Options configures a gateway process.
type Options struct {
	Mode Mode
	Pool string
	// ProxyAddr, DNSAddr and ControlAddr are listen addresses; an empty
	// DNSAddr runs no sinkhole.
	ProxyAddr, DNSAddr, ControlAddr string
	// Token is the control API's bearer token. It is required unless the
	// control address is loopback.
	Token string
	Log   *slog.Logger
}

// Run serves the gateway until ctx is done or a listener fails.
func Run(ctx context.Context, o Options) error {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if !o.Mode.Valid() {
		return fmt.Errorf("egress mode %q: use enforce or report", o.Mode)
	}
	if o.ProxyAddr == "" || o.ControlAddr == "" {
		return errors.New("the gateway needs a proxy and a control address")
	}
	if o.Token == "" && !loopbackAddr(o.ControlAddr) {
		return errors.New("a control listener that is not loopback needs a token")
	}
	g := New(Config{Mode: o.Mode, Pool: o.Pool, Log: o.Log})
	defer g.Close()
	proxyLn, err := net.Listen("tcp", o.ProxyAddr)
	if err != nil {
		return err
	}
	ctlLn, err := net.Listen("tcp", o.ControlAddr)
	if err != nil {
		proxyLn.Close()
		return err
	}
	var dnsPC net.PacketConn
	if o.DNSAddr != "" {
		if dnsPC, err = net.ListenPacket("udp", o.DNSAddr); err != nil {
			proxyLn.Close()
			ctlLn.Close()
			return fmt.Errorf("DNS sinkhole: %w", err)
		}
	}
	o.Log.Info("egress gateway started", "mode", o.Mode, "proxy", proxyLn.Addr().String(), "control", ctlLn.Addr().String())
	proxySrv := &http.Server{Handler: g.ProxyHandler(), ReadHeaderTimeout: 30 * time.Second}
	ctlSrv := &http.Server{Handler: g.ControlHandler(o.Token), ReadHeaderTimeout: 30 * time.Second}
	errc := make(chan error, 3)
	var wg sync.WaitGroup
	serve := func(f func() error) {
		wg.Add(1)
		go func() { defer wg.Done(); errc <- f() }()
	}
	serve(func() error { return ignoreClosed(proxySrv.Serve(proxyLn)) })
	serve(func() error { return ignoreClosed(ctlSrv.Serve(ctlLn)) })
	if dnsPC != nil {
		serve(func() error { return g.ServeDNS(dnsPC) })
	}
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = proxySrv.Close()
	_ = ctlSrv.Close()
	if dnsPC != nil {
		_ = dnsPC.Close()
	}
	wg.Wait()
	return err
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func loopbackAddr(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

const gatewayUsage = `usage:
  oyzu-executor gateway [--mode enforce|report] [--pool NAME] [--proxy :3128] [--dns :53]
                        [--control 127.0.0.1:9091] [--control-token-env NAME]
  oyzu-executor gateway probe --proxy URL [--deny host:port] [--direct host:port,...]
`

// Command runs `oyzu-executor gateway`, args without the word gateway. The
// pool manager starts it in the executor image: as the gateway itself, or
// with probe as the startup self-test's job.
func Command(args []string, log *slog.Logger) error {
	if len(args) > 0 && args[0] == "probe" {
		return probeCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "probe-readiness" {
		return readinessProbeCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "readiness-canary" {
		return canaryCommand(args[1:])
	}
	fs := flag.NewFlagSet("oyzu-executor gateway", flag.ContinueOnError)
	mode := fs.String("mode", string(ModeEnforce), "enforce, or report to log what enforcing would block and allow it")
	pool := fs.String("pool", "", "the pool's name, for the hint in each denial")
	proxyAddr := fs.String("proxy", fmt.Sprintf(":%d", DefaultProxyPort), "the proxy listen address")
	dnsAddr := fs.String("dns", fmt.Sprintf(":%d", DefaultDNSPort), "the DNS sinkhole listen address; empty for none")
	control := fs.String("control", fmt.Sprintf("127.0.0.1:%d", DefaultControlPort), "the control API listen address")
	controlIF := fs.String("control-interface", "", "bind the control API only to this management interface")
	tokenEnv := fs.String("control-token-env", TokenEnv, "the variable holding the control token")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, gatewayUsage)
	}
	ctx, stop := notifyContext()
	defer stop()
	controlAddress, err := controlInterface(*control, *controlIF)
	if err != nil {
		return err
	}
	return Run(ctx, Options{
		Mode: Mode(*mode), Pool: *pool, ProxyAddr: *proxyAddr, DNSAddr: *dnsAddr, ControlAddr: controlAddress,
		Token: os.Getenv(*tokenEnv), Log: log,
	})
}

func notifyContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
