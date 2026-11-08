package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/executionconfig"
	"github.com/oyzuai/fleet/runnerclient"
)

func executionCA(t *testing.T) string {
	t.Helper()
	p := &egressProxy{hosts: map[string]bool{"example.com": true}}
	if err := p.makeCA(); err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw}))
}

func reportTrust() {
	report := map[string]any{}
	for _, name := range append(append([]string{}, caBundleVars...), "NODE_EXTRA_CA_CERTS") {
		path := os.Getenv(name)
		body, err := os.ReadFile(path)
		if err != nil {
			os.Exit(5)
		}
		report[name] = path
		report[name+"_count"] = strings.Count(string(body), "-----BEGIN CERTIFICATE-----")
	}
	raw, _ := json.Marshal(report)
	if err := os.WriteFile(os.Getenv("FAKE_TRUST_REPORT"), raw, 0o600); err != nil {
		os.Exit(6)
	}
}

func TestRunProjectsCorporateAndJobCA(t *testing.T) {
	corporate := executionCA(t)
	canonical, digest, err := executionconfig.CanonicalBundle(corporate)
	if err != nil {
		t.Fatal(err)
	}
	job := buildJob("build", "oyzu", "build")
	job.ExecutionConfig = &runnerclient.ExecutionConfig{Version: 1, Revision: "revision-1", Required: true, Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}}}
	runs, cfg, _ := setup(t, job)
	runs.egress = `{"grants":[{"host":"example.com","authorization":"Bearer job-test","expires_at":"2030-01-01T00:00:00Z"}]}`
	roots := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(roots, []byte(executionCA(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", roots)
	reportFile := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("FAKE_TRUST_REPORT", reportFile)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runs.finished == nil || runs.finished.State != "succeeded" {
		t.Fatalf("outcome: %+v", runs.finished)
	}
	if runs.finished.Execution == nil || runs.finished.Execution.Revision != "revision-1" || len(runs.finished.Execution.BundleDigests) != 1 || runs.finished.Execution.BundleDigests[0] != digest {
		t.Fatal("missing execution evidence")
	}
	raw, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, caBundleVars...), "NODE_EXTRA_CA_CERTS") {
		want := float64(3)
		if name == "NODE_EXTRA_CA_CERTS" {
			want = 2
		}
		if report[name+"_count"] != want {
			t.Fatalf("%s has %v certificates, want %v", name, report[name+"_count"], want)
		}
		if _, err := os.Stat(report[name].(string)); !os.IsNotExist(err) {
			t.Fatalf("%s was not cleaned up", name)
		}
	}
	files, err := os.ReadDir(trustParent(cfg.WorkDir))
	if err != nil || len(files) != 0 {
		t.Fatal("execution files survived completion", err)
	}
	encoded, _ := json.Marshal(runs.finished.Execution)
	if strings.Contains(string(encoded), "CERTIFICATE") || strings.Contains(string(encoded), "job-test") {
		t.Fatal("launch material leaked into evidence")
	}
}

func TestRunFailsBeforeCheckoutWhenRequiredTrustIsMissing(t *testing.T) {
	job := buildJob("build", "oyzu", "build")
	job.ExecutionConfig = &runnerclient.ExecutionConfig{Version: 1, Revision: "revision-1", Bundles: []runnerclient.ExecutionCABundle{{Required: true}}}
	runs, cfg, gitLog := setup(t, job)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runs.finished == nil || runs.finished.ReasonCode != executionconfig.Unavailable {
		t.Fatalf("outcome: %+v", runs.finished)
	}
	if _, err := os.Stat(gitLog); !os.IsNotExist(err) {
		t.Fatal("git ran without required trust")
	}
}

func TestRunGatewayWithCorporateBundleAndNoGrants(t *testing.T) {
	canonical, digest, err := executionconfig.CanonicalBundle(executionCA(t))
	if err != nil {
		t.Fatal(err)
	}
	job := buildJob("build", "oyzu", "build")
	job.ExecutionConfig = &runnerclient.ExecutionConfig{Version: 1, Revision: "gateway-bundle", Required: true,
		Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}}}
	runs, cfg, _ := setup(t, job)
	runs.egress = `{"grants":[]}`
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			t.Error("fake build unexpectedly requested a gateway tunnel")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case egressgate.PathReady:
			// Model a job already registered by the manager.
			w.WriteHeader(http.StatusNoContent)
		case egressgate.PathDenials:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(egressgate.DenialsReply{})
		default:
			t.Errorf("unexpected gateway request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer gateway.Close()
	cfg.EgressGateway = gateway.URL
	roots := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(roots, []byte(executionCA(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", roots)
	reportFile := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("FAKE_TRUST_REPORT", reportFile)
	// Call Run directly: a nil job CA must neither panic nor fail the job.
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runs.finished == nil || runs.finished.State != "succeeded" || runs.finished.ExitCode == nil || *runs.finished.ExitCode != 0 {
		t.Fatalf("outcome: %+v", runs.finished)
	}
	if evidence := runs.finished.Execution; evidence == nil || evidence.Revision != "gateway-bundle" || len(evidence.BundleDigests) != 1 || evidence.BundleDigests[0] != digest {
		t.Fatalf("execution evidence: %+v", evidence)
	}
	raw, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, caBundleVars...), "NODE_EXTRA_CA_CERTS") {
		want := float64(2) // System and corporate roots, with no job CA.
		if name == "NODE_EXTRA_CA_CERTS" {
			want = 1
		}
		if report[name+"_count"] != want {
			t.Fatalf("%s has %v certificates, want %v", name, report[name+"_count"], want)
		}
		if _, err := os.Stat(report[name].(string)); !os.IsNotExist(err) {
			t.Fatalf("%s was not cleaned up", name)
		}
	}
	files, err := os.ReadDir(trustParent(cfg.WorkDir))
	if err != nil || len(files) != 0 {
		t.Fatal("execution files survived completion", err)
	}
}

func TestCorporateBypassStaysUpstreamOfCredentialProxy(t *testing.T) {
	for _, bypass := range []string{"example.com,other.test", "*"} {
		t.Run(bypass, func(t *testing.T) {
			u := newUpstreams(t)
			corporateProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("bypassed traffic reached the corporate proxy")
				w.WriteHeader(http.StatusBadGateway)
			}))
			defer corporateProxy.Close()
			config := &runnerclient.ExecutionConfig{Version: 1, Revision: "upstream-bypass",
				Proxy: &runnerclient.ExecutionProxy{HTTPS: corporateProxy.URL, HTTP: corporateProxy.URL, Bypass: strings.Split(bypass, ",")}}
			projection, err := executionconfig.Prepare(context.Background(), t.TempDir(), config, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer projection.Close()
			first := grant("example.com", "Bearer bypass-test", time.Now().Add(time.Hour))
			p, err := startEgress(first, nil, func(...string) {}, slog.New(slog.NewTextHandler(io.Discard, nil)), "",
				egressExecution{config: config, workDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer p.stop()
			// Substitute only test DNS and the fixture's TLS root; retain the
			// configured upstream proxy/bypass selection for requests and tunnels.
			transport := p.upstream.(*http.Transport)
			transport.DialContext = u.dial
			transport.TLSClientConfig.RootCAs.AddCert(u.tls.Certificate())
			env := p.env(projection.Env([]string{"NO_PROXY=ambient.example", "no_proxy=*"}, projection.Dir))
			values := map[string][]string{}
			for _, entry := range env {
				key, value, _ := strings.Cut(entry, "=")
				values[key] = append(values[key], value)
			}
			for _, name := range []string{"NO_PROXY", "no_proxy"} {
				if len(values[name]) != 1 || values[name][0] != "localhost,127.0.0.1,::1" {
					t.Fatalf("%s = %v", name, values[name])
				}
			}
			for _, name := range proxyVars {
				if len(values[name]) != 1 || values[name][0] != p.url {
					t.Fatalf("%s does not name the credential proxy", name)
				}
			}
			get(t, buildClient(t, p), "https://example.com/private", "")
			if u.last().Get("Authorization") != "Bearer bypass-test" {
				t.Fatal("bypassed host did not receive its job credential")
			}
			// Opaque tunnels follow the same upstream bypass list.
			conn, reader, status := connect(t, p, "other.test:443", "Basic "+basicAuth(egressProxyUser, p.secret))
			if status != http.StatusOK {
				t.Fatalf("CONNECT = %d", status)
			}
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "bypass\n"); err != nil {
				t.Fatal(err)
			}
			if line, err := reader.ReadString('\n'); err != nil || line != "bypass\n" {
				t.Fatalf("tunnel echo = %q, %v", line, err)
			}
		})
	}
}

func TestCredentialProxyUsesCorporateTrustAndProxy(t *testing.T) {
	corporate := &egressProxy{hosts: map[string]bool{"internal.example": true}, certs: map[string]*tls.Certificate{}}
	if err := corporate.makeCA(); err != nil {
		t.Fatal(err)
	}
	cert, err := corporate.leaf("internal.example")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 1)
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "trusted")
	}))
	internal.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	internal.StartTLS()
	defer internal.Close()
	connections := make(chan string, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connections <- r.Host
		if r.Method != http.MethodConnect || r.Host != "internal.example:443" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		up, err := net.Dial("tcp", internal.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = buffered.Flush()
		go func() { _, _ = io.Copy(up, buffered); up.Close() }()
		_, _ = io.Copy(client, up)
		client.Close()
	}))
	defer proxy.Close()
	canonical, digest, err := executionconfig.CanonicalBundle(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: corporate.ca.Raw})))
	if err != nil {
		t.Fatal(err)
	}
	config := &runnerclient.ExecutionConfig{Version: 1, Revision: "corporate-proxy", Required: true,
		Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}},
		Proxy:   &runnerclient.ExecutionProxy{HTTPS: proxy.URL, Required: true}}
	roots := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(roots, []byte(executionCA(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", roots)
	first := grant("internal.example", "Bearer job-only", time.Now().Add(time.Hour))
	p, err := startEgress(first, func(context.Context) (runnerclient.Egress, error) { return first, nil }, func(...string) {},
		slog.New(slog.NewTextHandler(io.Discard, nil)), "", egressExecution{config: config, workDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	client := buildClient(t, p)
	resp, err := client.Get("https://internal.example")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "trusted" {
		t.Fatalf("corporate upstream = %d %s", resp.StatusCode, body)
	}
	if <-connections != "internal.example:443" || <-seen != "Bearer job-only" {
		t.Fatal("credential proxy did not chain through corporate TLS and proxy")
	}
	proxy.Close()
	client.Transport.(*http.Transport).CloseIdleConnections()
	p.upstream.(*http.Transport).CloseIdleConnections()
	resp, err = client.Get("https://internal.example")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatal("corporate proxy failure did not fail closed", resp.StatusCode)
	}
}

// An anonymous source still needs the projected corporate trust, while main's
// no-App checkout must not manufacture an empty-token Authorization header.
func TestAnonymousCheckoutRetainsProjectedCorporateTrust(t *testing.T) {
	canonical, digest, err := executionconfig.CanonicalBundle(executionCA(t))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := executionconfig.Prepare(context.Background(), t.TempDir(), &runnerclient.ExecutionConfig{
		Version: 1, Revision: "anonymous-checkout", Required: true,
		Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}},
	}, []byte(canonical), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer projection.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "git-trust.json")
	t.Setenv("FAKE_TOOLS", "1")
	t.Setenv("FAKE_GIT_LOG", filepath.Join(t.TempDir(), "git.jsonl"))
	t.Setenv("FAKE_GIT_TRUST_REPORT", report)
	cfg := Config{Git: binary, WorkDir: t.TempDir(), GitURL: "https://github.example", trust: projection}
	if err := checkout(context.Background(), cfg, "", buildJob("build", "oyzu", "build")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]string
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	if actual["count"] != "0" || actual["header"] != "" {
		t.Fatalf("anonymous auth config: %+v", actual)
	}
	if actual["trust"] != filepath.Join(projection.Dir, "ca.pem") {
		t.Fatalf("projected trust missing: %+v", actual)
	}
}
