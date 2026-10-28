package executionconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
	"software.sslmate.com/src/go-pkcs12"
)

func testCA(t *testing.T, name string) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

func testConfig(t *testing.T) *runnerclient.ExecutionConfig {
	t.Helper()
	raw, _, _ := testCA(t, "corporate")
	canonical, digest, err := CanonicalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &runnerclient.ExecutionConfig{Version: 1, Revision: "revision-1", Required: true, Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}}}
}

func TestBundleValidation(t *testing.T) {
	c := testConfig(t)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")}))
	for _, raw := range []string{"", "junk", "junk\n" + c.Bundles[0].PEM, c.Bundles[0].PEM + "junk", c.Bundles[0].PEM + key, "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n" + c.Bundles[0].PEM, "-----BEGIN CERTIFICATE-----\nbroken\n" + c.Bundles[0].PEM} {
		if _, _, err := CanonicalBundle(raw); err == nil {
			t.Fatalf("accepted malformed bundle")
		}
	}
	canonical, digest, err := CanonicalBundle("\n" + c.Bundles[0].PEM + "\n")
	if err != nil || canonical != c.Bundles[0].PEM || digest != c.Bundles[0].Digest {
		t.Fatal("canonicalization changed certificate identity", err)
	}
	c.Bundles[0].Digest = strings.Repeat("0", 64)
	if _, err := Validate(c); Reason(err) != Invalid {
		t.Fatal("digest mismatch accepted", err)
	}
}

func TestProxyValidation(t *testing.T) {
	for _, endpoint := range []string{"http://user:secret@proxy.example", "https://proxy.example/?token=secret", "socks5://proxy.example", "http://proxy.example/path", "http://"} {
		c := &runnerclient.ExecutionConfig{Version: 1, Revision: "r1", Proxy: &runnerclient.ExecutionProxy{HTTPS: endpoint}}
		if _, err := Validate(c); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("proxy validation or redaction failed", err)
		}
	}
	c := &runnerclient.ExecutionConfig{Version: 1, Revision: "r1", Proxy: &runnerclient.ExecutionProxy{HTTPS: "http://proxy.example:3128", CredentialRef: "connector:1"}}
	if _, err := Validate(c); Reason(err) != ProxyUnsupported {
		t.Fatal("unsupported credentials accepted", err)
	}
}

func TestNoConfigurationIsUnchanged(t *testing.T) {
	parent := t.TempDir()
	p, err := Prepare(context.Background(), parent, nil, nil, nil)
	if err != nil || p != nil {
		t.Fatal(p, err)
	}
	env := []string{"PATH=tools", "HTTPS_PROXY=http://existing", "SSL_CERT_FILE=existing"}
	if !reflect.DeepEqual(p.Env(env, ""), env) {
		t.Fatal("unconfigured environment changed")
	}
	p.Close()
	files, err := os.ReadDir(parent)
	if err != nil || len(files) != 0 {
		t.Fatal("unconfigured execution created files", err)
	}
}

func TestProjectionAndCleanup(t *testing.T) {
	c := testConfig(t)
	roots, _, _ := testCA(t, "system")
	job, _, _ := testCA(t, "job")
	c.Proxy = &runnerclient.ExecutionProxy{HTTPS: "https://proxy.example:443", HTTP: "http://proxy.example:80", Bypass: []string{"internal.example", "10.0.0.0/8"}}
	p, err := Prepare(context.Background(), t.TempDir(), c, []byte(roots), []byte(job))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for name, want := range map[string]string{"ca.pem": roots + "\n" + c.Bundles[0].PEM + job, "corporate-ca.pem": c.Bundles[0].PEM, "additional-ca.pem": c.Bundles[0].PEM + job} {
		path := filepath.Join(p.Dir, name)
		body, err := os.ReadFile(path)
		if err != nil || string(body) != want {
			t.Fatalf("%s does not contain the expected anchors: %v", name, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o222 != 0 {
			t.Fatal("writable trust file")
		}
	}
	env := p.Env([]string{"HTTPS_PROXY=http://wrong", "ALL_PROXY=http://wrong", "PATH=tools"}, "/run/oyzu/trust")
	joined := strings.Join(env, "\n")
	for _, name := range BundleVars {
		if !strings.Contains(joined, name+"=/run/oyzu/trust/ca.pem") {
			t.Fatalf("missing %s", name)
		}
	}
	for _, forbidden := range []string{"http://wrong", "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY", "insecure"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unexpected environment value %s", forbidden)
		}
	}
	record, err := json.Marshal(p.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"CERTIFICATE", "https://", "http://", "connector", "internal.example"} {
		if strings.Contains(string(record), forbidden) {
			t.Fatal("execution evidence contains launch material")
		}
	}
	if !strings.Contains(string(record), c.Bundles[0].Digest) || !strings.Contains(string(record), "proxy.example") {
		t.Fatal("missing execution identity")
	}
	dir := p.Dir
	p.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("trust directory survived cleanup", err)
	}
}

func TestRequiredFailures(t *testing.T) {
	c := testConfig(t)
	c.Bundles[0].PEM = ""
	if _, err := Prepare(context.Background(), t.TempDir(), c, nil, nil); Reason(err) != Unavailable {
		t.Fatal(err)
	}
	c = testConfig(t)
	c.Consumers = []runnerclient.TrustConsumer{{Name: "scanner", Formats: []runnerclient.TrustFormat{{Name: "unknown", Required: true}}}}
	if _, err := Prepare(context.Background(), t.TempDir(), c, nil, nil); Reason(err) != Unsupported {
		t.Fatal(err)
	}
	c = testConfig(t)
	if _, err := Prepare(context.Background(), t.TempDir(), c, nil, nil); Reason(err) != ProjectionFailed {
		t.Fatal(err)
	}
}

func TestJavaPKCS12(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	c := testConfig(t)
	c.Consumers = []runnerclient.TrustConsumer{{Name: "java-scanner", Formats: []runnerclient.TrustFormat{{Name: "java-pkcs12", Required: true}}}}
	roots, _, _ := testCA(t, "system")
	job, _, _ := testCA(t, "job")
	p, err := Prepare(context.Background(), t.TempDir(), c, []byte(roots), []byte(job))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	body, err := os.ReadFile(filepath.Join(p.Dir, "truststore.p12"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pkcs12.DecodeTrustStore(body, "changeit")
	if err != nil || len(certs) != 3 {
		t.Fatalf("PKCS12 certificates = %d, error = %v", len(certs), err)
	}
	for i, name := range []string{"system", "corporate", "job"} {
		if certs[i].Subject.CommonName != name {
			t.Fatalf("certificate %d = %q, want %q", i, certs[i].Subject.CommonName, name)
		}
	}
	env := strings.Join(p.Env([]string{"JAVA_TOOL_OPTIONS=-Xmx256m"}, p.Dir), "\n")
	if !strings.Contains(env, "JAVA_TOOL_OPTIONS=-Xmx256m") || !strings.Contains(env, "trustStoreType=PKCS12") || !strings.Contains(env, "trustStorePassword=changeit") {
		t.Fatal("Java options missing")
	}
}

func TestProxyBypass(t *testing.T) {
	for _, tc := range []struct {
		target, entry string
		want          bool
	}{
		{"https://internal.example", "internal.example", true},
		{"https://a.internal.example", ".internal.example", true},
		{"https://internal.example", ".internal.example", false},
		{"https://other.example", "internal.example", false},
		{"https://10.1.2.3", "10.0.0.0/8", true},
		{"https://10.1.2.3:8443", "10.1.2.3:443", false},
		{"https://[::1]", "::1", true},
	} {
		u, _ := url.Parse(tc.target)
		if got := bypassed(u, []string{tc.entry}); got != tc.want {
			t.Errorf("%s bypass %s = %v", tc.target, tc.entry, got)
		}
	}
}

func TestCorporateTLSBehindProxy(t *testing.T) {
	raw, ca, key := testCA(t, "corporate")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "internal.example"}, DNSNames: []string{"internal.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "trusted") }))
	internal.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	internal.StartTLS()
	defer internal.Close()
	connections := make(chan string, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connections <- r.Host
		if r.Method != http.MethodConnect {
			t.Error("expected CONNECT")
			w.WriteHeader(400)
			return
		}
		up, err := net.Dial("tcp", internal.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
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
	canonical, digest, _ := CanonicalBundle(raw)
	c := &runnerclient.ExecutionConfig{Version: 1, Revision: "r1", Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest}}, Proxy: &runnerclient.ExecutionProxy{HTTPS: proxy.URL, Required: true}}
	transport, err := Transport(c)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("https://internal.example")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "trusted" || <-connections != "internal.example:443" {
		t.Fatal("did not use corporate trust and proxy")
	}
	conn, err := TunnelDialer(transport)(context.Background(), "tcp", "internal.example:443")
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{RootCAs: transport.TLSClientConfig.RootCAs, ServerName: "internal.example"})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Close()
	if <-connections != "internal.example:443" {
		t.Fatal("opaque tunnel bypassed proxy")
	}
	without := *c
	without.Bundles = nil
	negative, err := Transport(&without)
	if err != nil {
		t.Fatal(err)
	}
	defer negative.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: negative, Timeout: 5 * time.Second}).Get("https://internal.example"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted corporate TLS accepted")
	}
}
