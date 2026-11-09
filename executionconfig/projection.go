package executionconfig

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oyzuai/fleet/runnerclient"
	"software.sslmate.com/src/go-pkcs12"
)

// BundleVars replace a tool's trust store, so they always name system roots plus
// additional anchors. Node's variable instead adds anchors to its own roots.
var BundleVars = []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "CARGO_HTTP_CAINFO"}

// Projection owns files for one execution. Close removes them after all consumers
// exit. Container consumers must bind Dir read-only, never copy it into an image.
type Projection struct {
	Dir      string
	Evidence *runnerclient.ExecutionEvidence
	config   *runnerclient.ExecutionConfig
	java     bool
}

// Prepare writes public trust material under parent. roots is the executor's
// system PEM bundle; extra is the job-only CA when a credential proxy is active.
// No configuration means no files, environment changes or tool invocations.
func Prepare(ctx context.Context, parent string, c *runnerclient.ExecutionConfig, roots, extra []byte) (*Projection, error) {
	if c == nil {
		return nil, nil
	}
	corporate, err := Validate(c)
	if err != nil {
		return nil, err
	}
	p := &Projection{config: c, Evidence: Evidence(c)}
	if p.Evidence == nil {
		return nil, failure(Invalid, "invalid execution evidence identity")
	}
	java, javaRequired := false, false
	declaredTrust := false
	for _, consumer := range c.Consumers {
		for _, f := range consumer.Formats {
			if f.Name == "pem" || f.Name == "node" {
				declaredTrust = true
			}
			if f.Name == "java-pkcs12" {
				java = true
				javaRequired = javaRequired || f.Required || c.Required
			}
		}
	}
	if len(corporate) == 0 && len(extra) == 0 && !java && !declaredTrust {
		return p, nil
	}
	if len(roots) == 0 {
		return nil, failure(ProjectionFailed, "system PEM roots are unavailable on this executor")
	}
	if !x509.NewCertPool().AppendCertsFromPEM(roots) {
		return nil, failure(ProjectionFailed, "system PEM roots contain no certificates")
	}
	if parent != "" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, failure(ProjectionFailed, "could not create the execution directory")
		}
	}
	p.Dir, err = os.MkdirTemp(parent, ".oyzu-trust-")
	if err != nil {
		return nil, failure(ProjectionFailed, "could not create the trust directory")
	}
	complete := false
	defer func() {
		if !complete {
			p.Close()
		}
	}()
	additional := append(append([]byte{}, corporate...), extra...)
	combined := append(append(append([]byte{}, roots...), '\n'), additional...)
	for name, body := range map[string][]byte{"ca.pem": combined, "corporate-ca.pem": corporate, "additional-ca.pem": additional} {
		if err := os.WriteFile(filepath.Join(p.Dir, name), body, 0o444); err != nil {
			return nil, failure(ProjectionFailed, "could not write the trust bundle")
		}
	}
	p.Evidence.Formats = []string{"pem", "node"}
	if java {
		if err := p.writeJava(ctx, combined); err != nil {
			if javaRequired {
				return nil, err
			}
			_ = os.Remove(filepath.Join(p.Dir, "truststore.p12"))
		} else {
			p.java = true
			p.Evidence.Formats = append(p.Evidence.Formats, "java-pkcs12")
		}
	}
	if err := os.Chmod(p.Dir, 0o555); err != nil {
		return nil, failure(ProjectionFailed, "could not protect the trust directory")
	}
	complete = true
	return p, nil
}

// writeJava produces a certificate-only PKCS12 store without a JDK. The
// conventional changeit password protects public certificates, not secrets.
func (p *Projection) writeJava(ctx context.Context, bundle []byte) error {
	var certs []*x509.Certificate
	for len(strings.TrimSpace(string(bundle))) > 0 {
		if ctx.Err() != nil {
			return failure(ProjectionFailed, "Java truststore projection was cancelled")
		}
		block, rest := pem.Decode(bundle)
		if block == nil || block.Type != "CERTIFICATE" {
			return failure(ProjectionFailed, "Java truststore input is not certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return failure(ProjectionFailed, "Java truststore input is not an X.509 certificate")
		}
		certs = append(certs, cert)
		bundle = rest
	}
	body, err := pkcs12.Modern2023.EncodeTrustStore(certs, "changeit")
	if err != nil {
		return failure(ProjectionFailed, "could not encode the Java truststore")
	}
	if err := os.WriteFile(filepath.Join(p.Dir, "truststore.p12"), body, 0o444); err != nil {
		return failure(ProjectionFailed, "could not write the Java truststore")
	}
	return nil
}

// Env overlays the projection on environ. target is Dir for a process or the
// read-only mount's destination for a container.
func (p *Projection) Env(environ []string, target string) []string {
	if p == nil {
		return environ
	}
	set := map[string]string{}
	join := filepath.Join
	if strings.HasPrefix(target, "/") {
		join = path.Join
	}
	if p.Dir != "" {
		for _, name := range BundleVars {
			set[name] = join(target, "ca.pem")
		}
		set["NODE_EXTRA_CA_CERTS"] = join(target, "additional-ca.pem")
		if p.java {
			value := ""
			for _, entry := range environ {
				if strings.HasPrefix(entry, "JAVA_TOOL_OPTIONS=") {
					value = strings.TrimPrefix(entry, "JAVA_TOOL_OPTIONS=")
				}
			}
			set["JAVA_TOOL_OPTIONS"] = strings.TrimSpace(value + ` -Djavax.net.ssl.trustStore="` + join(target, "truststore.p12") + `" -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit`)
		}
	}
	if proxy := p.config.Proxy; proxy != nil {
		set["HTTPS_PROXY"], set["https_proxy"] = proxy.HTTPS, proxy.HTTPS
		set["HTTP_PROXY"], set["http_proxy"] = proxy.HTTP, proxy.HTTP
		set["NO_PROXY"], set["no_proxy"] = strings.Join(proxy.Bypass, ","), strings.Join(proxy.Bypass, ",")
		set["ALL_PROXY"], set["all_proxy"] = "", ""
	}
	out := make([]string, 0, len(environ)+len(set))
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if _, exists := set[name]; !exists {
			out = append(out, entry)
		}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+set[key])
	}
	return out
}

func (p *Projection) Close() {
	if p != nil && p.Dir != "" {
		_ = os.Chmod(p.Dir, 0o700)
		entries, _ := os.ReadDir(p.Dir)
		for _, entry := range entries {
			_ = os.Chmod(filepath.Join(p.Dir, entry.Name()), 0o600)
		}
		_ = os.RemoveAll(p.Dir)
	}
}

// SystemRoots finds the executor's PEM system trust store. Windows executors
// requiring PEM projection must provision SSL_CERT_FILE; platform root stores
// cannot be exported by crypto/x509.
func SystemRoots() []byte {
	paths := []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}
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
