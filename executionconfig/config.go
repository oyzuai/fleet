// Package executionconfig validates and projects job-scoped trust and proxy
// configuration for executors. It has no dependency on platform models.
package executionconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/url"
	"regexp"
	"strings"

	"github.com/oyzuai/fleet/runnerclient"
)

const (
	Invalid          = "EXECUTION_CONFIG_INVALID"
	Unavailable      = "TRUST_BUNDLE_UNAVAILABLE"
	Unsupported      = "TRUST_FORMAT_UNSUPPORTED"
	ProjectionFailed = "TRUST_PROJECTION_FAILED"
	ProxyUnsupported = "PROXY_CONFIG_UNSUPPORTED"
)

// Error is a sanitized launch failure; it never includes configuration bodies.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func failure(code, message string) error { return &Error{Code: code, Message: message} }

// Reason returns the stable reason code for a projection failure.
func Reason(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ProjectionFailed
}

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

// CanonicalBundle accepts only PEM X.509 CA certificates. It rejects skipped
// junk, keys and PEM headers, and returns canonical PEM and its SHA-256 digest.
func CanonicalBundle(raw string) (string, string, error) {
	if len(raw) > 4<<20 {
		return "", "", failure(Invalid, "CA bundle exceeds the size limit")
	}
	rest := []byte(raw)
	var out []byte
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return "", "", failure(Invalid, "CA bundle contains non-certificate data")
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return "", "", failure(Invalid, "CA bundle contains invalid PEM")
		}
		end += len("-----END CERTIFICATE-----")
		if bytes.Count(rest[:end], []byte("-----BEGIN ")) != 1 {
			return "", "", failure(Invalid, "CA bundle contains malformed certificate boundaries")
		}
		block, skipped := pem.Decode(rest[:end])
		tail := rest[end:]
		if block == nil || len(bytes.TrimSpace(skipped)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", "", failure(Invalid, "CA bundle contains invalid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return "", "", failure(Invalid, "CA bundle must contain X.509 CA certificates")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		rest = tail
	}
	if len(out) == 0 {
		return "", "", failure(Unavailable, "CA bundle is empty")
	}
	digest := sha256.Sum256(out)
	return string(out), hex.EncodeToString(digest[:]), nil
}

// Validate checks launch inputs without creating files or making connections.
func Validate(c *runnerclient.ExecutionConfig) ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	if c.Version != 1 || !identity.MatchString(c.Revision) {
		return nil, failure(Invalid, "unsupported version or invalid configuration revision")
	}
	var corporate []byte
	for _, b := range c.Bundles {
		if b.PEM == "" && !b.Required && !c.Required {
			continue
		}
		canonical, digest, err := CanonicalBundle(b.PEM)
		if err != nil {
			return nil, err
		}
		if digest != b.Digest {
			return nil, failure(Invalid, "CA bundle digest does not match canonical PEM")
		}
		corporate = append(corporate, canonical...)
	}
	if p := c.Proxy; p != nil {
		for _, raw := range []string{p.HTTPS, p.HTTP} {
			if raw == "" {
				continue
			}
			if _, err := proxyURL(raw); err != nil {
				return nil, err
			}
		}
		if (p.Required || c.Required) && p.HTTPS == "" && p.HTTP == "" {
			return nil, failure(Invalid, "required proxy has no endpoint")
		}
		if p.CredentialRef != "" {
			return nil, failure(ProxyUnsupported, "proxy credential references need a supported credential adapter")
		}
		for _, bypass := range p.Bypass {
			if !validBypass(bypass) {
				return nil, failure(Invalid, "invalid proxy bypass entry")
			}
		}
	}
	for _, consumer := range c.Consumers {
		for _, f := range consumer.Formats {
			switch f.Name {
			case "pem", "node", "java-pkcs12":
			default:
				if f.Required || c.Required {
					return nil, failure(Unsupported, "a required trust format is unsupported")
				}
			}
		}
	}
	return corporate, nil
}

func proxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, failure(Invalid, "proxy must be an HTTP(S) endpoint without userinfo, path, query or fragment")
	}
	return u, nil
}

// Evidence validates identities independently of projection, so an unavailable
// required bundle or unsupported format still has a secret-free failure record.
func Evidence(c *runnerclient.ExecutionConfig) *runnerclient.ExecutionEvidence {
	if c == nil {
		return nil
	}
	if !identity.MatchString(c.Revision) {
		return nil
	}
	e := &runnerclient.ExecutionEvidence{Revision: c.Revision}
	for _, b := range c.Bundles {
		digest, err := hex.DecodeString(b.Digest)
		if err != nil || len(digest) != sha256.Size || b.Digest != strings.ToLower(b.Digest) {
			return nil
		}
		e.BundleDigests = append(e.BundleDigests, b.Digest)
	}
	if c.Proxy != nil {
		for _, raw := range []string{c.Proxy.HTTPS, c.Proxy.HTTP} {
			if raw != "" {
				u, err := proxyURL(raw)
				if err != nil {
					return nil
				}
				e.ProxyHosts = append(e.ProxyHosts, u.Hostname())
			}
		}
	}
	return e
}
