// Package readiness defines the self-contained runner readiness wire types.
// Measurements are assertions by an enrolled manager, not host attestation.
package readiness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

const Capability = "network-egress"
const Suite = "fleet-egress-baseline"
const MaxChecks = 16

// Boundary identifies the actual manager-controlled allocation template. The
// host and gateway are private opaque identities, never public topology.
type Boundary struct {
	Driver        string `json:"driver"`
	Host          string `json:"host"`
	Node          string `json:"node,omitempty"`
	Image         string `json:"image"`
	Runtime       string `json:"runtime"`
	Network       string `json:"network"`
	Gateway       string `json:"gateway"`
	Mode          string `json:"mode"`
	IPv6          bool   `json:"ipv6"`
	ExtraNetworks bool   `json:"extra_networks"`
}

func (b Boundary) Fingerprint() string {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (b Boundary) Valid() bool {
	for _, s := range []string{b.Driver, b.Host, b.Node, b.Image, b.Runtime, b.Network, b.Gateway} {
		if len(s) > 256 || strings.ContainsAny(s, "\r\n\x00") {
			return false
		}
	}
	if b.Mode != "enforce" && b.Mode != "report" && b.Mode != "open" {
		return false
	}
	if b.Driver == "container" || b.Driver == "kubernetes" {
		return b.Host != "" && b.Image != "" && b.Runtime != "" && b.Network != "" &&
			(b.Mode == "open" || b.Gateway != "") && (b.Driver != "kubernetes" || b.Node != "")
	}
	return b.Driver == "process" || b.Driver == "vm"
}

// Descriptor is fixed infrastructure wiring selected by the server, never a
// customer-supplied URL, command, image or credential.
type Descriptor struct {
	URL        string `json:"url"`
	DNSAddress string `json:"dns_address"`
	DNSName    string `json:"dns_name"`
}

func (d Descriptor) Validate() error {
	u, err := url.Parse(d.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("readiness: invalid diagnostic origin")
	}
	h, _, dnsErr := net.SplitHostPort(d.DNSAddress)
	if dnsErr != nil || net.ParseIP(h) == nil || net.ParseIP(u.Hostname()) == nil {
		return errors.New("readiness: diagnostic controls require literal IP addresses")
	}
	if len(d.URL) > 512 || len(d.DNSAddress) > 256 || len(d.DNSName) > 253 || d.DNSName == "" || strings.ContainsAny(d.DNSName, " /\r\n\x00") {
		return errors.New("readiness: invalid diagnostic descriptor")
	}
	return nil
}

type Session struct {
	ID      string `json:"session"`
	Enabled bool   `json:"enabled"`
}

type Challenge struct {
	ID          string     `json:"challenge"`
	Session     string     `json:"session"`
	Generation  int64      `json:"generation"`
	Fingerprint string     `json:"fingerprint"`
	Suite       string     `json:"suite"`
	Nonce       string     `json:"nonce"`
	Descriptor  Descriptor `json:"descriptor"`
	Dispatched  time.Time  `json:"dispatched_at"`
	Deadline    time.Time  `json:"deadline_at"`
}

type Subcheck struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

type Result struct {
	Challenge   string     `json:"challenge"`
	Session     string     `json:"session"`
	Generation  int64      `json:"generation"`
	Fingerprint string     `json:"fingerprint"`
	Suite       string     `json:"suite"`
	Outcome     string     `json:"outcome"`
	Checks      []Subcheck `json:"checks"`
}

var requiredChecks = []string{"allowed-path", "control-reachability", "proxy-refusal", "direct-egress", "dns-confinement", "control-isolation", "cleanup"}

func CheckNames() []string { return append([]string{}, requiredChecks...) }

func (r Result) Validate() error {
	if r.Suite != Suite || r.Challenge == "" || r.Session == "" || r.Generation < 1 || len(r.Fingerprint) != 64 || len(r.Checks) < 1 || len(r.Checks) > MaxChecks {
		return errors.New("readiness: invalid result binding")
	}
	seen := map[string]bool{}
	failed, incomplete := false, false
	for _, c := range r.Checks {
		known := false
		for _, name := range requiredChecks {
			known = known || c.Name == name
		}
		if !known || seen[c.Name] || len(c.Reason) > 128 || strings.ContainsAny(c.Reason, "\r\n\x00") {
			return errors.New("readiness: invalid subcheck")
		}
		seen[c.Name] = true
		switch c.Outcome {
		case "passed":
		case "failed":
			failed = true
		case "inconclusive":
			incomplete = true
		default:
			return errors.New("readiness: invalid outcome")
		}
	}
	for _, name := range requiredChecks {
		incomplete = incomplete || !seen[name]
	}
	want := "passed"
	if incomplete {
		want = "inconclusive"
	}
	if failed {
		want = "failed"
	}
	if r.Outcome != want {
		return errors.New("readiness: inconsistent aggregate outcome")
	}
	return nil
}

// Binding is server-selected assignment context, not a job capability. A driver
// must compare it to actual allocation before launching the executor.
type Binding struct {
	Session     string    `json:"session"`
	Generation  int64     `json:"generation"`
	Fingerprint string    `json:"fingerprint"`
	Evidence    string    `json:"evidence"`
	ValidUntil  time.Time `json:"valid_until"`
}

type Work struct {
	Mode      string     `json:"mode"`
	Challenge *Challenge `json:"challenge"`
}
