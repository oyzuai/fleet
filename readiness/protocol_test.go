package readiness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMissingCheckCannotBecomePassingEvidence(t *testing.T) {
	r := Result{Challenge: "c", Session: "s", Generation: 1, Fingerprint: strings.Repeat("a", 64), Suite: Suite, Outcome: "passed"}
	for _, n := range CheckNames() {
		if n != "control-reachability" {
			r.Checks = append(r.Checks, Subcheck{Name: n, Outcome: "passed"})
		}
	}
	if r.Validate() == nil {
		t.Fatal("missing positive control accepted as pass")
	}
	r.Aggregate()
	if r.Outcome != "inconclusive" || r.Validate() != nil {
		t.Fatalf("missing control: %+v", r)
	}
	r.Checks = append(r.Checks, Subcheck{Name: "control-reachability", Outcome: "passed"})
	r.Checks[0].Outcome = "failed"
	r.Aggregate()
	if r.Outcome != "failed" || r.Validate() != nil {
		t.Fatalf("observed bypass lost: %+v", r)
	}
}

func TestEchoRequiresChallengeResponseAndNeverFollowsRedirect(t *testing.T) {
	called := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte("oyzu-readiness:" + strings.Repeat("a", 32)))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	if err := AllowedEcho(context.Background(), Descriptor{URL: redirect.URL}, strings.Repeat("a", 32), ""); err == nil || called != 0 {
		t.Fatal("diagnostic redirect was followed")
	}
	if err := AllowedEcho(context.Background(), Descriptor{URL: destination.URL}, strings.Repeat("b", 32), ""); err == nil {
		t.Fatal("unrelated echo accepted")
	}
	if err := AllowedEcho(context.Background(), Descriptor{URL: destination.URL}, strings.Repeat("a", 32), ""); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosticDestinationsCannotDependOnSandboxDNS(t *testing.T) {
	d := Descriptor{URL: "http://canary.example:8080", DNSAddress: "127.0.0.1:53", DNSName: "readiness.oyzu.test"}
	if d.Validate() == nil {
		t.Fatal("name-only direct test could pass because sandbox DNS failed")
	}
	d.URL = "http://127.0.0.1:8080"
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}
