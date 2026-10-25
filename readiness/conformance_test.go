package readiness

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestPublicWireConformanceAndFingerprint(t *testing.T) {
	raw, err := os.ReadFile("schema/readiness.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const base = "https://github.com/oyzuai/oyzu/blob/main/docs/contracts/runner-v1/readiness.schema.json"
	if err = compiler.AddResource(base, doc); err != nil {
		t.Fatal(err)
	}
	vector, err := os.ReadFile("schema/readiness-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Fingerprint struct {
			Boundary Boundary `json:"boundary"`
			SHA256   string   `json:"sha256"`
		} `json:"fingerprint"`
	}
	if err = json.Unmarshal(vector, &v); err != nil {
		t.Fatal(err)
	}
	if got := v.Fingerprint.Boundary.Fingerprint(); got != v.Fingerprint.SHA256 {
		t.Fatalf("fingerprint differs from independent public vector: %s", got)
	}
	// Container runtime measurements may bind an inspected namespace anchor
	// inside their opaque digest without adding fields or changing this wire
	// version's independent fingerprint algorithm.
	anchored := v.Fingerprint.Boundary
	anchored.Runtime = strings.Repeat("b", 64)
	if !anchored.Valid() || anchored.Fingerprint() == v.Fingerprint.SHA256 {
		t.Fatal("opaque anchored runtime did not change the boundary")
	}
	anchorSchema, err := compiler.Compile(base + "#/$defs/Boundary")
	if err != nil {
		t.Fatal(err)
	}
	anchoredJSON, _ := json.Marshal(anchored)
	anchoredValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(anchoredJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := anchorSchema.Validate(anchoredValue); err != nil {
		t.Fatal(err)
	}
	c := Challenge{ID: "11111111-1111-4111-8111-111111111111", Session: "22222222-2222-4222-8222-222222222222", Generation: 2, Fingerprint: v.Fingerprint.SHA256, Suite: Suite, Nonce: strings.Repeat("a", 32), Descriptor: Descriptor{URL: "http://192.0.2.1:8080", DNSAddress: "192.0.2.1:8053", DNSName: "readiness.oyzu.test"}, Dispatched: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), Deadline: time.Date(2026, 10, 22, 12, 5, 0, 0, time.UTC)}
	r := Result{Challenge: c.ID, Session: c.Session, Generation: c.Generation, Fingerprint: c.Fingerprint, Suite: c.Suite}
	for _, name := range CheckNames() {
		r.Checks = append(r.Checks, Subcheck{Name: name, Outcome: "passed", Reason: "CHECK_PASSED"})
	}
	r.Aggregate()
	samples := map[string]any{"Boundary": v.Fingerprint.Boundary, "SessionRequest": map[string]string{"boot": strings.Repeat("a", 32)}, "Session": Session{ID: c.Session, Enabled: true}, "Challenge": c, "Result": r, "Work": Work{Mode: "enforce", Generation: 2, Fingerprint: c.Fingerprint, Challenge: &c}, "Binding": Binding{Challenge: c.ID, Session: c.Session, Generation: c.Generation, Fingerprint: c.Fingerprint, Evidence: c.ID, ValidUntil: c.Deadline}}
	for name, value := range samples {
		t.Run(name, func(t *testing.T) {
			schema, err := compiler.Compile(base + "#/$defs/" + name)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err = schema.Validate(document); err != nil {
				t.Fatal(err)
			}
		})
	}
	schema, err := compiler.Compile(base + "#/$defs/Result")
	if err != nil {
		t.Fatal(err)
	}
	r.Checks = r.Checks[1:] // a false passing aggregate lacks a required check
	raw, _ = json.Marshal(r)
	document, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if schema.Validate(document) == nil {
		t.Fatal("public schema accepted a false positive without all required checks")
	}
}
