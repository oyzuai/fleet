package kindprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Plans from other implementations may retain schema-valid optional zero values.
func TestRawPlanDigestPreservesOptionalValuesAndNumbers(t *testing.T) {
	for _, attrs := range []string{
		"[]",
		`[{"path":"/count","before":null,"after":9007199254740993}]`,
		`[{"path":"/ratio","before":0.1234567890123456789,"after":1.234567890123456789e+30}]`,
		`[{"path":"/count","before":null,"after":9007199254740993,"sensitive":false}]`,
		`[{"path":"/ratio","before":0.1234567890123456789,"after":1.234567890123456789e+30,"sensitive":false}]`,
	} {
		raw := []byte(`{"schema_version":"v1alpha1","type":"deployment-plan","kind":{"name":"fake","version":"1.0.0"},"summary":"test","changes":[{"action":"update","resource":{"type":"test","name":"web"},"attributes":` + attrs + `}],"risk_flags":[]}`)
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		canonical, err := Canonical(doc)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		doc["digest"] = "sha256:" + hex.EncodeToString(sum[:])
		raw, _ = json.Marshal(doc)
		plan, err := DecodePlan(raw)
		if err != nil {
			t.Fatalf("attributes=%s: %v", attrs, err)
		}
		if err := plan.Verify(); err != nil {
			t.Fatal("typed Verify:", err)
		}
		forwarded, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodePlan(forwarded); err != nil {
			t.Fatal("forwarded plan:", err)
		}
		plan.Summary = "changed"
		if err := plan.Verify(); !errors.Is(err, ErrDigestMismatch) {
			t.Fatal("edited typed plan still verifies:", err)
		}
		req := []byte(`{"schema_version":"v1alpha1","type":"deployment-kind-request","operation":"apply","execution_id":"e1","kind":{"name":"fake","version":"1.0.0"},"target_settings":{},"components":[{"component":"web","version":"1","artifacts":[{"name":"image","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}],"approved_plan":` + string(raw) + `}`)
		if _, err := DecodeRequest(req); err != nil {
			t.Fatal("nested request:", err)
		}
		result := []byte(`{"schema_version":"v1alpha1","type":"deployment-kind-result","operation":"plan","execution_id":"e1","outcome":"succeeded","plan":` + string(raw) + `}`)
		if _, err := DecodeResult(result); err != nil {
			t.Fatal("nested result:", err)
		}
		tampered := []byte(strings.Replace(string(raw), `"summary":"test"`, `"summary":"changed"`, 1))
		if _, err := DecodePlan(tampered); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("tampered plan: %v", err)
		}
	}
}
