package runnerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Validate the actual transport body against the public contract, rather than
// just serializing a separate DTO that the client might never use.
func TestReadinessTransportMatchesPublicRequestSchemas(t *testing.T) {
	raw, err := os.ReadFile("../readiness/schema/readiness.schema.json")
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
	schemas := map[string]*jsonschema.Schema{}
	for path, name := range map[string]string{"session": "SessionRequest", "work": "SessionBinding", "invalidate": "Invalidation"} {
		schema, err := compiler.Compile(base + "#/$defs/" + name)
		if err != nil {
			t.Fatal(err)
		}
		schemas[path] = schema
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer manager-access" {
			t.Error("readiness transport lost manager operation authority")
			http.Error(w, "unauthenticated", 401)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/runner/v1/readiness/")
		schema := schemas[path]
		if schema == nil {
			t.Error("unexpected readiness route", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		body, err := jsonschema.UnmarshalJSON(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "body", 400)
			return
		}
		if err = schema.Validate(body); err != nil {
			t.Error(err)
			http.Error(w, "contract", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch path {
		case "session":
			_ = json.NewEncoder(w).Encode(map[string]any{"session": "11111111-1111-4111-8111-111111111111", "enabled": true})
		case "work":
			_, _ = w.Write([]byte(`{"mode":"enforce","generation":2,"fingerprint":"","binding":null,"challenge":null}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	client := New(server.URL, server.Client())
	ctx := context.Background()
	session, err := client.ReadinessSession(ctx, "manager-access", strings.Repeat("a", 32))
	if err != nil || !session.Enabled {
		t.Fatal(session, err)
	}
	if _, err = client.ReadinessWork(ctx, "manager-access", session.ID); err != nil {
		t.Fatal(err)
	}
	if err = client.ReadinessInvalidate(ctx, "manager-access", session.ID, 2); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal("missing request conformance coverage", calls)
	}
}
