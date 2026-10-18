package kindprotocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func examples(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob("testdata/examples/*.json")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, p := range paths {
		if filepath.Base(p) == "invalid-cases.json" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = b
	}
	if len(out) == 0 {
		t.Fatal("no examples")
	}
	return out
}

// TestExamplesRoundTrip checks the Go types against the published schemas:
// every example validates, decodes strictly (no member the types lack), and
// encodes back to the same document, which still validates.
func TestExamplesRoundTrip(t *testing.T) {
	for name, raw := range examples(t) {
		t.Run(name, func(t *testing.T) {
			var v any
			var err error
			switch strings.SplitN(name, ".", 2)[0] {
			case "manifest":
				v, err = DecodeManifest(raw)
			case "request":
				v, err = DecodeRequest(raw)
			case "result":
				v, err = DecodeResult(raw)
			case "event":
				v, err = DecodeEvent(raw)
			case "plan":
				v, err = DecodePlan(raw)
			default:
				t.Fatalf("no schema for %s", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			again, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := CanonicalJSON(raw)
			got, _ := CanonicalJSON(again)
			if !bytes.Equal(want, got) {
				t.Fatalf("round trip changed the document\nwant %s\ngot  %s", want, got)
			}
			if err := Validate(strings.SplitN(name, ".", 2)[0], again); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestInvalidCases runs the contract's refused documents through the Go
// validator, so it agrees with the published checker.
func TestInvalidCases(t *testing.T) {
	ex := examples(t)
	raw, err := os.ReadFile("testdata/examples/invalid-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string          `json:"name"`
		Base    string          `json:"base"`
		Pointer string          `json:"pointer"`
		Value   json.RawMessage `json:"value"`
		Remove  bool            `json:"remove"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal(ex[c.Base], &doc); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(c.Pointer, "/")[1:]
			parent := doc
			for _, p := range parts[:len(parts)-1] {
				switch x := parent.(type) {
				case map[string]any:
					parent = x[p]
				case []any:
					i, _ := strconv.Atoi(p)
					parent = x[i]
				}
			}
			last := parts[len(parts)-1]
			switch x := parent.(type) {
			case map[string]any:
				if c.Remove {
					delete(x, last)
				} else {
					var v any
					_ = json.Unmarshal(c.Value, &v)
					x[last] = v
				}
			case []any:
				i, _ := strconv.Atoi(last)
				var v any
				_ = json.Unmarshal(c.Value, &v)
				x[i] = v
			}
			changed, _ := json.Marshal(doc)
			if err := Validate(strings.SplitN(c.Base, ".", 2)[0], changed); err == nil {
				t.Fatalf("schema admitted %s", c.Name)
			}
		})
	}
}

func TestPlanSealMatchesPublishedDigest(t *testing.T) {
	for _, name := range []string{"plan.typed.json", "plan.untyped.json", "plan.availability.json"} {
		p, err := DecodePlan(examples(t)[name])
		if err != nil {
			t.Fatal(err)
		}
		want := p.Digest
		p.Digest = ""
		if err := p.Seal(); err != nil {
			t.Fatal(err)
		}
		if p.Digest != want {
			t.Fatalf("%s: Seal gives %s, published %s", name, p.Digest, want)
		}
		p.Summary += "."
		if err := p.Verify(); err == nil {
			t.Fatalf("%s: edited plan still verifies", name)
		}
	}
}

func TestCanonicalJSON(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// RFC 8785 section 3.2.3: sorting by UTF-16 code units.
		{`{"\u20ac":"Euro","\r":"CR","\ufb33":"Hebrew","1":"One","\ud83d\ude00":"Emoji","\u0080":"Control","\u00f6":"Latin"}`,
			"{\"\\r\":\"CR\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin\",\"\u20ac\":\"Euro\",\"\U0001F600\":\"Emoji\",\"\ufb33\":\"Hebrew\"}"},
		// RFC 8785 section 3.2.2.3 numbers.
		{`[1E30, 4.50, 2e-3, 0.000000000000000000000000001, -0, 333333333.33333329, 1e21, 1e-7, 100]`,
			`[1e+30,4.5,0.002,1e-27,0,333333333.3333333,1e+21,1e-7,100]`},
		{"{\"b\" : [true, null], \"a\":\"<&>\\u2028\\u0001\\/\"}", "{\"a\":\"<&>\u2028\\u0001/\",\"b\":[true,null]}"},
	} {
		got, err := CanonicalJSON([]byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("CanonicalJSON(%s)\n got %s\nwant %s", c.in, got, c.want)
		}
	}
}
