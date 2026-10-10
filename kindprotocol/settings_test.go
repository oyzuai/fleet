package kindprotocol

import (
	"os"
	"testing"
)

func TestCheckSettings(t *testing.T) {
	raw, err := os.ReadFile("testdata/examples/manifest.script.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := m.CheckSettings([]byte(`{"apply": ["./deploy.sh"], "observe": ["./version.sh"]}`)); err != nil || p != nil {
		t.Fatalf("valid settings: %v, %v", p, err)
	}
	p, err := m.CheckSettings([]byte(`{"apply": [], "observe": "./version.sh"}`))
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, x := range p {
		paths[x.Path] = true
	}
	if !paths["/apply"] || !paths["/observe"] {
		t.Fatalf("problems %+v, want /apply and /observe", p)
	}
	if p, _ := m.CheckSettings([]byte(`not json`)); len(p) != 1 {
		t.Fatalf("not JSON: %+v", p)
	}
}
