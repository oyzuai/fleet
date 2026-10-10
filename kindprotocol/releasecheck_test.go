package kindprotocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckReleasePlan(t *testing.T) {
	ex := examples(t)
	ecs, err := DecodeManifest(ex["manifest.ecs.json"])
	if err != nil {
		t.Fatal(err)
	}
	script, err := DecodeManifest(ex["manifest.script.json"])
	if err != nil {
		t.Fatal(err)
	}
	set := ManifestSet{}
	set.Add(ecs)
	set.Add(script)
	// A kind without stage or shift: canary must be refused.
	noTraffic := *ecs
	noTraffic.Version = "1.3.0"
	noTraffic.Operations = map[Operation]OperationDef{OpValidate: {60}, OpPlan: {60}, OpApply: {60}, OpObserve: {60}}
	set.Add(&noTraffic)

	settings := json.RawMessage(`{"region":"us-east-1","cluster":"prod-use1","service":"checkout"}`)
	ok := PlannedExecution{Ref: "checkout to prod-use1", Kind: ecs.Ref(), Strategy: "canary",
		ApplyConnector: "aws", ObserveConnector: "aws", TargetSettings: settings}

	cases := []struct {
		name  string
		step  func(PlannedExecution) PlannedExecution
		codes []string
	}{
		{"valid canary", func(s PlannedExecution) PlannedExecution { return s }, nil},
		{"default strategy", func(s PlannedExecution) PlannedExecution { s.Strategy = ""; return s }, nil},
		{"delegated linear", func(s PlannedExecution) PlannedExecution { s.Strategy = "linear"; return s }, nil},
		{"unknown kind version", func(s PlannedExecution) PlannedExecution { s.Kind.Version = "9.9.9"; return s }, []string{"unknown-kind-version"}},
		{"undeclared strategy", func(s PlannedExecution) PlannedExecution { s.Strategy = "shadow"; return s }, []string{"strategy-not-supported"}},
		{"canary without traffic operations", func(s PlannedExecution) PlannedExecution { s.Kind = noTraffic.Ref(); return s },
			[]string{"operation-missing", "operation-missing", "operation-missing"}},
		{"wrong connector", func(s PlannedExecution) PlannedExecution { s.ApplyConnector = "gcp"; return s }, []string{"connector-not-accepted"}},
		{"missing observe connector", func(s PlannedExecution) PlannedExecution { s.ObserveConnector = ""; return s }, []string{"connector-missing"}},
		{"bad settings", func(s PlannedExecution) PlannedExecution {
			s.TargetSettings = json.RawMessage(`{"region":"use-east-1","cluster":"c"}`)
			return s
		}, []string{"invalid-target-settings"}},
		{"script kind with no observe credential", func(s PlannedExecution) PlannedExecution {
			s.Kind, s.Strategy, s.ApplyConnector, s.ObserveConnector = script.Ref(), "", "ssh", ""
			s.TargetSettings = json.RawMessage(`{"apply":["./deploy.sh"],"observe":["curl","-f","http://web/health"]}`)
			return s
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems, err := CheckReleasePlan([]PlannedExecution{c.step(ok)}, set)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range problems {
				got = append(got, p.Code)
			}
			if strings.Join(got, ",") != strings.Join(c.codes, ",") {
				t.Fatalf("problems %v, want %v", problems, c.codes)
			}
		})
	}
}

func TestDecodeManifestRefusesUndeclaredDefault(t *testing.T) {
	var m map[string]any
	_ = json.Unmarshal(examples(t)["manifest.ecs.json"], &m)
	m["default_strategy"] = "shadow"
	raw, _ := json.Marshal(m)
	if _, err := DecodeManifest(raw); err == nil {
		t.Fatal("manifest with an undeclared default strategy was accepted")
	}
}

func TestNoResultClass(t *testing.T) {
	if NoResultClass(OpPlan) != Retryable || NoResultClass(OpApply) != PartialChange || NoResultClass(OpShift) != PartialChange {
		t.Fatal("a run with no result is misclassified")
	}
}
