package kindprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// strategyOperations lists the optional operations the engine needs to drive a
// strategy itself (mode native). The kind's own update (recreate, rolling)
// needs only apply; a delegated strategy is timed by the customer's tool.
var strategyOperations = map[string][]Operation{
	"recreate":   nil,
	"rolling":    nil,
	"canary":     {OpStage, OpShift, OpRetire},
	"linear":     {OpStage, OpShift, OpRetire},
	"shadow":     {OpStage, OpShift, OpRetire},
	"blue-green": {OpStage, OpSwitch, OpRetire},
}

func (m *Manifest) strategy(name string) *StrategyDef {
	for i := range m.Strategies {
		if m.Strategies[i].Name == name {
			return &m.Strategies[i]
		}
	}
	return nil
}

// CheckStrategy reports why the kind cannot run the named strategy (empty
// means its default strategy): the kind does not list it, or, for a strategy
// the engine drives itself, the kind lacks an operation the engine needs. Ref
// is left empty for the caller to fill.
func (m *Manifest) CheckStrategy(name string) []PlanProblem {
	if name == "" {
		name = m.DefaultStrategy
	}
	s := m.strategy(name)
	if s == nil {
		return []PlanProblem{{Code: "strategy-not-supported", Message: fmt.Sprintf("kind %s does not support the %s strategy", m.Ref(), name)}}
	}
	if s.Mode != ModeNative {
		return nil
	}
	needs, known := strategyOperations[name]
	if !known {
		return []PlanProblem{{Code: "strategy-not-supported", Message: fmt.Sprintf("strategy %s is not known to this platform version", name)}}
	}
	var out []PlanProblem
	for _, op := range needs {
		if !m.Has(op) {
			out = append(out, PlanProblem{Code: "operation-missing", Message: fmt.Sprintf("the %s strategy needs %s, which kind %s does not declare", name, op, m.Ref())})
		}
	}
	return out
}

// Strategy returns the kind's definition of the named strategy (empty means
// its default), or nil when the kind does not support it.
func (m *Manifest) Strategy(name string) *StrategyDef {
	if name == "" {
		name = m.DefaultStrategy
	}
	return m.strategy(name)
}

// PlannedExecution is one execution a release plan will run, reduced to what
// the manifest check needs. Release plan derivation (brief 14) maps its steps
// onto this.
type PlannedExecution struct {
	// Ref names the step in problems, for example "checkout to prod-use1".
	Ref  string
	Kind KindRef
	// Strategy comes from rollout policy (IMPL-264); empty means the kind's
	// default strategy.
	Strategy string
	// ApplyConnector and ObserveConnector are the connector types bound to the
	// target for each credential; empty when none is bound.
	ApplyConnector   string
	ObserveConnector string
	TargetSettings   json.RawMessage
}

// PlanProblem is one reason a release plan asks a kind for something it
// cannot do.
type PlanProblem struct {
	Ref     string
	Code    string
	Message string
}

func (p PlanProblem) String() string { return p.Ref + ": " + p.Message }

// ManifestSet holds manifests by exact kind version.
type ManifestSet map[KindRef]*Manifest

// Add puts a manifest in the set.
func (s ManifestSet) Add(m *Manifest) { s[m.Ref()] = m }

// CheckReleasePlan checks every planned execution against the manifest of the
// exact kind version it pins (IMPL-238). It returns every problem found, so a
// release is refused at creation with all its reasons rather than during the
// rollout. An error means a manifest itself is unusable.
func CheckReleasePlan(plan []PlannedExecution, manifests ManifestSet) ([]PlanProblem, error) {
	var problems []PlanProblem
	add := func(ref, code, format string, args ...any) {
		problems = append(problems, PlanProblem{Ref: ref, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	schemas := map[KindRef]*jsonschema.Schema{}
	for _, step := range plan {
		m, ok := manifests[step.Kind]
		if !ok {
			add(step.Ref, "unknown-kind-version", "kind %s has no published manifest", step.Kind)
			continue
		}

		for _, p := range m.CheckStrategy(step.Strategy) {
			add(step.Ref, p.Code, "%s", p.Message)
		}

		checkConnector(step.Ref, "apply", step.ApplyConnector, m.Connectors.Apply, add)
		checkConnector(step.Ref, "observe", step.ObserveConnector, m.Connectors.Observe, add)

		s, ok := schemas[step.Kind]
		if !ok {
			var err error
			if s, err = compileSettingsSchema(m.TargetSettingsSchema); err != nil {
				return nil, fmt.Errorf("kindprotocol: manifest %s: target settings schema: %w", step.Kind, err)
			}
			schemas[step.Kind] = s
		}
		settings, err := jsonschema.UnmarshalJSON(bytes.NewReader(step.TargetSettings))
		if err != nil {
			add(step.Ref, "invalid-target-settings", "target settings are not JSON: %v", err)
		} else if err := s.Validate(settings); err != nil {
			add(step.Ref, "invalid-target-settings", "target settings do not match kind %s: %v", step.Kind, err)
		}
	}
	return problems, nil
}

func checkConnector(ref, use, bound string, accepted []string, add func(ref, code, format string, args ...any)) {
	switch {
	case bound == "" && len(accepted) > 0:
		add(ref, "connector-missing", "no %s connector is bound; the kind accepts %v", use, accepted)
	case bound != "" && !slices.Contains(accepted, bound):
		add(ref, "connector-not-accepted", "the %s connector type %s is not one the kind accepts %v", use, bound, accepted)
	}
}
