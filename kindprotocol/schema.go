package kindprotocol

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/*.schema.json
var schemaFiles embed.FS

const schemaBase = "https://oyzu.dev/contracts/kinds-v1alpha1/"

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

// schemaFor returns the compiled published schema for a document type:
// "manifest", "request", "result", "event" or "plan".
func schemaFor(name string) (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		entries, err := schemaFiles.ReadDir("schema")
		if err != nil {
			compileErr = err
			return
		}
		for _, e := range entries {
			b, err := schemaFiles.ReadFile("schema/" + e.Name())
			if err != nil {
				compileErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				compileErr = fmt.Errorf("%s: %w", e.Name(), err)
				return
			}
			if err := c.AddResource(schemaBase+e.Name(), doc); err != nil {
				compileErr = err
				return
			}
		}
		compiled = map[string]*jsonschema.Schema{}
		for _, n := range []string{"manifest", "request", "result", "event", "plan"} {
			s, err := c.Compile(schemaBase + n + ".schema.json")
			if err != nil {
				compileErr = err
				return
			}
			compiled[n] = s
		}
	})
	if compileErr != nil {
		return nil, compileErr
	}
	s, ok := compiled[name]
	if !ok {
		return nil, fmt.Errorf("kindprotocol: no schema %q", name)
	}
	return s, nil
}

// Validate checks raw JSON against the published schema for a document type
// ("manifest", "request", "result", "event" or "plan").
func Validate(name string, raw []byte) error {
	s, err := schemaFor(name)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("kindprotocol: %s is not JSON: %w", name, err)
	}
	if err := s.Validate(doc); err != nil {
		return fmt.Errorf("kindprotocol: invalid %s: %w", name, err)
	}
	return nil
}

// decode validates raw against the schema, then decodes it strictly.
func decode[T any](name string, raw []byte) (*T, error) {
	if err := Validate(name, raw); err != nil {
		return nil, err
	}
	var v T
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("kindprotocol: decode %s: %w", name, err)
	}
	return &v, nil
}

// DecodeManifest validates and decodes a manifest. The default strategy must be
// one the manifest declares, and the target settings schema must compile.
func DecodeManifest(raw []byte) (*Manifest, error) {
	m, err := decode[Manifest]("manifest", raw)
	if err != nil {
		return nil, err
	}
	if !m.Verifies() && m.strategy(m.DefaultStrategy) == nil {
		return nil, fmt.Errorf("kindprotocol: manifest %s: default strategy %q is not declared", m.Ref(), m.DefaultStrategy)
	}
	if _, err := compileSettingsSchema(m.TargetSettingsSchema); err != nil {
		return nil, fmt.Errorf("kindprotocol: manifest %s: target settings schema: %w", m.Ref(), err)
	}
	if err := m.CheckSchedule(); err != nil {
		return nil, fmt.Errorf("kindprotocol: %w", err)
	}
	return m, nil
}

// DecodeRequest validates and decodes a request. An approved plan's digest
// must recompute.
func DecodeRequest(raw []byte) (*Request, error) {
	r, err := decode[Request]("request", raw)
	if err != nil {
		return nil, err
	}
	if r.ApprovedPlan != nil {
		if err := r.ApprovedPlan.Verify(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// DecodeResult validates and decodes a result. A returned plan's digest must
// recompute.
func DecodeResult(raw []byte) (*Result, error) {
	r, err := decode[Result]("result", raw)
	if err != nil {
		return nil, err
	}
	if r.Plan != nil {
		if err := r.Plan.Verify(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// DecodeEvent validates and decodes one event line.
func DecodeEvent(raw []byte) (*Event, error) { return decode[Event]("event", raw) }

// DecodePlan validates and decodes a plan and checks its digest.
func DecodePlan(raw []byte) (*Plan, error) {
	p, err := decode[Plan]("plan", raw)
	if err != nil {
		return nil, err
	}
	if err := p.Verify(); err != nil {
		return nil, err
	}
	return p, nil
}

// compileSettingsSchema compiles a kind's target settings schema on its own:
// it may reference nothing outside itself.
func compileSettingsSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noLoader{})
	const url = "urn:oyzu:kind-target-settings"
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	return c.Compile(url)
}

// noLoader refuses every external reference, so compiling a customer's schema
// never fetches anything.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %s is not allowed", url)
}

// SettingsValidator checks target settings against one manifest's target
// settings schema. Services that store kind-specific settings (brief 12)
// compile it once per kind version and reuse it.
type SettingsValidator struct {
	schema *jsonschema.Schema
}

// TargetSettingsValidator compiles the manifest's target settings schema.
func (m *Manifest) TargetSettingsValidator() (*SettingsValidator, error) {
	s, err := compileSettingsSchema(m.TargetSettingsSchema)
	if err != nil {
		return nil, fmt.Errorf("kindprotocol: manifest %s: target settings schema: %w", m.Ref(), err)
	}
	return &SettingsValidator{schema: s}, nil
}

// Validate reports how settings fail the schema, or nil when they match.
func (v *SettingsValidator) Validate(settings json.RawMessage) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(settings))
	if err != nil {
		return fmt.Errorf("settings are not JSON: %w", err)
	}
	return v.schema.Validate(doc)
}

// CheckSettings validates target settings against the manifest's schema and
// returns each problem by JSON pointer, the shape validate reports invalid
// settings in (IMPL-338). Nil means the settings are valid.
func (m *Manifest) CheckSettings(settings json.RawMessage) ([]Problem, error) {
	v, err := m.TargetSettingsValidator()
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(settings))
	if err != nil {
		return []Problem{{Path: "", Message: "the target settings are not JSON"}}, nil
	}
	err = v.schema.Validate(doc)
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return nil, err
	}
	var problems []Problem
	for _, u := range verr.BasicOutput().Errors {
		if u.Error == nil || u.KeywordLocation == "" {
			continue
		}
		problems = append(problems, Problem{Path: u.InstanceLocation, Message: u.Error.String()})
	}
	if len(problems) == 0 {
		problems = []Problem{{Path: "", Message: verr.Error()}}
	}
	return problems, nil
}
