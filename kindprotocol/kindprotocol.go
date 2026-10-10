// Package kindprotocol is the deployment kind protocol (platform decisions
// IMPL-235 to 238, IMPL-248 to 252): the Go types for the request a kind reads,
// the result and events it writes, its manifest and its plan, schema validation
// against the published contract, the plan digest, and the check of a release
// plan against the manifests of its kinds.
//
// The contract is owned by oyzuai/oyzu (docs/contracts/kinds-v1alpha1); schema/
// holds a pinned copy. This package is a copy of the platform's
// internal/lib/kindprotocol, which the runs service validates with; the two
// change together. The conformance suite that runs a kind stays in the
// platform's kindprotocoltest.
package kindprotocol

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the protocol version these types speak.
const SchemaVersion = "v1alpha1"

// Document types, the value of each document's "type" member.
const (
	TypeManifest = "deployment-kind-manifest"
	TypeRequest  = "deployment-kind-request"
	TypeResult   = "deployment-kind-result"
	TypeEvent    = "deployment-kind-event"
	TypePlan     = "deployment-plan"
)

// Operation is one kind operation. The first four are required of every kind.
type Operation string

const (
	OpValidate Operation = "validate"
	OpPlan     Operation = "plan"
	OpApply    Operation = "apply"
	OpObserve  Operation = "observe"
	OpStage    Operation = "stage"
	OpShift    Operation = "shift"
	OpSwitch   Operation = "switch"
	OpRetire   Operation = "retire"
	OpAbort    Operation = "abort"
	OpRollback Operation = "rollback"
	OpDrift    Operation = "drift"
)

// KindRef names one version of a kind.
type KindRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (k KindRef) String() string { return k.Name + "@" + k.Version }

// Artifact is one artifact of a component version, pinned by digest.
type Artifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type,omitempty"`
	Digest    string `json:"digest"`
	URI       string `json:"uri,omitempty"`
}

// ComponentVersion is a desired (or claimed) version of one component.
type ComponentVersion struct {
	Component string     `json:"component"`
	Version   string     `json:"version"`
	Artifacts []Artifact `json:"artifacts"`
}

// Health is one of the five Oyzu status words as a machine value.
type Health string

const (
	Healthy        Health = "healthy"
	Pending        Health = "pending"
	Paused         Health = "paused"
	NeedsAttention Health = "needs-attention"
	Failed         Health = "failed"
)

// ObservedComponent is what observe found for one component. Version is empty
// when nothing is deployed.
type ObservedComponent struct {
	Component string     `json:"component"`
	Version   string     `json:"version,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	Health    Health     `json:"health"`
	Message   string     `json:"message,omitempty"`
}

// ObservedState is a target's observed state and when it was read.
type ObservedState struct {
	AsOf       time.Time           `json:"as_of"`
	Components []ObservedComponent `json:"components"`
}

// Change is one entry of a plan's typed diff.
type Change struct {
	Action     string            `json:"action"` // create, update, replace, delete, run
	Resource   ResourceRef       `json:"resource"`
	Attributes []AttributeChange `json:"attributes,omitempty"`
}

// ResourceRef names the resource a change touches.
type ResourceRef struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// AttributeChange is one attribute's before and after. A sensitive change
// carries no values.
type AttributeChange struct {
	Path      string          `json:"path"`
	Before    json.RawMessage `json:"before,omitempty"`
	After     json.RawMessage `json:"after,omitempty"`
	Sensitive bool            `json:"sensitive,omitempty"`
}

// RiskFlag values. Policy can require an approval when one is present.
const (
	RiskDestroy          = "destroy"
	RiskReplace          = "replace"
	RiskPermissionChange = "permission-change"
	RiskDataLoss         = "data-loss"
	RiskIrreversible     = "irreversible"
	RiskUntyped          = "untyped"
)

// RiskFlag is one deterministic risk in a plan.
type RiskFlag struct {
	Flag     string `json:"flag"`
	Reason   string `json:"reason"`
	Resource string `json:"resource,omitempty"`
}

// Plan is what a person approves. Digest covers everything else (see Seal).
type Plan struct {
	SchemaVersion string     `json:"schema_version"`
	Type          string     `json:"type"`
	Kind          KindRef    `json:"kind"`
	Summary       string     `json:"summary"`
	Changes       []Change   `json:"changes"`
	RiskFlags     []RiskFlag `json:"risk_flags"`
	Capacity      string     `json:"capacity,omitempty"`
	Digest        string     `json:"digest"`
}

// HasRisk reports whether the plan carries the flag.
func (p *Plan) HasRisk(flag string) bool {
	for _, f := range p.RiskFlags {
		if f.Flag == flag {
			return true
		}
	}
	return false
}

// Config is the configuration a kind receives. Secrets are references only.
type Config struct {
	Values  map[string]any `json:"values,omitempty"`
	Secrets []SecretRef    `json:"secrets,omitempty"`
}

// SecretRef names a secret the pool resolves through the secrets use path.
type SecretRef struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

// Request is the one document a kind reads on standard input.
type Request struct {
	SchemaVersion  string             `json:"schema_version"`
	Type           string             `json:"type"`
	Operation      Operation          `json:"operation"`
	ExecutionID    string             `json:"execution_id"`
	Kind           KindRef            `json:"kind"`
	TargetSettings json.RawMessage    `json:"target_settings"`
	Components     []ComponentVersion `json:"components"`
	Config         *Config            `json:"config,omitempty"`
	LastObserved   *ObservedState     `json:"last_observed,omitempty"`
	ApprovedPlan   *Plan              `json:"approved_plan,omitempty"`
	TrafficPercent *int               `json:"traffic_percent,omitempty"`
	RollbackTo     *ObservedState     `json:"rollback_to,omitempty"`
}

// Outcome is how an operation ended.
type Outcome string

const (
	Succeeded Outcome = "succeeded"
	// StalePlan means apply refused an approved plan that no longer holds;
	// nothing changed and the engine plans again.
	StalePlan     Outcome = "stale-plan"
	OutcomeFailed Outcome = "failed"
)

// FailureClass says what state a failure left.
type FailureClass string

const (
	Retryable     FailureClass = "retryable"      // nothing changed
	NeedsPerson   FailureClass = "needs-person"   // a person must act
	PartialChange FailureClass = "partial-change" // the target may be between versions; the release run holds
)

// Failure describes a failed operation.
type Failure struct {
	Class    FailureClass `json:"class"`
	Code     string       `json:"code"`
	Message  string       `json:"message"`
	Problems []Problem    `json:"problems,omitempty"`
}

// Problem is one setting or input that failed validation, by JSON pointer.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Staged is the private address stage returns.
type Staged struct {
	Address string `json:"address"`
}

// Drift is what drift found.
type Drift struct {
	Drifted bool     `json:"drifted"`
	Changes []Change `json:"changes"`
}

// Result is the one document a kind writes on standard output.
type Result struct {
	SchemaVersion string             `json:"schema_version"`
	Type          string             `json:"type"`
	Operation     Operation          `json:"operation"`
	ExecutionID   string             `json:"execution_id"`
	Outcome       Outcome            `json:"outcome"`
	Plan          *Plan              `json:"plan,omitempty"`
	Applied       []ComponentVersion `json:"applied,omitempty"`
	Observed      *ObservedState     `json:"observed,omitempty"`
	Staged        *Staged            `json:"staged,omitempty"`
	Drift         *Drift             `json:"drift,omitempty"`
	Failure       *Failure           `json:"failure,omitempty"`
}

// Event is one line of a kind's event stream on standard error.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	Type          string    `json:"type"`
	ExecutionID   string    `json:"execution_id"`
	Operation     Operation `json:"operation"`
	Sequence      int64     `json:"sequence"`
	Time          time.Time `json:"time"`
	Event         EventBody `json:"event"`
}

// EventBody is a heartbeat, progress or log event.
type EventBody struct {
	Type    string `json:"type"` // heartbeat, progress, log
	Message string `json:"message,omitempty"`
	Percent *int   `json:"percent,omitempty"`
	Level   string `json:"level,omitempty"` // log: debug, info, warn, error
}

// Manifest is what a kind declares it can do.
type Manifest struct {
	SchemaVersion        string                     `json:"schema_version"`
	Type                 string                     `json:"type"`
	Name                 string                     `json:"name"`
	Version              string                     `json:"version"`
	Description          string                     `json:"description,omitempty"`
	Operations           map[Operation]OperationDef `json:"operations"`
	Rollback             string                     `json:"rollback"` // native, redeploy, none
	Strategies           []StrategyDef              `json:"strategies"`
	DefaultStrategy      string                     `json:"default_strategy"`
	TargetSettingsSchema json.RawMessage            `json:"target_settings_schema"`
	Connectors           Connectors                 `json:"connectors"`
}

// Ref names this manifest's kind version.
func (m *Manifest) Ref() KindRef { return KindRef{Name: m.Name, Version: m.Version} }

// Has reports whether the kind declares the operation.
func (m *Manifest) Has(op Operation) bool { _, ok := m.Operations[op]; return ok }

// OperationDef is one declared operation.
type OperationDef struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

// Strategy modes.
const (
	ModeNative    = "native"    // the engine drives each step through the kind's operations
	ModeDelegated = "delegated" // a tool the customer runs times the steps
)

// StrategyDef is one strategy a kind supports.
type StrategyDef struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
	Tool string `json:"tool,omitempty"`
}

// Connectors lists the connector types a kind accepts, apply and observe apart.
type Connectors struct {
	Apply   []string `json:"apply"`
	Observe []string `json:"observe"`
}

// NoResultClass is how the runner classifies a run that ended without a valid
// result: nothing can have changed for an operation without side effects, and
// anything else may have left the target between versions.
func NoResultClass(op Operation) FailureClass {
	switch op {
	case OpValidate, OpPlan, OpObserve, OpDrift:
		return Retryable
	}
	return PartialChange
}
