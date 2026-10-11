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
	"fmt"
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
	OpWatch    Operation = "watch"
	OpStage    Operation = "stage"
	OpShift    Operation = "shift"
	OpSwitch   Operation = "switch"
	OpRetire   Operation = "retire"
	OpAbort    Operation = "abort"
	OpRollback Operation = "rollback"
	OpDrift    Operation = "drift"
	// OpVerify runs a verification: a verification kind's one operation.
	OpVerify Operation = "verify"
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

// ComponentVersion is a desired (or claimed) version of one component. In an
// observe, watch or drift request Version and Artifacts may both be empty: the
// target has no desired version and observe reports whatever runs there.
type ComponentVersion struct {
	Component string     `json:"component"`
	Version   string     `json:"version,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
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
	// Details are the component's family-specific details (IMPL-280).
	Details *ObservedDetails `json:"details,omitempty"`
}

// Observation families, the value of ObservedDetails.Family.
const (
	FamilyWorkload       = "workload"
	FamilyInfrastructure = "infrastructure"
	FamilyDelegated      = "delegated"
	FamilyPublishing     = "publishing"
	FamilyData           = "data"
	FamilyControl        = "control"
)

// ObservedDetails are one component's family-specific details. Family says
// which members apply; Raw keeps anything else the kind wants shown.
type ObservedDetails struct {
	Family string `json:"family"`
	// Unmanaged names what runs when the kind cannot attribute it to an Oyzu
	// release; the component's version is then absent (IMPL-282).
	Unmanaged   string          `json:"unmanaged,omitempty"`
	Replicas    *Replicas       `json:"replicas,omitempty"`
	Instances   []Instance      `json:"instances,omitempty"`
	Traffic     []TrafficShare  `json:"traffic,omitempty"`
	StateSerial *int64          `json:"state_serial,omitempty"`
	LastApply   string          `json:"last_apply,omitempty"` // succeeded, failed, none
	Outputs     map[string]any  `json:"outputs,omitempty"`
	Drifted     *bool           `json:"drifted,omitempty"`
	Sync        *SyncStatus     `json:"sync,omitempty"`
	Available   []Availability  `json:"available,omitempty"`
	Migration   *MigrationState `json:"migration,omitempty"`
	Value       *ControlValue   `json:"value,omitempty"`
	Raw         map[string]any  `json:"raw,omitempty"`
}

// Replicas are a workload's desired and ready instances.
type Replicas struct {
	Desired  int  `json:"desired"`
	Ready    int  `json:"ready"`
	Restarts *int `json:"restarts,omitempty"`
	Failed   *int `json:"failed,omitempty"`
}

// Instance roles.
const (
	RolePrimary  = "primary"
	RoleStaged   = "staged"
	RoleCanary   = "canary"
	RolePrevious = "previous"
)

// Instance is one instance, task set, revision or deployment group of a
// workload. A group carries its own replicas and load balancer targets.
type Instance struct {
	Name     string    `json:"name"`
	Role     string    `json:"role,omitempty"`
	Version  string    `json:"version,omitempty"`
	Digest   string    `json:"digest,omitempty"`
	Health   Health    `json:"health"`
	Replicas *Replicas `json:"replicas,omitempty"`
	Targets  *Targets  `json:"targets,omitempty"`
	Message  string    `json:"message,omitempty"`
}

// Targets are load balancer targets passing and failing health checks.
type Targets struct {
	Healthy   int `json:"healthy"`
	Unhealthy int `json:"unhealthy"`
}

// TrafficShare is the share of traffic one version, or one instance when
// its version is unknown, serves.
type TrafficShare struct {
	Version  string `json:"version,omitempty"`
	Instance string `json:"instance,omitempty"`
	Percent  int    `json:"percent"`
}

// SyncStatus is a delegated tool's own view, in its words.
type SyncStatus struct {
	Revision string `json:"revision"`
	Status   string `json:"status"`
	Health   string `json:"health,omitempty"`
}

// Availability is whether a published version is where it should be.
type Availability struct {
	Location        string `json:"location"`
	Present         bool   `json:"present"`
	ChecksumMatches *bool  `json:"checksum_matches,omitempty"`
}

// MigrationState is a database's applied migration version and phase.
type MigrationState struct {
	Version  string `json:"version"`
	Phase    string `json:"phase,omitempty"` // expanded, contracted, backfilling
	LockHeld *bool  `json:"lock_held,omitempty"`
}

// ControlValue is a release control's current value.
type ControlValue struct {
	Current        any  `json:"current"`
	MatchesDesired bool `json:"matches_desired"`
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
	rawPlan       json.RawMessage
	decodedPlan   json.RawMessage
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
	Verification   *Verification      `json:"verification,omitempty"`
}

// Report formats a suite writes.
const (
	ReportJUnit     = "junit"
	ReportK6Summary = "k6-summary"
)

// Pass rules (IMPL-272): every test passes, or the tests the suite itself
// lists as known failures may fail. Oyzu never decides on its own to ignore a
// test.
const (
	PassAll           = "all"
	PassKnownFailures = "known-failures-in-suite"
)

// Verification is a verify request's suite: its command and report format
// from the test-suite component version's manifest, and its inputs resolved.
type Verification struct {
	Suite           string            `json:"suite"`
	Run             []string          `json:"run"`
	Results         string            `json:"results"`
	Inputs          map[string]string `json:"inputs"`
	PassRule        string            `json:"pass_rule"`
	KnownFailures   []string          `json:"known_failures,omitempty"`
	DurationSeconds int               `json:"duration_seconds,omitempty"`
}

// VerificationReport is a verify result's normalized report.
type VerificationReport struct {
	Passed          bool          `json:"passed"`
	Summary         string        `json:"summary,omitempty"`
	Format          string        `json:"format"`
	Tests           int           `json:"tests"`
	Failed          int           `json:"failed"`
	Skipped         int           `json:"skipped"`
	KnownFailures   int           `json:"known_failures"`
	Failures        []TestFailure `json:"failures"`
	ExitCode        int           `json:"exit_code"`
	DurationSeconds int           `json:"duration_seconds"`
}

// TestFailure is one failing test with its first error; Known when the pass
// rule let it through.
type TestFailure struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Known   bool   `json:"known"`
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
	// Outputs are what each component publishes for others to bind, by
	// component and output name, after apply, rollback or observe.
	Outputs      map[string]map[string]Output `json:"outputs,omitempty"`
	Verification *VerificationReport          `json:"verification,omitempty"`
	Failure      *Failure                     `json:"failure,omitempty"`
}

// Output is one published output. A sensitive output carries no value.
type Output struct {
	Value     json.RawMessage `json:"value,omitempty"`
	Sensitive bool            `json:"sensitive"`
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

// EventBody is a heartbeat, progress, log or observed event. Only watch
// writes observed events, one for each change it sees.
type EventBody struct {
	Type     string         `json:"type"` // heartbeat, progress, log, observed
	Message  string         `json:"message,omitempty"`
	Percent  *int           `json:"percent,omitempty"`
	Level    string         `json:"level,omitempty"` // log: debug, info, warn, error
	Observed *ObservedState `json:"observed,omitempty"`
}

// Manifest is what a kind declares it can do.
type Manifest struct {
	SchemaVersion        string                     `json:"schema_version"`
	Type                 string                     `json:"type"`
	Name                 string                     `json:"name"`
	Version              string                     `json:"version"`
	Description          string                     `json:"description,omitempty"`
	Role                 string                     `json:"role,omitempty"` // deployment (the default) or verification
	Operations           map[Operation]OperationDef `json:"operations"`
	Rollback             string                     `json:"rollback,omitempty"` // native, redeploy, none
	Strategies           []StrategyDef              `json:"strategies,omitempty"`
	DefaultStrategy      string                     `json:"default_strategy,omitempty"`
	TargetSettingsSchema json.RawMessage            `json:"target_settings_schema"`
	Connectors           Connectors                 `json:"connectors"`
	// Observation sets how often the pool observes a target of this kind and
	// when an observation is stale; absent members take the defaults.
	Observation *Observation `json:"observation,omitempty"`
}

// Kind roles.
const (
	RoleDeployment   = "deployment"
	RoleVerification = "verification"
)

// Verifies reports whether the kind runs verifications rather than deploying.
func (m *Manifest) Verifies() bool { return m.Role == RoleVerification }

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
// Named lists the types a target may bind beside them under an alias of its
// choosing; empty means the kind takes no named connectors.
type Connectors struct {
	Apply   []string `json:"apply"`
	Observe []string `json:"observe"`
	Named   []string `json:"named,omitempty"`
}

// Observation is a manifest's observation member.
type Observation struct {
	IntervalSeconds      *Intervals `json:"interval_seconds,omitempty"`
	DriftIntervalSeconds int        `json:"drift_interval_seconds,omitempty"`
	StaleAfterSeconds    int        `json:"stale_after_seconds,omitempty"`
}

// Intervals are the poll intervals while an execution is in flight and at
// rest.
type Intervals struct {
	Active int `json:"active,omitempty"`
	Rest   int `json:"rest,omitempty"`
}

// The platform's observation defaults (IMPL-279, IMPL-281), used for any
// member a manifest leaves out.
const (
	DefaultActiveInterval = 15 * time.Second
	DefaultRestInterval   = 300 * time.Second
	DefaultDriftInterval  = 3600 * time.Second
	DefaultStaleAfter     = 1200 * time.Second
)

// Schedule is a kind's effective observation schedule.
type Schedule struct {
	Active time.Duration `json:"active"`
	Rest   time.Duration `json:"rest"`
	// Drift is zero when the kind has no drift operation.
	Drift      time.Duration `json:"drift,omitempty"`
	StaleAfter time.Duration `json:"stale_after"`
	// Watch is true when the kind declares watch.
	Watch bool `json:"watch,omitempty"`
}

// Schedule returns the kind's observation schedule with defaults filled in.
func (m *Manifest) Schedule() Schedule {
	s := Schedule{Active: DefaultActiveInterval, Rest: DefaultRestInterval, StaleAfter: DefaultStaleAfter, Watch: m.Has(OpWatch)}
	if m.Has(OpDrift) {
		s.Drift = DefaultDriftInterval
	}
	if o := m.Observation; o != nil {
		if o.IntervalSeconds != nil && o.IntervalSeconds.Active > 0 {
			s.Active = time.Duration(o.IntervalSeconds.Active) * time.Second
		}
		if o.IntervalSeconds != nil && o.IntervalSeconds.Rest > 0 {
			s.Rest = time.Duration(o.IntervalSeconds.Rest) * time.Second
		}
		if o.DriftIntervalSeconds > 0 {
			s.Drift = time.Duration(o.DriftIntervalSeconds) * time.Second
		}
		if o.StaleAfterSeconds > 0 {
			s.StaleAfter = time.Duration(o.StaleAfterSeconds) * time.Second
		}
	}
	return s
}

// CheckSchedule reports what the schema cannot say about a schedule: an
// observation must be stale only after the next one at rest is due, and the
// active interval cannot be slower than the rest interval.
func (m *Manifest) CheckSchedule() error {
	s := m.Schedule()
	if s.StaleAfter <= s.Rest {
		return fmt.Errorf("kind %s: observations go stale after %s, which must be longer than the rest interval of %s", m.Ref(), s.StaleAfter, s.Rest)
	}
	if s.Active > s.Rest {
		return fmt.Errorf("kind %s: the active interval of %s is longer than the rest interval of %s", m.Ref(), s.Active, s.Rest)
	}
	return nil
}

// NoResultClass is how the runner classifies a run that ended without a valid
// result: nothing can have changed for an operation without side effects, and
// anything else may have left the target between versions.
func NoResultClass(op Operation) FailureClass {
	switch op {
	case OpValidate, OpPlan, OpObserve, OpWatch, OpDrift, OpVerify:
		return Retryable
	}
	return PartialChange
}
