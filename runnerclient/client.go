// Package runnerclient calls the runs runner API: the pool manager uses it to
// enroll, log in, rotate its key, read its pool's demand, and claim and
// release jobs, and the job runner to start, heartbeat, fetch source and
// finish.
package runnerclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/telemetry"
)

var (
	// ErrUnauthenticated is a 401: the credential is unknown, expired, used
	// or revoked, or the job's lease is gone.
	ErrUnauthenticated = errors.New("runs refused the credential")
	// ErrKeyLimit is a 409 from key registration: two keys are already active.
	ErrKeyLimit = errors.New("the manager already has two active keys")
)

// clientAssertionType is the private_key_jwt assertion type (RFC 7523).
// MaxPlanRecord bounds the plan record a plan job reports. It matches the
// limit runs enforces (plan.MaxRecord in the platform).
const MaxPlanRecord = 4 << 20

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Client calls one runs server.
type Client struct {
	base string
	// prefix is the runner API's path, which a route name is relative to.
	prefix string
	http   *http.Client
}

// New returns a Client for the runs server at base, such as
// https://oyzu.example/ (the runner API is under runner/v1/).
func New(base string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := &Client{base: strings.TrimRight(base, "/") + "/runner/v1/", http: hc}
	if u, err := url.Parse(c.base); err == nil {
		c.prefix = u.Path
	}
	return c
}

// Enrolled is the manager an enrollment created or rekeyed.
type Enrolled struct {
	ManagerID int64  `json:"manager_id"`
	KeyID     int64  `json:"key_id"`
	Pool      string `json:"pool"`
	Name      string `json:"name"`
	Rekeyed   bool   `json:"rekeyed"`
}

// Enroll spends an enrollment or rekey token, registering pub.
func (c *Client) Enroll(ctx context.Context, token, name string, pub ed25519.PublicKey) (Enrolled, error) {
	var out Enrolled
	in := map[string]string{"token": token, "name": name, "public_key": assertion.EncodeKey(pub)}
	return out, c.do(ctx, "enroll", "", in, &out)
}

// AccessToken is a manager access token.
type AccessToken struct {
	Token   string
	Expires time.Time
}

// Login exchanges a login assertion for an access token.
func (c *Client) Login(ctx context.Context, signedAssertion string) (AccessToken, error) {
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {signedAssertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"token", strings.NewReader(form.Encode()))
	if err != nil {
		return AccessToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	start := time.Now()
	if err := c.send(req, &out); err != nil {
		return AccessToken{}, err
	}
	return AccessToken{Token: out.AccessToken, Expires: start.Add(time.Duration(out.ExpiresIn) * time.Second)}, nil
}

// RegisterKey sends a rotation request signed by the current key and
// returns the new key's id.
func (c *Client) RegisterKey(ctx context.Context, signedRotation string) (int64, error) {
	var out struct {
		KeyID int64 `json:"key_id"`
	}
	return out.KeyID, c.do(ctx, "keys", "", map[string]string{"assertion": signedRotation}, &out)
}

// Claim is a job claimed for this manager.
type Claim struct {
	// ExecutionTrustDecision is server-issued correlation metadata. It grants
	// no authority and must reach startup unchanged when present.
	ExecutionTrustDecision string    `json:"execution_trust_decision,omitempty"`
	JobID                  int64     `json:"job_id"`
	Attempt                int       `json:"attempt"`
	StartupToken           string    `json:"startup_token"`
	StartupExpires         time.Time `json:"startup_expires_at"`
	// Egress is where the job may connect, enforced by the manager's
	// gateway. A runs that predates it sends none, which allows only the
	// runs server.
	Egress    ClaimEgress        `json:"egress"`
	Readiness *readiness.Binding `json:"readiness,omitempty"`
}

// ClaimEgress is a job's network allow list.
type ClaimEgress struct {
	Allow []EgressAllow `json:"allow"`
}

// EgressAllow is one destination a job may reach: an exact host or
// "*.suffix", and a port, where 0 means 443.
type EgressAllow struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Claim takes the next job in the manager's pool, or returns nil when there
// is none.
func (c *Client) Claim(ctx context.Context, access string) (*Claim, error) {
	return c.ClaimSession(ctx, access, "")
}

func (c *Client) ClaimSession(ctx context.Context, access, session string) (*Claim, error) {
	var out Claim
	found := false
	err := c.doStatus(ctx, "claim", access, struct {
		Session string `json:"session,omitempty"`
	}{session}, &out, func(status int) { found = status == http.StatusOK })
	if err != nil || !found {
		return nil, err
	}
	if err := (StartupAssignment{ExecutionTrustDecision: out.ExecutionTrustDecision}).Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// Demand is the queued work a manager's pool could take.
type Demand struct {
	// Eligible counts queued jobs the pool may take, including those
	// waiting out a retry delay.
	Eligible int `json:"eligible"`
	// Ready counts those it could claim now.
	Ready int `json:"ready"`
}

// Demand reads the pool's eligible demand, which an autoscaling manager
// provisions executors for.
func (c *Client) Demand(ctx context.Context, access string) (Demand, error) {
	var out Demand
	return out, c.do(ctx, "demand", access, nil, &out)
}

// Report is what a manager tells runs about itself: the oyzu.io/ facts its
// driver discovered and its slots.
type Report struct {
	Facts    map[string]string   `json:"facts"`
	Slots    Slots               `json:"slots"`
	Session  string              `json:"session,omitempty"`
	Boundary *readiness.Boundary `json:"boundary,omitempty"`
}

// Slots counts a manager's executor slots.
type Slots struct {
	Max          int `json:"max"`
	Running      int `json:"running"`
	Ready        int `json:"ready"`
	Provisioning int `json:"provisioning"`
}

// Report sends the manager's facts and slots. Requirement matching uses the
// facts, and placement ranks managers by what they last reported.
func (c *Client) Report(ctx context.Context, access string, r Report) error {
	return c.do(ctx, "report", access, r, nil)
}

// Release hands back a claimed job whose executor ended.
type Release struct {
	JobID   int64  `json:"job_id"`
	Attempt int    `json:"attempt"`
	Reason  string `json:"reason"`
}

// Release hands a claimed job back. When its runner never started, runs
// requeues it without using an attempt, records the reason as an executor
// failure against the pool and reports true. When the runner had started,
// or the job is no longer this manager's, nothing changes and it reports
// false.
func (c *Client) Release(ctx context.Context, access string, r Release) (bool, error) {
	var out struct {
		Released bool `json:"released"`
	}
	return out.Released, c.do(ctx, "release", access, r, &out)
}

// Job is what a runner runs.
type Job struct {
	ExecutionConfig *ExecutionConfig `json:"execution_config,omitempty"`

	ID            int64    `json:"id"`
	RunID         int64    `json:"run_id"`
	Kind          string   `json:"kind"`
	Attempt       int      `json:"attempt"`
	CorrelationID string   `json:"correlation_id"`
	Repository    string   `json:"repository"`
	HeadSHA       string   `json:"head_sha,omitempty"`
	HeadBranch    string   `json:"head_branch"`
	CheckName     string   `json:"check_name"`
	Operation     string   `json:"operation"`
	Targets       []string `json:"targets"`
	Task          string   `json:"task"`
	AffectedBase  string   `json:"affected_base"`
	Mandatory     bool     `json:"mandatory"`
	Command       []string `json:"command"`
	// AdmittedPlan is the persisted native executable plan for a slice. It is
	// passed to Oyzu through bounded stdin, never rebuilt from command argv.
	AdmittedPlan json.RawMessage `json:"admitted_plan,omitempty"`
	// SliceTargets is the existing coupled group assigned to this job;
	// Handoff is its persisted upstream/result repository.
	SliceTargets []string `json:"slice_targets,omitempty"`
	Handoff      string   `json:"handoff,omitempty"`
	// Secrets are the build secret variables to pull before running.
	Secrets []string `json:"secrets"`
	// KindOperation is set on a kind job (Kind is KindOperation): the runner
	// runs this deployment kind operation instead of a command.
	KindOperation *KindOperation `json:"kind_operation,omitempty"`
}

// Started is a runner's job token and job.
type Started struct {
	JobToken         string    `json:"job_token"`
	Expires          time.Time `json:"expires_at"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	Job              Job       `json:"job"`
}

// StartupAssignment echoes only server-selected assignment metadata. The
// server still validates the exact current startup credential and attempt.
type StartupAssignment struct {
	Readiness              *readiness.Binding `json:"readiness,omitempty"`
	ExecutionTrustDecision string             `json:"execution_trust_decision,omitempty"`
}

var executionDecisionReference = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Validate checks wire shape only, never decision facts or current authority.
// An absent reference is meaningful only when the server did not require one.
func (a StartupAssignment) Validate() error {
	if a.ExecutionTrustDecision != "" && (!executionDecisionReference.MatchString(a.ExecutionTrustDecision) || a.ExecutionTrustDecision == "00000000-0000-0000-0000-000000000000") {
		return errors.New("invalid server execution decision reference")
	}
	return nil
}

// Start spends the startup token once, preserving the claimed assignment.
func (c *Client) Start(ctx context.Context, startup string, assignment StartupAssignment) (Started, error) {
	var out Started
	if err := assignment.Validate(); err != nil {
		return out, err
	}
	return out, c.do(ctx, "job/start", startup, assignment, &out)
}

// Heartbeat renews the job's lease and token.
func (c *Client) Heartbeat(ctx context.Context, job string) error {
	return c.do(ctx, "job/heartbeat", job, nil, nil)
}

// Source is a read-only token for the job's repository.
type Source struct {
	Kind       string    `json:"kind,omitempty"`
	URL        string    `json:"url,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	Token      string    `json:"token,omitempty"`
	Expires    time.Time `json:"expires_at,omitempty"`
	Repository string    `json:"repository,omitempty"`
}

// Source asks for the job's repository token.
func (c *Client) Source(ctx context.Context, job string) (Source, error) {
	var out Source
	return out, c.do(ctx, "job/source", job, nil, &out)
}

// DownloadSource uses the runner's configured control transport and proxy/trust
// settings, without sending its job bearer or following credential redirects.
func (c *Client) DownloadSource(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	hc := *c.http
	hc.Timeout = 15 * time.Minute
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return hc.Do(req)
}

// IDToken is an OIDC ID token naming the job, for one audience.
type IDToken struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires_at"`
}

// IDToken asks for an ID token bound to audience.
func (c *Client) IDToken(ctx context.Context, job, audience string) (IDToken, error) {
	var out IDToken
	return out, c.do(ctx, "job/id-token", job, map[string]string{"audience": audience}, &out)
}

// JobSecret is one build secret: an environment variable's value, or with
// File the contents of a file the variable will name.
type JobSecret struct {
	Variable string `json:"variable"`
	File     bool   `json:"file"`
	Value    []byte `json:"value"`
}

// Secrets pulls the job's build secrets.
func (c *Client) Secrets(ctx context.Context, job string) ([]JobSecret, error) {
	var out struct {
		Secrets []JobSecret `json:"secrets"`
	}
	return out.Secrets, c.do(ctx, "job/secrets", job, nil, &out)
}

// EgressGrant is a host the runner's egress proxy adds a credential to.
type EgressGrant struct {
	Host          string    `json:"host"`
	Authorization string    `json:"authorization"`
	Expires       time.Time `json:"expires_at"`
}

// Egress is what the job's egress proxy may add credentials to.
type Egress struct {
	Grants       []EgressGrant `json:"grants"`
	Repositories []string      `json:"repositories"`
}

// Egress asks for the job's egress grants, each minted for this call. A
// runs that predates them answers 404, which is no grants.
func (c *Client) Egress(ctx context.Context, job string) (Egress, error) {
	var out Egress
	err := c.do(ctx, "job/egress", job, nil, &out)
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return Egress{}, nil
	}
	return out, err
}

// WriteToken is a token that can write to the job's repository.
type WriteToken struct {
	Token      string    `json:"token"`
	Expires    time.Time `json:"expires_at"`
	Repository string    `json:"repository"`
	// Access is renovate or push.
	Access string `json:"access"`
}

// WriteToken asks for a token that can write to the job's repository. Runs
// gives one only to renovate and lock jobs.
func (c *Client) WriteToken(ctx context.Context, job string) (WriteToken, error) {
	var out WriteToken
	return out, c.do(ctx, "job/write-token", job, nil, &out)
}

// Outcome is how a job ended.
type Outcome struct {
	Execution *ExecutionEvidence `json:"execution,omitempty"`

	State    string `json:"state"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Summary  string `json:"summary"`
	// ReasonCode says why a job failed before oyzu exited, such as
	// SOURCE_UNAVAILABLE or RUNNER_ERROR.
	ReasonCode string `json:"reason_code,omitempty"`
	// Plan is what a plan job's command printed, sent when it succeeded.
	Plan json.RawMessage `json:"plan,omitempty"`
	// Outputs are what a succeeded build's manifest lists: the manifest
	// itself and every artifact, by digest (IMPL-450).
	Outputs []Output `json:"outputs,omitempty"`
	// TestFailures are bounded JUnit failures from this build's manifest,
	// including when the native build failed. At most 200 are sent, with
	// messages bounded to 1024 UTF-8 bytes.
	TestFailures []TestFailure `json:"test_failures,omitempty"`
}

// TestFailure is one JUnit failure or error associated with a target's test
// stage. Path and Line are optional checkout-relative source coordinates.
type TestFailure struct {
	Scope     string `json:"scope"`
	Name      string `json:"name"`
	Classname string `json:"classname,omitempty"`
	Path      string `json:"path,omitempty"`
	Line      int    `json:"line,omitempty"`
	Message   string `json:"message"`
}

// Output is one file a build wrote, as its build manifest records it. Target,
// Name and Version are set on artifacts only; OCIDigest on OCI images and
// indexes, the digest a registry addresses them by.
type Output struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Target    string `json:"target,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	OCIDigest string `json:"oci_digest,omitempty"`
}

// Finish reports the outcome. Only the log routes retain the token's
// authority during the server's 15-minute drain window.
func (c *Client) Finish(ctx context.Context, job string, o Outcome) error {
	return c.do(ctx, "job/finish", job, o, nil)
}

func (c *Client) do(ctx context.Context, path, bearer string, in, out any) error {
	return c.doStatus(ctx, path, bearer, in, out, nil)
}

func (c *Client) doStatus(ctx context.Context, path, bearer string, in, out any, status func(int)) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if path == "job/start" {
		req.Header.Set(ExecutionCapabilityHeader, "1")
	}
	return c.sendStatus(req, out, status)
}

func (c *Client) send(req *http.Request, out any) error { return c.sendStatus(req, out, nil) }

// sendStatus sends req and decodes a 2xx body into out.
func (c *Client) sendStatus(req *http.Request, out any, status func(int)) (err error) {
	req.Header.Set("Accept", "application/json")
	// Telemetry is optional and never changes the call: it records the route
	// (a fixed name, never the URL or a header), the outcome and the time, and
	// offers runs a trace parent to link to. Nothing it holds is a credential.
	route := telemetry.Route(strings.TrimPrefix(req.URL.Path, c.prefix))
	ctx, span := telemetry.Start(req.Context(), "fleet.client."+strings.NewReplacer("/", "_", "-", "_").Replace(route), telemetry.Client)
	start, code := time.Now(), 0
	defer func() {
		o, reason := telemetry.Classify(req.Context(), err, code, errors.Is(err, ErrUnauthenticated))
		telemetry.Request(route, o, reason, time.Since(start))
		span.Str("oyzu.fleet.route", route)
		if code != 0 {
			span.Int("http.response.status_code", int64(code))
		}
		span.End(o, reason)
		logDrain(route, o, reason)
	}()
	if span != nil {
		req = req.WithContext(ctx)
		telemetry.Inject(ctx, req.Header)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	code = resp.StatusCode
	if status != nil {
		status(resp.StatusCode)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthenticated
	case resp.StatusCode == http.StatusConflict && strings.HasSuffix(req.URL.Path, "/keys"):
		return ErrKeyLimit
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		var p struct {
			Detail  string `json:"detail"`
			NextSeq int64  `json:"next_seq"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = json.Unmarshal(raw, &p)
		return &StatusError{Status: resp.StatusCode, Detail: p.Detail, RetryAfter: resp.Header.Get("Retry-After"), NextSeq: p.NextSeq}
	case out == nil || resp.StatusCode == http.StatusNoContent:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// StatusError is any other non-2xx answer.
type StatusError struct {
	NextSeq    int64
	Status     int
	Detail     string
	RetryAfter string
}

func (e *StatusError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("runs answered %d", e.Status)
	}
	return fmt.Sprintf("runs answered %d: %s", e.Status, e.Detail)
}
