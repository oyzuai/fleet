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
	"strings"
	"time"

	"github.com/oyzuai/fleet/assertion"
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
	http *http.Client
}

// New returns a Client for the runs server at base, such as
// https://oyzu.example/ (the runner API is under runner/v1/).
func New(base string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/") + "/runner/v1/", http: hc}
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
	JobID          int64     `json:"job_id"`
	Attempt        int       `json:"attempt"`
	StartupToken   string    `json:"startup_token"`
	StartupExpires time.Time `json:"startup_expires_at"`
}

// Claim takes the next job in the manager's pool, or returns nil when there
// is none.
func (c *Client) Claim(ctx context.Context, access string) (*Claim, error) {
	var out Claim
	found := false
	err := c.doStatus(ctx, "claim", access, nil, &out, func(status int) { found = status == http.StatusOK })
	if err != nil || !found {
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
	Facts map[string]string `json:"facts"`
	Slots Slots             `json:"slots"`
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
}

// Started is a runner's job token and job.
type Started struct {
	JobToken         string    `json:"job_token"`
	Expires          time.Time `json:"expires_at"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	Job              Job       `json:"job"`
}

// Start spends the startup token.
func (c *Client) Start(ctx context.Context, startup string) (Started, error) {
	var out Started
	return out, c.do(ctx, "job/start", startup, nil, &out)
}

// Heartbeat renews the job's lease and token.
func (c *Client) Heartbeat(ctx context.Context, job string) error {
	return c.do(ctx, "job/heartbeat", job, nil, nil)
}

// Source is a read-only token for the job's repository.
type Source struct {
	Token      string    `json:"token"`
	Expires    time.Time `json:"expires_at"`
	Repository string    `json:"repository"`
}

// Source asks for the job's repository token.
func (c *Client) Source(ctx context.Context, job string) (Source, error) {
	var out Source
	return out, c.do(ctx, "job/source", job, nil, &out)
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
	State    string `json:"state"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Summary  string `json:"summary"`
	// Plan is what a plan job's command printed, sent when it succeeded.
	Plan json.RawMessage `json:"plan,omitempty"`
}

// Finish reports the outcome; the job token stops working.
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
	return c.sendStatus(req, out, status)
}

func (c *Client) send(req *http.Request, out any) error { return c.sendStatus(req, out, nil) }

// sendStatus sends req and decodes a 2xx body into out.
func (c *Client) sendStatus(req *http.Request, out any, status func(int)) error {
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
			Detail string `json:"detail"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = json.Unmarshal(raw, &p)
		return &StatusError{Status: resp.StatusCode, Detail: p.Detail, RetryAfter: resp.Header.Get("Retry-After")}
	case out == nil || resp.StatusCode == http.StatusNoContent:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// StatusError is any other non-2xx answer.
type StatusError struct {
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
