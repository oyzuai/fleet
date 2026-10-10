package runnerclient

import (
	"context"
	"encoding/json"
	"time"
)

// KindOperationJob is the Job kind of a kind job.
const KindOperationJob = "kind-operation"

// KindOperation is one deployment kind operation to run.
type KindOperation struct {
	RecordID string `json:"record_id"`
	Kind     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"kind"`
	// Image is the kind's pinned image; empty for a built-in kind.
	Image     string `json:"image,omitempty"`
	Operation string `json:"operation"`
	// Request is the protocol request for the kind's standard input.
	Request             json.RawMessage `json:"request"`
	TimeoutSeconds      int             `json:"timeout_seconds"`
	AbortTimeoutSeconds int             `json:"abort_timeout_seconds,omitempty"`
	// Secrets names the secrets to pull with KindSecrets.
	Secrets   []string `json:"secrets"`
	Placement string   `json:"placement,omitempty"`
}

// KindBeat is runs' answer to a kind job heartbeat.
type KindBeat struct {
	Expires time.Time `json:"expires_at"`
	// Cancel asks the runner to stop the kind.
	Cancel bool `json:"cancel"`
}

// KindHeartbeat renews a kind job's lease and token.
func (c *Client) KindHeartbeat(ctx context.Context, job string) (KindBeat, error) {
	var out KindBeat
	return out, c.do(ctx, "job/kind/heartbeat", job, nil, &out)
}

// KindEvent is one event the kind wrote, numbered in the order it was read.
type KindEvent struct {
	N       int       `json:"n"`
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Level   string    `json:"level,omitempty"`
	Message string    `json:"message,omitempty"`
	Percent *int      `json:"percent,omitempty"`
}

// KindEvents posts a batch of events; resending a batch is harmless.
func (c *Client) KindEvents(ctx context.Context, job string, events []KindEvent) error {
	return c.do(ctx, "job/kind/events", job, map[string]any{"events": events}, nil)
}

// KindSecret is a secret released for this run.
type KindSecret struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// KindSecrets pulls the secrets the request names, released for this run.
func (c *Client) KindSecrets(ctx context.Context, job string) ([]KindSecret, error) {
	var out struct {
		Secrets []KindSecret `json:"secrets"`
	}
	return out.Secrets, c.do(ctx, "job/kind/secrets", job, nil, &out)
}

// KindNoResult is sent in place of a result the kind did not give.
type KindNoResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Started bool   `json:"started"`
}

// KindFinish reports the kind's result, or why there is none; the job token
// stops working.
func (c *Client) KindFinish(ctx context.Context, job string, result json.RawMessage, none *KindNoResult) error {
	body := map[string]any{}
	if none != nil {
		body["no_result"] = none
	} else {
		body["result"] = result
	}
	return c.do(ctx, "job/kind/finish", job, body, nil)
}
