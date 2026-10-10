package runnerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	// Connectors names the connector roles to pull with KindConnectors.
	Connectors []string `json:"connectors,omitempty"`
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

// planDigestHeader names the plan a plan file belongs to.
const planDigestHeader = "Oyzu-Plan-Digest"

// maxPlanFile bounds a fetched plan file.
const maxPlanFile = 64 << 20

// KindPlanFileSave sends the plan file a plan job's kind saved for the plan
// with digest, before the job finishes (IMPL-401).
func (c *Client) KindPlanFileSave(ctx context.Context, job, digest string, file []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"job/kind/plan-file", bytes.NewReader(file))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(planDigestHeader, digest)
	req.Header.Set("Authorization", "Bearer "+job)
	return c.send(req, nil)
}

// KindPlanFile fetches the plan file of the plan an apply job applies.
// found is false when runs keeps none.
func (c *Client) KindPlanFile(ctx context.Context, job string) (file []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"job/kind/plan-file/fetch", nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+job)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, false, ErrUnauthenticated
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	case resp.StatusCode != http.StatusOK:
		var p struct {
			Detail string `json:"detail"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = json.Unmarshal(raw, &p)
		return nil, false, &StatusError{Status: resp.StatusCode, Detail: p.Detail, RetryAfter: resp.Header.Get("Retry-After")}
	}
	file, err = io.ReadAll(io.LimitReader(resp.Body, maxPlanFile+1))
	if err != nil {
		return nil, false, err
	}
	if len(file) > maxPlanFile {
		return nil, false, fmt.Errorf("the plan file is larger than %d bytes", maxPlanFile)
	}
	return file, true, nil
}
