package runnerclient

import (
	"context"
	"time"
)

// KindConnectorSecret is one secret setting of a connector, released for
// this attempt.
type KindConnectorSecret struct {
	Field string `json:"field"`
	Value []byte `json:"value"`
}

// KindConnector is one of the target's connectors, with its credentials for
// this attempt.
type KindConnector struct {
	Role           string                `json:"role"`
	Alias          string                `json:"alias,omitempty"`
	Identifier     string                `json:"identifier"`
	Kind           string                `json:"kind"`
	Mechanism      string                `json:"mechanism"`
	Settings       map[string]any        `json:"settings"`
	Parameters     map[string]any        `json:"parameters"`
	Secrets        []KindConnectorSecret `json:"secrets"`
	IDToken        string                `json:"id_token,omitempty"`
	IDTokenExpires *time.Time            `json:"id_token_expires_at,omitempty"`
}

// KindConnectors are the target's connectors for this attempt.
type KindConnectors struct {
	Target     string          `json:"target"`
	Grant      string          `json:"grant,omitempty"`
	Connectors []KindConnector `json:"connectors"`
}

// KindConnectors pulls the target's connectors, released for this attempt.
func (c *Client) KindConnectors(ctx context.Context, job string) (KindConnectors, error) {
	var out KindConnectors
	return out, c.do(ctx, "job/kind/connectors", job, nil, &out)
}
