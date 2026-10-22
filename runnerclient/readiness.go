package runnerclient

import (
	"context"
	"github.com/oyzuai/fleet/readiness"
)

func (c *Client) ReadinessSession(ctx context.Context, access, boot string) (readiness.Session, error) {
	var out readiness.Session
	err := c.do(ctx, "readiness/session", access, map[string]string{"boot_nonce": boot}, &out)
	return out, err
}

func (c *Client) ReadinessWork(ctx context.Context, access, session string) (readiness.Work, error) {
	var out readiness.Work
	err := c.do(ctx, "readiness/work", access, map[string]string{"session": session}, &out)
	return out, err
}

func (c *Client) ReadinessResult(ctx context.Context, access string, r readiness.Result) error {
	return c.do(ctx, "readiness/results", access, r, nil)
}

func (c *Client) ReadinessInvalidate(ctx context.Context, access, session string, generation int64) error {
	return c.do(ctx, "readiness/invalidate", access, struct {
		Session    string `json:"session"`
		Generation int64  `json:"generation"`
	}{session, generation}, nil)
}
