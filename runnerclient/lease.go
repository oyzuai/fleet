package runnerclient

import (
	"context"
	"errors"
	"time"
)

// WatchLease stops work at the last confirmed expiry, allowing for clock skew.
// Missing expiry values from older servers get at most three heartbeat intervals.
func WatchLease(ctx context.Context, every time.Duration, expires time.Time, beat func(context.Context) (time.Time, error), lost func(), warn func(error)) {
	if expires.IsZero() {
		expires = time.Now().Add(3 * every)
	}
	for {
		deadline := expires.Add(-min(time.Second, every/10))
		remaining := time.Until(deadline)
		if remaining <= 0 {
			lost()
			return
		}
		timer := time.NewTimer(min(every, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if !time.Now().Before(deadline) {
			lost()
			return
		}
		callCtx, cancel := context.WithDeadline(ctx, deadline)
		next, err := beat(callCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrUnauthenticated) || !time.Now().Before(deadline) {
			lost()
			return
		}
		if err != nil {
			warn(err)
			continue
		}
		if next.IsZero() {
			next = time.Now().Add(3 * every)
		}
		expires = next
	}
}

// HeartbeatLease renews the build lease and returns its confirmed expiry.
func (c *Client) HeartbeatLease(ctx context.Context, job string) (time.Time, error) {
	expires, _, err := c.HeartbeatStatus(ctx, job)
	return expires, err
}

// HeartbeatStatus renews the ordinary build attempt while carrying its stop
// request. Cancellation keeps finish authority alive for a stopped outcome.
func (c *Client) HeartbeatStatus(ctx context.Context, job string) (time.Time, bool, error) {
	var out struct {
		Expires time.Time `json:"expires_at"`
		Cancel  bool      `json:"cancel"`
	}
	err := c.do(ctx, "job/heartbeat", job, nil, &out)
	return out.Expires, out.Cancel, err
}
