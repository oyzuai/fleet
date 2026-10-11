package runnerclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLeaseExpiryBoundsStalledHeartbeat(t *testing.T) {
	start := time.Now()
	lost := false
	WatchLease(context.Background(), 10*time.Millisecond, start.Add(100*time.Millisecond),
		func(ctx context.Context) (time.Time, error) { <-ctx.Done(); return time.Time{}, ctx.Err() },
		func() { lost = true }, func(error) {})
	if !lost || time.Since(start) > time.Second {
		t.Fatal("stalled heartbeat outlived lease")
	}
}

func TestLeaseRenewalExtendsConfirmedExpiry(t *testing.T) {
	start := time.Now()
	calls := 0
	WatchLease(context.Background(), 10*time.Millisecond, start.Add(50*time.Millisecond),
		func(ctx context.Context) (time.Time, error) {
			calls++
			if calls == 1 {
				return time.Now().Add(150 * time.Millisecond), nil
			}
			return time.Time{}, errors.New("partition")
		}, func() {}, func(error) {})
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond || elapsed > time.Second {
		t.Fatal(elapsed)
	}
}

func TestPlanUploadRejectsOversizedArchive(t *testing.T) {
	c := New("http://unused.invalid", nil)
	if err := c.KindPlanFileSave(context.Background(), "token", "digest", make([]byte, maxPlanFile+1)); err == nil {
		t.Fatal("oversized plan archive accepted")
	} else if err.Error() != "the plan file is larger than 67108864 bytes" {
		t.Fatal(err)
	}
}
