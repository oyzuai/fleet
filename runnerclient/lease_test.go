package runnerclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeartbeatStatusCarriesCancellationWithoutLosingLease(t *testing.T) {
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runner/v1/job/heartbeat" || r.Header.Get("Authorization") != "Bearer current-attempt" {
			t.Errorf("heartbeat contract: %s", r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cancel":true,"expires_at":"` + expires.Format(time.RFC3339) + `"}`))
	}))
	defer server.Close()
	client := New(server.URL, server.Client())
	got, cancel, err := client.HeartbeatStatus(context.Background(), "current-attempt")
	if err != nil || !cancel || !got.Equal(expires) {
		t.Fatalf("heartbeat directive: %v %v %v", got, cancel, err)
	}
	got, err = client.HeartbeatLease(context.Background(), "current-attempt")
	if err != nil || !got.Equal(expires) {
		t.Fatalf("expiry-only wrapper changed: %v %v", got, err)
	}
}

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
