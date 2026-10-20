package runnerclient

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/telemetry"
)

type sink struct {
	mu   sync.Mutex
	body strings.Builder
}

func (s *sink) text() string { s.mu.Lock(); defer s.mu.Unlock(); return s.body.String() }

func collector(t *testing.T) (*sink, *httptest.Server) {
	t.Helper()
	s := &sink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.body.Write(b)
		s.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

func provider(t *testing.T, endpoint string) *telemetry.Provider {
	t.Helper()
	return telemetry.Setup(telemetry.Config{Enabled: true, Endpoint: endpoint, Service: "oyzu-test", Environment: "t", Version: "v", Instance: "i"}, slog.New(slog.DiscardHandler))
}

func flush(p *telemetry.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Shutdown(ctx)
}

// Invariant: telemetry records the route, outcome and timing of runner calls
// and sends runs a trace parent, but no bearer, startup token or body ever
// reaches the Collector; a refusal is a challenge, not a fault.
func TestClientTelemetryCarriesNoCredential(t *testing.T) {
	const bearer = "oyzu_job_SECRETSECRETSECRET"
	var gotParent, gotAuth string
	runs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotParent, gotAuth = r.Header.Get("traceparent"), r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/job/finish") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"expires_at":"2030-01-01T00:00:00Z","cancel":false}`)
	}))
	defer runs.Close()
	s, col := collector(t)
	p := provider(t, col.URL)
	c := New(runs.URL, nil)
	ctx, span := telemetry.Start(context.Background(), "fleet.executor.job", telemetry.Internal)
	if _, _, err := c.HeartbeatStatus(ctx, bearer); err != nil {
		t.Fatal(err)
	}
	if gotParent == "" || gotParent != "" && !strings.HasPrefix(gotParent, "00-") {
		t.Fatalf("traceparent = %q", gotParent)
	}
	if gotAuth != "Bearer "+bearer {
		t.Fatalf("the call itself lost its bearer: %q", gotAuth)
	}
	if err := c.Finish(ctx, bearer, Outcome{State: "succeeded", Summary: "build output that must not leave"}); err != ErrUnauthenticated {
		t.Fatalf("finish = %v", err)
	}
	span.End(telemetry.Success, "")
	flush(p)
	all := s.text()
	for _, want := range []string{"fleet.client.job_heartbeat", "fleet.client.job_finish", telemetry.NameRequests, `"challenge"`, `"refused"`} {
		if !strings.Contains(all, want) {
			t.Errorf("telemetry lacks %s: %s", want, all)
		}
	}
	for _, leak := range []string{bearer, "SECRETSECRET", "build output", "Bearer", runs.URL, "127.0.0.1"} {
		if strings.Contains(all, leak) {
			t.Fatalf("telemetry leaks %q: %s", leak, all)
		}
	}
}

// Invariant (FLEET-AUTH-05): a hanging or dead Collector does not slow, fail or
// delay a lease renewal, and renewals keep extending the lease.
func TestCollectorOutageDoesNotBlockRenewal(t *testing.T) {
	var beats int
	var mu sync.Mutex
	runs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		beats++
		mu.Unlock()
		_, _ = io.WriteString(w, `{"expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer runs.Close()
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer hang.Close()
	defer close(release)
	p := provider(t, hang.URL)
	c := New(runs.URL, nil)
	start := time.Now()
	for range 300 {
		exp, err := c.HeartbeatLease(context.Background(), "oyzu_job_x")
		if err != nil || exp.IsZero() {
			t.Fatalf("renewal failed with the Collector hanging: %v", err)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("300 renewals took %s with the Collector hanging", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if beats != 300 {
		t.Fatalf("runs saw %d renewals", beats)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.Shutdown(ctx)
}
