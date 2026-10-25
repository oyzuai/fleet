package runnerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/readiness"
)

const testExecutionDecision = "11111111-2222-4333-8444-555555555555"

// Actual HTTP client round trips; the server is a controlled contract fixture,
// not production authorization or native runtime qualification.
func TestExecutionDecisionClaimAndStartupEcho(t *testing.T) {
	ctx := context.Background()
	binding := &readiness.Binding{Challenge: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Session: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
		Generation: 3, Fingerprint: strings.Repeat("a", 64), Evidence: "cccccccc-dddd-4eee-8fff-111111111111", ValidUntil: time.Now().UTC().Add(time.Minute)}
	var starts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runner/v1/claim":
			_ = json.NewEncoder(w).Encode(Claim{JobID: 7, Attempt: 2, StartupToken: "once", StartupExpires: time.Now().Add(time.Minute), Readiness: binding, ExecutionTrustDecision: testExecutionDecision})
		case "/runner/v1/job/start":
			starts.Add(1)
			var in StartupAssignment
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || r.Header.Get("Authorization") != "Bearer once" || in.ExecutionTrustDecision != testExecutionDecision || in.Readiness == nil || *in.Readiness != *binding {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(Started{JobToken: "job", Job: Job{ID: 7}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := New(server.URL, nil)
	claim, err := client.ClaimSession(ctx, "manager", binding.Session)
	if err != nil || claim == nil || claim.ExecutionTrustDecision != testExecutionDecision {
		t.Fatalf("claim lost server decision: %v", err)
	}
	assignment := StartupAssignment{Readiness: claim.Readiness, ExecutionTrustDecision: claim.ExecutionTrustDecision}
	started, err := client.Start(ctx, claim.StartupToken, assignment)
	if err != nil || started.Job.ID != claim.JobID {
		t.Fatalf("bound startup did not echo assignment: %v", err)
	}
	for _, tc := range []struct{ name, token, reference string }{
		{"missing required reference", "once", ""},
		{"substituted reference", "once", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"},
		{"other attempt credential", "other-attempt", testExecutionDecision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := starts.Load()
			_, err := client.Start(ctx, tc.token, StartupAssignment{Readiness: binding, ExecutionTrustDecision: tc.reference})
			if !errors.Is(err, ErrUnauthenticated) || starts.Load() != before+1 {
				t.Fatalf("refused startup used a fallback or returned the wrong error: %v", err)
			}
		})
	}
}

func TestExecutionDecisionMalformedReferenceMakesNoStartupRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := New(server.URL, nil)
	for _, ref := range []string{"not-a-reference", "00000000-0000-0000-0000-000000000000", strings.Repeat("a", 4096)} {
		if _, err := client.Start(context.Background(), "once", StartupAssignment{ExecutionTrustDecision: ref}); err == nil {
			t.Fatal("malformed reference accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed reference spent a startup credential")
	}
}
