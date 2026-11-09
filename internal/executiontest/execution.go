// Package executiontest checks the runner launch contract used by driver fakes.
package executiontest

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oyzuai/fleet/executor"
	"github.com/oyzuai/fleet/runnerclient"
)

// RefuseMissingTrust maps a fake driver's work volume and token into local
// files, then executes its actual runner arguments against a job/start server.
// No source tool or consumer may run when a required bundle is unavailable.
func RefuseMissingTrust(t *testing.T, args []string, token string) {
	t.Helper()
	finished := make(chan runnerclient.Outcome, 1)
	config := &runnerclient.ExecutionConfig{Version: 1, Revision: "driver-test", Required: true,
		Bundles: []runnerclient.ExecutionCABundle{{Digest: strings.Repeat("a", 64), Required: true}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/job/start"):
			if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get(runnerclient.ExecutionCapabilityHeader) != "1" {
				t.Error("driver launch lost startup authority or execution capability")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(runnerclient.Started{JobToken: "job-test", HeartbeatSeconds: 3600,
				Job: runnerclient.Job{ID: 1, Attempt: 1, ExecutionConfig: config}})
		case strings.HasSuffix(r.URL.Path, "/job/finish"):
			var got runnerclient.Outcome
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
			}
			finished <- got
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("required trust failure made an unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	work := filepath.Join(t.TempDir(), "work")
	tokenFile := filepath.Join(t.TempDir(), "startup")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append([]string{}, args...)
	hasServer, hasWork, hasToken := false, false, false
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--server":
			args[i+1], hasServer = server.URL, true
		case "--work-dir":
			args[i+1], hasWork = work, true
		case "--startup-token-file":
			args[i+1], hasToken = tokenFile, true
		case "--startup-token-env":
			t.Setenv(args[i+1], token)
			hasToken = true
		}
	}
	if !hasServer || !hasWork || !hasToken {
		t.Fatal("driver did not pass the executor's server, workspace and startup authority")
	}
	if err := executor.Command(args, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-finished:
		if outcome.ReasonCode != "TRUST_BUNDLE_UNAVAILABLE" || outcome.Execution == nil || outcome.Execution.Revision != config.Revision {
			t.Fatalf("driver execution outcome = %+v", outcome)
		}
	default:
		t.Fatal("driver execution did not finish")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("missing required trust created a workspace or launched a consumer", err)
	}
}
