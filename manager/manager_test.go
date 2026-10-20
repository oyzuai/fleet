package manager

import (
	"errors"
	"github.com/oyzuai/fleet/telemetry"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The manager's end-to-end tests run against the real runs service and its
// database, so they live with runs in the platform repository
// (backend/internal/runs/fleettest) and import this package.

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestProcessPassesOnlyAllowlistedEnvironment(t *testing.T) {
	p := &Process{Docker: true, ExtraEnv: []string{"BUILD_CACHE"}, environ: func() []string {
		return []string{"Path=C:\\bin", "HOME=/home/m", "OYZU_ENROLLMENT_TOKEN=secret", "AWS_SECRET_ACCESS_KEY=x",
			"BUILD_CACHE=/c", "GITHUB_TOKEN=ghp_x", "=C:=C:\\"}
	}}
	got := strings.Join(p.env(), " ")
	if got != `Path=C:\bin HOME=/home/m BUILD_CACHE=/c` {
		t.Fatalf("env = %s", got)
	}
}

func TestStateAndKeysRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load before enrollment = %v", err)
	}
	k, priv, err := s.NewKey(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	k.ID = 3
	if err := s.Save(&State{ManagerID: 1, Current: k}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil || st.Current.ID != 3 {
		t.Fatalf("Load = %+v, %v", st, err)
	}
	back, err := s.PrivateKey(st.Current)
	if err != nil || !back.Equal(priv) {
		t.Fatalf("key round trip: %v", err)
	}
	if err := s.Remove(k); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, k.File)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key file not removed")
	}
}

// Invariant (FLEET-AUTH-05): a telemetry setting reaches an executor only
// through Process.Telemetry, never through the pass-through list, and what
// the executor gets carries the endpoint and trace parent but no credential.
func TestProcessHandsTelemetryToTheExecutorOnly(t *testing.T) {
	p := &Process{Docker: true, ExtraEnv: []string{"OYZU_OTEL_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "TRACEPARENT", "BUILD_CACHE"},
		Telemetry: telemetry.Config{Enabled: true, Endpoint: "http://collector:4318", Environment: "proof", Version: "v1"},
		environ: func() []string {
			return []string{"HOME=/h", "OYZU_OTEL_ENDPOINT=http://elsewhere:1", "OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer x", "TRACEPARENT=00-aa", "BUILD_CACHE=/c"}
		}}
	if got := strings.Join(p.env(), " "); got != "HOME=/h BUILD_CACHE=/c" {
		t.Fatalf("env = %s", got)
	}
	parent := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	got := strings.Join(p.Telemetry.Env(parent), " ")
	for _, want := range []string{"OYZU_OTEL_ENABLED=true", "OYZU_OTEL_ENDPOINT=http://collector:4318", "TRACEPARENT=" + parent} {
		if !strings.Contains(got, want) {
			t.Errorf("executor telemetry env lacks %s: %s", want, got)
		}
	}
	if strings.Contains(strings.ToLower(got), "bearer") || strings.Contains(got, "authorization") {
		t.Fatalf("a credential is in the executor's telemetry env: %s", got)
	}
	if env := (telemetry.Config{}).Env(parent); env != nil {
		t.Fatalf("disabled telemetry still sets %v", env)
	}
}
