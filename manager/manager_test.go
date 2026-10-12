package manager

import (
	"errors"
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
