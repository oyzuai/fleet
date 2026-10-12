package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// fakeRuns serves the runner API calls the manager loop makes: it hands out
// claims, takes reports and records releases.
type fakeRuns struct {
	mu       sync.Mutex
	claims   []runnerclient.Claim
	releases []runnerclient.Release
}

func (f *fakeRuns) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(r.URL.Path, "/runner/v1/") {
		case "token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "claim":
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.claims) == 0 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			c := f.claims[0]
			f.claims = f.claims[1:]
			_ = json.NewEncoder(w).Encode(c)
		case "demand":
			_, _ = w.Write([]byte(`{"eligible":0,"ready":0}`))
		case "report":
			w.WriteHeader(http.StatusNoContent)
		case "release":
			var rel runnerclient.Release
			_ = json.NewDecoder(r.Body).Decode(&rel)
			f.mu.Lock()
			f.releases = append(f.releases, rel)
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"released":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// hungDriver is a driver whose engine never answers: Start and Teardown
// block until their context ends.
type hungDriver struct {
	slots           int
	startCalls      atomic.Int32
	startEnded      chan struct{}
	teardownBounded atomic.Bool
	teardownEnded   chan struct{}
}

func (d *hungDriver) Facts(context.Context) (Facts, error) { return Facts{}, nil }

func (d *hungDriver) Capacity(context.Context) (Capacity, error) {
	c := Capacity{Max: d.slots}
	for i := range d.slots {
		c.Ready = append(c.Ready, SlotID(string(rune('0'+i))))
	}
	return c, nil
}

func (d *hungDriver) Provision(context.Context, int) error { return nil }

func (d *hungDriver) Start(ctx context.Context, slot SlotID, c runnerclient.Claim) (Handle, error) {
	d.startCalls.Add(1)
	<-ctx.Done()
	close(d.startEnded)
	return Handle{Slot: slot, Job: c.JobID, Attempt: c.Attempt, Ref: "ref"}, ctx.Err()
}

func (d *hungDriver) Wait(ctx context.Context, _ Handle) (Exit, error) {
	<-ctx.Done()
	return Exit{}, ctx.Err()
}

func (d *hungDriver) Teardown(ctx context.Context, _ Handle) error {
	_, ok := ctx.Deadline()
	d.teardownBounded.Store(ok)
	<-ctx.Done()
	close(d.teardownEnded)
	return ctx.Err()
}

func (d *hungDriver) Reap(context.Context, []JobID) error { return nil }

func openTestManager(t *testing.T, runs *httptest.Server, d Driver, cfg Config) *Manager {
	t.Helper()
	s := Store{Dir: t.TempDir()}
	k, _, err := s.NewKey(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	k.ID = 1
	if err := s.Save(&State{Server: runs.URL, Audience: "oyzu-runs", ManagerID: 7, Pool: "p", Current: k}); err != nil {
		t.Fatal(err)
	}
	cfg.Client, cfg.Store, cfg.Driver, cfg.Log = runnerclient.New(runs.URL, nil), s, d, quiet()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	m, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A hung engine must not keep the manager from stopping: Start runs off the
// claim loop and ends with the drain timeout, and teardown has its own bound.
func TestRunStopsWhileTheEngineHangs(t *testing.T) {
	runs := &fakeRuns{claims: []runnerclient.Claim{{JobID: 42, Attempt: 1, StartupToken: "st",
		StartupExpires: time.Now().Add(time.Hour)}}}
	srv := runs.server(t)
	d := &hungDriver{slots: 2, startEnded: make(chan struct{}), teardownEnded: make(chan struct{})}
	m := openTestManager(t, srv, d, Config{DrainTimeout: 50 * time.Millisecond, TeardownTimeout: 50 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for d.startCalls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("the job was never started")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// The claim loop is still turning while Start hangs: the starting slot
	// is not offered again, and the other slot stays ready.
	time.Sleep(50 * time.Millisecond)
	if n := d.startCalls.Load(); n != 1 {
		t.Fatalf("Start called %d times", n)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return while the engine hung")
	}
	<-d.startEnded
	<-d.teardownEnded
	if !d.teardownBounded.Load() {
		t.Fatal("teardown ran without a deadline")
	}
	runs.mu.Lock()
	defer runs.mu.Unlock()
	if len(runs.releases) != 1 || runs.releases[0].JobID != 42 || !strings.Contains(runs.releases[0].Reason, "did not start") {
		t.Fatalf("releases = %+v", runs.releases)
	}
}

func TestStartingSlotsAreNotReady(t *testing.T) {
	m := &Manager{}
	m.markStarting("1", true)
	c := m.withoutStarting(Capacity{Max: 3, Running: 1, Ready: []SlotID{"1", "2"}})
	if c.Running != 2 || len(c.Ready) != 1 || c.Ready[0] != "2" {
		t.Fatalf("capacity = %+v", c)
	}
	m.markStarting("1", false)
	if c := m.withoutStarting(Capacity{Ready: []SlotID{"1"}}); len(c.Ready) != 1 {
		t.Fatalf("capacity after start = %+v", c)
	}
}

func TestStartTimeoutFollowsTheStartupExpiry(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		expires time.Time
		want    time.Duration
	}{
		{time.Time{}, defaultStartTimeout},
		{now.Add(3 * time.Minute), 3 * time.Minute},
		{now.Add(time.Hour), defaultStartTimeout},
		{now.Add(-time.Hour), time.Minute}, // clocks disagree
	} {
		if got := startTimeout(now, runnerclient.Claim{StartupExpires: tc.expires}); got != tc.want {
			t.Errorf("startTimeout(%v) = %s, want %s", tc.expires.Sub(now), got, tc.want)
		}
	}
}
