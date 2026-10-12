package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

// fakeCloud is an in-memory provider. Each instance gets the address
// 10.0.0.<n>; a proof's document is simply the instance id, and its
// signature must be "signed".
type fakeCloud struct {
	mu        sync.Mutex
	next      int
	instances map[string]*Instance
	image     map[string]string
	destroyed []string
	createErr error
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{instances: map[string]*Instance{}, image: map[string]string{}}
}

func (f *fakeCloud) Create(_ context.Context, spec Spec, tags map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return "", f.createErr
	}
	f.next++
	id := fmt.Sprintf("i-%d", f.next)
	t := map[string]string{}
	for k, v := range tags {
		t[k] = v
	}
	f.instances[id] = &Instance{ID: id, State: StateRunning, Address: fmt.Sprintf("10.0.0.%d", f.next),
		Launched: time.Unix(0, 0), Tags: t}
	f.image[id] = spec.Image
	return id, nil
}

func (f *fakeCloud) Describe(_ context.Context, ids []string) (map[string]Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]Instance{}
	for _, id := range ids {
		if inst, ok := f.instances[id]; ok {
			out[id] = *inst
		}
	}
	return out, nil
}

func (f *fakeCloud) List(_ context.Context, manager string) ([]Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Instance
	for _, inst := range f.instances {
		if inst.Tags[TagManager] == manager && inst.State != StateGone {
			out = append(out, *inst)
		}
	}
	return out, nil
}

func (f *fakeCloud) Tag(_ context.Context, id string, tags map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst, ok := f.instances[id]
	if !ok {
		return errors.New("no such instance")
	}
	for k, v := range tags {
		inst.Tags[k] = v
	}
	return nil
}

func (f *fakeCloud) Destroy(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if inst, ok := f.instances[id]; ok {
		inst.State = StateGone
	}
	f.destroyed = append(f.destroyed, id)
	return nil
}

func (f *fakeCloud) VerifyIdentity(_ context.Context, p Proof) (Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if string(p.Signature) != "signed" {
		return Identity{}, errors.New("bad signature")
	}
	id := string(p.Document)
	if _, ok := f.instances[id]; !ok {
		return Identity{}, errors.New("no such instance")
	}
	return Identity{InstanceID: id, Image: f.image[id]}, nil
}

func (f *fakeCloud) Facts(context.Context, Spec) (manager.Facts, error) {
	return manager.Facts{manager.FactArch: "amd64", manager.FactCPU: "8"}, nil
}

func (f *fakeCloud) set(id string, change func(*Instance)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.instances[id])
}

func (f *fakeCloud) address(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.instances[id].Address
}

func (f *fakeCloud) wasDestroyed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.destroyed {
		if d == id {
			return true
		}
	}
	return false
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newDriver(cloud *fakeCloud, warm, maxN int) (*Driver, *clock) {
	c := &clock{now: time.Unix(1_000_000, 0)}
	return &Driver{
		Cloud: cloud, Spec: Spec{Image: "ami-executor", Shape: "c7i.2xlarge"},
		Pool: "vms", Manager: 7, Warm: warm, Max: maxN,
		PollInterval: time.Millisecond, Now: c.Now,
	}, c
}

func proof(id string) Proof { return Proof{Document: []byte(id), Signature: []byte("signed")} }

// capacity reads capacity and waits for any boots it started.
func capacity(t *testing.T, d *Driver) manager.Capacity {
	t.Helper()
	c, err := d.Capacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d.creating.Wait()
	return c
}

// bootAll checks every booting instance in, from its own address.
func bootAll(t *testing.T, d *Driver, cloud *fakeCloud) {
	t.Helper()
	d.mu.Lock()
	var ids []string
	for id, m := range d.machines {
		if m.phase == booting {
			ids = append(ids, id)
		}
	}
	d.mu.Unlock()
	for _, id := range ids {
		if err := d.checkIn(context.Background(), proof(id), cloud.address(id)+":5000"); err != nil {
			t.Fatalf("check in %s: %v", id, err)
		}
	}
}

func claim(job int64) runnerclient.Claim {
	return runnerclient.Claim{JobID: job, Attempt: 1, StartupToken: "startup-" + strconv.FormatInt(job, 10),
		StartupExpires: time.Unix(1_000_000, 0).Add(5 * time.Minute)}
}

func TestWarmPoolBootsAndBecomesReady(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 2, 5)
	c := capacity(t, d)
	if len(c.Ready) != 0 {
		t.Fatalf("ready before any boot: %v", c.Ready)
	}
	c = capacity(t, d)
	if c.Provisioning != 2 || c.Max != 5 {
		t.Fatalf("want 2 booting of max 5, got %+v", c)
	}
	bootAll(t, d, cloud)
	c = capacity(t, d)
	if len(c.Ready) != 2 || c.Provisioning != 0 {
		t.Fatalf("want 2 ready, got %+v", c)
	}
	if got := cloud.instances["i-1"].Tags; got[TagPool] != "vms" || got[TagManager] != "7" {
		t.Fatalf("instance tags: %v", got)
	}
}

func TestProvisionStopsAtMax(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 0, 3)
	if err := d.Provision(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	d.creating.Wait()
	if err := d.Provision(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	d.creating.Wait()
	if c := capacity(t, d); c.Provisioning != 3 || c.Room() != 0 {
		t.Fatalf("want 3 booting and no room, got %+v", c)
	}
}

func TestStartHandsTheTokenOnlyToTheAssignedInstanceOnce(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 2, 2)
	capacity(t, d)
	bootAll(t, d, cloud)
	c := capacity(t, d)
	slot := c.Ready[0]
	other := string(c.Ready[1])
	h, err := d.Start(context.Background(), slot, claim(41))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ref != string(slot) || cloud.instances[h.Ref].Tags[TagJob] != "41" {
		t.Fatalf("handle %+v, tags %v", h, cloud.instances[h.Ref].Tags)
	}
	ctx := context.Background()
	// Another instance has no job.
	if got, err := d.assignment(ctx, proof(other), cloud.address(other)+":1", time.Millisecond); err != nil || got != nil {
		t.Fatalf("other instance got %v, %v", got, err)
	}
	// The right document from the wrong address is refused.
	if _, err := d.assignment(ctx, proof(h.Ref), "10.9.9.9:1", time.Millisecond); !errors.Is(err, ErrWrongAddress) {
		t.Fatalf("wrong address: %v", err)
	}
	got, err := d.assignment(ctx, proof(h.Ref), cloud.address(h.Ref)+":1", time.Millisecond)
	if err != nil || got == nil || got.StartupToken != "startup-41" {
		t.Fatalf("assignment: %v, %v", got, err)
	}
	// The response can be lost, so the same instance may collect again
	// until it acknowledges; another instance still cannot.
	if got, err := d.assignment(ctx, proof(h.Ref), cloud.address(h.Ref)+":1", time.Millisecond); err != nil || got.StartupToken != "startup-41" {
		t.Fatalf("re-collection: %v, %v", got, err)
	}
	if err := d.acknowledge(ctx, proof(other), cloud.address(other)+":1"); !errors.Is(err, ErrNotAssigned) {
		t.Fatalf("acknowledging another instance: %v", err)
	}
	if err := d.acknowledge(ctx, proof(h.Ref), cloud.address(h.Ref)+":1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.assignment(ctx, proof(h.Ref), cloud.address(h.Ref)+":1", time.Millisecond); !errors.Is(err, ErrAlreadyHanded) {
		t.Fatalf("collection after the acknowledgement: %v", err)
	}
}

// An instance that collected its token but whose acknowledgement never
// arrives holds its slot only until the token and a lease after it are
// spent.
func TestUnacknowledgedAssignmentIsLostAfterTheLease(t *testing.T) {
	cloud := newFakeCloud()
	d, clk := newDriver(cloud, 1, 1)
	capacity(t, d)
	bootAll(t, d, cloud)
	h, err := d.Start(context.Background(), capacity(t, d).Ready[0], claim(12))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.assignment(context.Background(), proof(h.Ref), cloud.address(h.Ref)+":1", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	m := d.machines[h.Ref]
	clk.advance(6 * time.Minute) // past the token's expiry, within the lease
	if _, done := d.check(context.Background(), m); done {
		t.Fatal("failed an instance still within its lease")
	}
	clk.advance(5 * time.Minute)
	exit, done := d.check(context.Background(), m)
	if !done || exit.Reason != manager.ExitLost || !strings.Contains(exit.Detail, "never acknowledged") {
		t.Fatalf("check = %+v, %v", exit, done)
	}
}

func TestStartRefusesASlotThatIsNotReady(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	h, err := d.Start(context.Background(), "i-1", claim(1))
	if err == nil || h.Ref != "" {
		t.Fatalf("started a booting instance: %+v, %v", h, err)
	}
}

func TestWaitReportsTheAgentsExitAndTeardownDestroys(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	bootAll(t, d, cloud)
	h, err := d.Start(context.Background(), capacity(t, d).Ready[0], claim(5))
	if err != nil {
		t.Fatal(err)
	}
	addr := cloud.address(h.Ref) + ":1"
	if err := d.reportExit(context.Background(), proof(h.Ref), addr, 0, ""); !errors.Is(err, ErrNotAssigned) {
		t.Fatalf("exit before collecting the token: %v", err)
	}
	if _, err := d.assignment(context.Background(), proof(h.Ref), addr, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := d.reportExit(context.Background(), proof(h.Ref), addr, 3, "tests failed"); err != nil {
		t.Fatal(err)
	}
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Reason != manager.ExitExited || exit.Code != 3 {
		t.Fatalf("exit %+v, %v", exit, err)
	}
	if err := d.Teardown(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if !cloud.wasDestroyed(h.Ref) {
		t.Fatal("instance not destroyed after its job")
	}
	if _, err := d.assignment(context.Background(), proof(h.Ref), addr, time.Millisecond); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("a torn-down instance was still served: %v", err)
	}
}

func TestSpotReclaimIsLost(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	bootAll(t, d, cloud)
	h, err := d.Start(context.Background(), capacity(t, d).Ready[0], claim(9))
	if err != nil {
		t.Fatal(err)
	}
	cloud.set(h.Ref, func(i *Instance) { i.State = StateGone; i.Preempted = true })
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Clean() || exit.Reason != manager.ExitLost {
		t.Fatalf("exit %+v, %v", exit, err)
	}
}

func TestUncollectedTokenIsLost(t *testing.T) {
	cloud := newFakeCloud()
	d, clk := newDriver(cloud, 1, 1)
	capacity(t, d)
	bootAll(t, d, cloud)
	h, err := d.Start(context.Background(), capacity(t, d).Ready[0], claim(11))
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(6 * time.Minute)
	exit, err := d.Wait(context.Background(), h)
	if err != nil || exit.Reason != manager.ExitLost {
		t.Fatalf("exit %+v, %v", exit, err)
	}
}

func TestBootTimeoutDestroysAndReplaces(t *testing.T) {
	cloud := newFakeCloud()
	d, clk := newDriver(cloud, 1, 2)
	capacity(t, d)
	clk.advance(11 * time.Minute)
	c := capacity(t, d)
	if !cloud.wasDestroyed("i-1") {
		t.Fatal("an instance that never checked in was kept")
	}
	if c.Provisioning != 1 || len(c.Ready) != 0 {
		t.Fatalf("want one replacement booting, got %+v", c)
	}
}

func TestSurplusIdleInstancesAreRetired(t *testing.T) {
	cloud := newFakeCloud()
	d, clk := newDriver(cloud, 1, 3)
	if err := d.Provision(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	d.creating.Wait()
	bootAll(t, d, cloud)
	clk.advance(11 * time.Minute)
	c := capacity(t, d)
	if len(c.Ready) != 1 {
		t.Fatalf("want the warm count of 1 kept, got %+v", c)
	}
}

func TestReapDestroysUntrackedLeftovers(t *testing.T) {
	cloud := newFakeCloud()
	ctx := context.Background()
	// A predecessor's instances: one serving live job 3, one idle, one of
	// another manager.
	live, _ := cloud.Create(ctx, Spec{}, map[string]string{TagManager: "7", TagJob: "3"})
	idle, _ := cloud.Create(ctx, Spec{}, map[string]string{TagManager: "7"})
	foreign, _ := cloud.Create(ctx, Spec{}, map[string]string{TagManager: "8"})
	d, _ := newDriver(cloud, 0, 1)
	if err := d.Reap(ctx, []manager.JobID{3}); err != nil {
		t.Fatal(err)
	}
	if cloud.wasDestroyed(live) || cloud.wasDestroyed(foreign) || !cloud.wasDestroyed(idle) {
		t.Fatalf("destroyed %v", cloud.destroyed)
	}
}

func TestWrongImageIsRefused(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	cloud.image["i-1"] = "ami-other"
	if err := d.checkIn(context.Background(), proof("i-1"), cloud.address("i-1")+":1"); !errors.Is(err, ErrWrongImage) {
		t.Fatalf("check in from another image: %v", err)
	}
}

func TestHandlerServesTheAssignment(t *testing.T) {
	cloud := newFakeCloud()
	d, _ := newDriver(cloud, 1, 1)
	capacity(t, d)
	h := d.Handler()
	post := func(path, remote string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	addr := cloud.address("i-1") + ":40000"
	if w := post("/v1/ready", addr, readyRequest{Proof: proof("i-1")}); w.Code != http.StatusNoContent {
		t.Fatalf("ready: %d %s", w.Code, w.Body)
	}
	if w := post("/v1/ready", addr, readyRequest{Proof: Proof{Document: []byte("i-1"), Signature: []byte("forged")}}); w.Code != http.StatusForbidden {
		t.Fatalf("forged proof: %d", w.Code)
	}
	if _, err := d.Start(context.Background(), "i-1", claim(21)); err != nil {
		t.Fatal(err)
	}
	w := post("/v1/assignment", addr, readyRequest{Proof: proof("i-1")})
	var got assignmentResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.StartupToken != "startup-21" {
		t.Fatalf("assignment: %d %s", w.Code, w.Body)
	}
	if w := post("/v1/assignment", addr, readyRequest{Proof: proof("i-1")}); w.Code != http.StatusOK {
		t.Fatalf("unacknowledged second assignment: %d", w.Code)
	}
	if w := post("/v1/started", addr, readyRequest{Proof: proof("i-1")}); w.Code != http.StatusNoContent {
		t.Fatalf("started: %d %s", w.Code, w.Body)
	}
	if w := post("/v1/started", addr, readyRequest{Proof: proof("i-1")}); w.Code != http.StatusNoContent {
		t.Fatalf("started again: %d %s", w.Code, w.Body)
	}
	if w := post("/v1/assignment", addr, readyRequest{Proof: proof("i-1")}); w.Code != http.StatusConflict {
		t.Fatalf("assignment after the acknowledgement: %d", w.Code)
	}
	if w := post("/v1/exit", addr, exitRequest{Proof: proof("i-1"), Code: 0}); w.Code != http.StatusNoContent {
		t.Fatalf("exit: %d %s", w.Code, w.Body)
	}
}

func TestVMFactsReportOpenEgressAndNeverUntrusted(t *testing.T) {
	d := &Driver{Cloud: &fakeCloud{}}
	f, err := d.Facts(context.Background())
	if err != nil || f[manager.FactIsolation] != "vm" || f[manager.FactEgress] != manager.EgressOpen || f[manager.FactUntrusted] != "" {
		t.Fatalf("facts = %v, %v", f, err)
	}
}
