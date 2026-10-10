package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/vm"
	"github.com/oyzuai/fleet/manager/vm/idtoken/idtokentest"
	"github.com/oyzuai/fleet/runnerclient"
)

type fakeGCE struct {
	mu        sync.Mutex
	inserted  []InsertInput
	filters   []string
	labelled  map[string]map[string]string
	deleted   []string
	instances map[string]Instance
}

func (f *fakeGCE) InsertInstance(_ context.Context, in InsertInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inserted = append(f.inserted, in)
	if f.instances == nil {
		f.instances = map[string]Instance{}
	}
	// Compute Engine boots the instance at once in this fake.
	n := len(f.instances) + 1
	f.instances[in.Name] = Instance{Name: in.Name, ID: strconv.Itoa(5550000 + n), Status: "RUNNING",
		NetworkIP: fmt.Sprintf("10.0.0.%d", n), SourceImage: "https://www.googleapis.com/compute/v1/" + in.SourceImage,
		CreationTimestamp: created, Labels: in.Labels, Spot: in.Spot}
	return nil
}

func (f *fakeGCE) GetInstance(_ context.Context, name string) (Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.instances[name]
	if !ok {
		return Instance{}, ErrNotFound
	}
	return i, nil
}

func (f *fakeGCE) ListInstances(_ context.Context, filter string) ([]Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, filter)
	var out []Instance
	for _, i := range f.instances {
		out = append(out, i)
	}
	return out, nil
}

func (f *fakeGCE) SetLabels(_ context.Context, name string, labels map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.labelled == nil {
		f.labelled = map[string]map[string]string{}
	}
	f.labelled[name] = labels
	return nil
}

func (f *fakeGCE) DeleteInstance(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	if _, ok := f.instances[name]; !ok {
		return ErrNotFound
	}
	delete(f.instances, name)
	return nil
}

func (f *fakeGCE) GetMachineType(_ context.Context, name string) (MachineType, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return MachineType{GuestCPUs: 8, MemoryMB: 32768, Architecture: "ARM64"}, nil
}

const image = "projects/oyzu-images/global/images/oyzu-executor-20261010"

var created = time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC)

func newCloud(t *testing.T, api API, keys *idtokentest.Signer) *Cloud {
	t.Helper()
	c, err := New(Config{API: api, Project: "oyzu-builds", Zone: "us-central1-a", Audience: "https://manager.pool.internal",
		NetworkTags: []string{"oyzu-executor"}, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateUsesTheInstancesOwnAccountAndNoStartupScript(t *testing.T) {
	api := &fakeGCE{}
	c := newCloud(t, api, idtokentest.New(t, "k"))
	ctx := context.Background()
	spec := vm.Spec{Image: image, Shape: "t2a-standard-8", Network: "regions/us-central1/subnetworks/builds",
		Identity: "executor@oyzu-builds.iam.gserviceaccount.com", Spot: true}
	id, err := c.Create(ctx, spec, map[string]string{vm.TagPool: "Linux_ARM", vm.TagManager: "7"})
	if err != nil {
		t.Fatal(err)
	}
	in := api.inserted[0]
	if in.Name != id || !strings.HasPrefix(id, "oyzu-linux-arm-") || len(id) > 63 {
		t.Fatalf("name %q, id %q", in.Name, id)
	}
	if in.ServiceAccount != spec.Identity || in.SourceImage != image || !in.Spot || !in.ShieldedSecureBoot ||
		in.Subnetwork != spec.Network || in.NetworkTags[0] != "oyzu-executor" {
		t.Fatalf("insert input: %+v", in)
	}
	if in.Labels["oyzu-pool"] != "linux_arm" || in.Labels["oyzu-manager"] != "7" {
		t.Fatalf("labels: %v", in.Labels)
	}
	for k := range in.Metadata {
		if strings.Contains(k, "startup") || strings.Contains(k, "user-data") {
			t.Fatalf("metadata carries %s", k)
		}
	}
	if in.Metadata["block-project-ssh-keys"] != "true" {
		t.Fatalf("metadata: %v", in.Metadata)
	}
	again, _ := c.Create(ctx, spec, map[string]string{vm.TagPool: "Linux_ARM", vm.TagManager: "7"})
	if again == id {
		t.Fatal("an instance name was reused")
	}
	spec.Identity = ""
	if _, err := c.Create(ctx, spec, nil); err == nil {
		t.Fatal("created an instance that cannot prove its identity")
	}
}

func TestListTagAndDestroy(t *testing.T) {
	api := &fakeGCE{instances: map[string]Instance{
		"oyzu-a": {Name: "oyzu-a", Status: "RUNNING", NetworkIP: "10.0.0.5", Labels: map[string]string{"oyzu-manager": "7", "oyzu-job": "41"}},
		"oyzu-b": {Name: "oyzu-b", Status: "TERMINATED", Spot: true, Labels: map[string]string{"oyzu-manager": "7"}},
		"oyzu-c": {Name: "oyzu-c", Status: "STOPPING", Labels: map[string]string{"oyzu-manager": "7"}},
	}}
	c := newCloud(t, api, idtokentest.New(t, "k"))
	ctx := context.Background()
	got, err := c.List(ctx, "7")
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if api.filters[0] != `labels.oyzu-manager = "7"` {
		t.Fatalf("filter %q", api.filters[0])
	}
	d, err := c.Describe(ctx, []string{"oyzu-a", "oyzu-b", "oyzu-c", "gone"})
	if err != nil || len(d) != 3 {
		t.Fatalf("describe = %v, %v", d, err)
	}
	if a := d["oyzu-a"]; a.State != vm.StateRunning || a.Address != "10.0.0.5" || a.Tags[vm.TagJob] != "41" || a.Tags[vm.TagManager] != "7" {
		t.Fatalf("running instance: %+v", a)
	}
	if b := d["oyzu-b"]; b.State != vm.StateStopping || !b.Preempted {
		t.Fatalf("reclaimed spot instance: %+v", b)
	}
	if cc := d["oyzu-c"]; cc.Preempted {
		t.Fatalf("a standard instance stopping counts as preempted: %+v", cc)
	}
	if err := c.Tag(ctx, "oyzu-a", map[string]string{vm.TagJob: "42"}); err != nil {
		t.Fatal(err)
	}
	if l := api.labelled["oyzu-a"]; l["oyzu-job"] != "42" || l["oyzu-manager"] != "7" {
		t.Fatalf("labels after tagging: %v", l)
	}
	if err := c.Destroy(ctx, "gone"); err != nil {
		t.Fatalf("destroying a deleted instance: %v", err)
	}
}

func token(t *testing.T, s *idtokentest.Signer, mod func(ce map[string]any)) vm.Proof {
	t.Helper()
	ce := map[string]any{"project_id": "oyzu-builds", "zone": "us-central1-a", "instance_id": "5551234",
		"instance_name": "oyzu-a", "instance_creation_timestamp": created.Unix()}
	if mod != nil {
		mod(ce)
	}
	now := time.Now()
	return vm.Proof{Document: []byte(s.Sign(t, map[string]any{
		"iss": "https://accounts.google.com", "aud": "https://manager.pool.internal", "iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(), "google": map[string]any{"compute_engine": ce},
	}))}
}

func TestVerifyIdentity(t *testing.T) {
	s := idtokentest.New(t, "k")
	api := &fakeGCE{instances: map[string]Instance{"oyzu-a": {Name: "oyzu-a", ID: "5551234", CreationTimestamp: created,
		SourceImage: "https://www.googleapis.com/compute/v1/" + image}}}
	c := newCloud(t, api, s)
	ctx := context.Background()
	id, err := c.VerifyIdentity(ctx, token(t, s, nil))
	if err != nil || id.InstanceID != "oyzu-a" || id.Image != image {
		t.Fatalf("verify = %+v, %v", id, err)
	}
	for name, p := range map[string]vm.Proof{
		"other project":      token(t, s, func(ce map[string]any) { ce["project_id"] = "attacker" }),
		"other zone":         token(t, s, func(ce map[string]any) { ce["zone"] = "europe-west1-b" }),
		"reused name":        token(t, s, func(ce map[string]any) { ce["instance_id"] = "999" }),
		"recreated instance": token(t, s, func(ce map[string]any) { ce["instance_creation_timestamp"] = created.Add(time.Hour).Unix() }),
		"unknown instance":   token(t, s, func(ce map[string]any) { ce["instance_name"] = "oyzu-z" }),
		"standard format":    token(t, s, func(ce map[string]any) { delete(ce, "instance_name") }),
		"other signer":       token(t, idtokentest.New(t, "k"), nil),
	} {
		if _, err := c.VerifyIdentity(ctx, p); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestFactsFromTheCatalogue(t *testing.T) {
	c := newCloud(t, &fakeGCE{}, idtokentest.New(t, "k"))
	f, err := c.Facts(context.Background(), vm.Spec{Shape: "t2a-standard-8"})
	if err != nil {
		t.Fatal(err)
	}
	if f[manager.FactArch] != "arm64" || f[manager.FactCPU] != "8" || f[manager.FactMemory] != "32768Mi" || f[manager.FactOS] != "linux" {
		t.Fatalf("facts: %v", f)
	}
}

// The generic VM driver runs a job end to end on Compute Engine with only
// the adapter differing from AWS: boot, check in with a Google-signed token,
// claim into the ready slot, hand over the startup token once, exit, delete.
func TestDriverRunsAJobOnComputeEngine(t *testing.T) {
	s := idtokentest.New(t, "k")
	api := &fakeGCE{}
	d := &vm.Driver{Cloud: newCloud(t, api, s), Pool: "vms", Manager: 7, Warm: 1, Max: 1, PollInterval: time.Millisecond,
		Spec: vm.Spec{Image: image, Shape: "e2-standard-4", Identity: "executor@oyzu-builds.iam.gserviceaccount.com"}}
	ctx := context.Background()
	if _, err := d.Capacity(ctx); err != nil {
		t.Fatal(err)
	}
	var inst Instance
	deadline := time.Now().Add(5 * time.Second)
	for {
		api.mu.Lock()
		for _, i := range api.instances {
			inst = i
		}
		api.mu.Unlock()
		if inst.Name != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no instance was created")
		}
		time.Sleep(5 * time.Millisecond)
	}
	proof := token(t, s, func(ce map[string]any) {
		ce["instance_name"], ce["instance_id"] = inst.Name, inst.ID
	})
	h := d.Handler()
	post := func(path, remote string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	addr := inst.NetworkIP + ":40000"
	if w := post("/v1/ready", "10.9.9.9:40000", map[string]any{"proof": proof}); w.Code != http.StatusForbidden {
		t.Fatalf("check in from another address: %d", w.Code)
	}
	if w := post("/v1/ready", addr, map[string]any{"proof": proof}); w.Code != http.StatusNoContent {
		t.Fatalf("check in: %d %s", w.Code, w.Body)
	}
	c, err := d.Capacity(ctx)
	if err != nil || len(c.Ready) != 1 {
		t.Fatalf("capacity after check-in = %+v, %v", c, err)
	}
	hd, err := d.Start(ctx, c.Ready[0], runnerclient.Claim{JobID: 21, Attempt: 1, StartupToken: "startup-21",
		StartupExpires: time.Now().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		StartupToken string `json:"startup_token"`
	}
	if w := post("/v1/assignment", addr, map[string]any{"proof": proof}); w.Code != http.StatusOK ||
		json.Unmarshal(w.Body.Bytes(), &got) != nil || got.StartupToken != "startup-21" {
		t.Fatalf("assignment: %d %s", w.Code, w.Body)
	}
	if w := post("/v1/exit", addr, map[string]any{"proof": proof, "code": 0}); w.Code != http.StatusNoContent {
		t.Fatalf("exit: %d %s", w.Code, w.Body)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if exit, err := d.Wait(waitCtx, hd); err != nil || !exit.Clean() {
		t.Fatalf("wait = %+v, %v", exit, err)
	}
	if err := d.Teardown(ctx, hd); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if _, ok := api.instances[inst.Name]; ok || api.labelled[inst.Name]["oyzu-job"] != "21" {
		t.Fatalf("after teardown: instances %v, labels %v", api.instances, api.labelled)
	}
}
