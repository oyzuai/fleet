package azure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/vm"
	"github.com/oyzuai/fleet/manager/vm/idtoken/idtokentest"
	"github.com/oyzuai/fleet/runnerclient"
)

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	sub    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	image  = "/subscriptions/" + sub + "/resourceGroups/images/providers/Microsoft.Compute/galleries/oyzu/images/executor/versions/2026.10.10"
)

type fakeARM struct {
	mu      sync.Mutex
	created []CreateInput
	merged  map[string]map[string]string
	vms     map[string]VM
}

func (f *fakeARM) CreateVM(_ context.Context, in CreateInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, in)
	if f.vms == nil {
		f.vms = map[string]VM{}
	}
	// Azure creates and starts the VM at once in this fake.
	n := len(f.vms) + 1
	f.vms[in.Name] = VM{Name: in.Name, VMID: fmt.Sprintf("vm-%d", n), PrincipalID: fmt.Sprintf("principal-%d", n),
		ImageID: in.ImageID, ProvisioningState: "Succeeded", PowerState: "running", PrivateIP: fmt.Sprintf("10.1.0.%d", n),
		Tags: in.Tags, Spot: in.Spot}
	return nil
}

func (f *fakeARM) GetVM(_ context.Context, name string) (VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vms[name]
	if !ok {
		return VM{}, ErrNotFound
	}
	return v, nil
}

func (f *fakeARM) ListVMs(context.Context) ([]VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []VM
	for _, v := range f.vms {
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeARM) MergeTags(_ context.Context, name string, tags map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.merged == nil {
		f.merged = map[string]map[string]string{}
	}
	f.merged[name] = tags
	if v, ok := f.vms[name]; ok {
		for k, val := range tags {
			v.Tags[k] = val
		}
	}
	return nil
}

func (f *fakeARM) DeleteVM(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.vms[name]; !ok {
		return ErrNotFound
	}
	delete(f.vms, name)
	return nil
}

func (f *fakeARM) GetVMSize(context.Context, string) (VMSize, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return VMSize{VCPUs: 4, MemoryMiB: 16384, Architecture: "x64"}, nil
}

func newCloud(t *testing.T, api API, keys *idtokentest.Signer) *Cloud {
	t.Helper()
	c, err := New(Config{API: api, Tenant: tenant, Subscription: sub, ResourceGroup: "oyzu-builds",
		Audience: "api://oyzu-pool-manager", Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateLocksTheVMDown(t *testing.T) {
	api := &fakeARM{}
	c := newCloud(t, api, idtokentest.New(t, "k"))
	ctx := context.Background()
	spec := vm.Spec{Image: image, Shape: "Standard_D4s_v5", Network: "/subscriptions/x/subnets/builds",
		Identity: "/subscriptions/x/userAssignedIdentities/executor", Spot: true}
	id, err := c.Create(ctx, spec, map[string]string{vm.TagPool: "Linux_x64", vm.TagManager: "7"})
	if err != nil {
		t.Fatal(err)
	}
	in := api.created[0]
	if in.Name != id || !strings.HasPrefix(id, "oyzu-linux-x64-") || len(id) > 64 {
		t.Fatalf("name %q, id %q", in.Name, id)
	}
	if !in.SystemAssignedIdentity || in.UserAssignedIdentity != spec.Identity || !in.Spot || !in.DeleteWithVM ||
		!in.SecureBoot || in.CustomData != "" || in.ImageID != image || in.SubnetID != spec.Network {
		t.Fatalf("create input: %+v", in)
	}
	if in.Tags["oyzu-pool"] != "Linux_x64" || in.Tags["oyzu-manager"] != "7" || in.Tags[tagImage] != image {
		t.Fatalf("tags: %v", in.Tags)
	}
	for k := range in.Tags {
		if strings.Contains(k, "/") {
			t.Fatalf("tag name %q is not allowed on Azure", k)
		}
	}
	// The login key is a well-formed ed25519 key, different every time.
	f := strings.Fields(in.SSHPublicKey)
	if len(f) != 3 || f[0] != "ssh-ed25519" {
		t.Fatalf("ssh key %q", in.SSHPublicKey)
	}
	if b, err := base64.StdEncoding.DecodeString(f[1]); err != nil || len(b) != 4+11+4+32 {
		t.Fatalf("ssh key blob: %d bytes, %v", len(b), err)
	}
	again, _ := c.Create(ctx, spec, map[string]string{vm.TagPool: "Linux_x64"})
	if again == id || api.created[1].SSHPublicKey == in.SSHPublicKey {
		t.Fatal("a name or login key was reused")
	}
}

func TestListTagAndDestroy(t *testing.T) {
	api := &fakeARM{vms: map[string]VM{
		"oyzu-a": {Name: "oyzu-a", ProvisioningState: "Succeeded", PowerState: "running", PrivateIP: "10.1.0.4",
			Tags: map[string]string{"oyzu-manager": "7", "oyzu-job": "41"}},
		"oyzu-b": {Name: "oyzu-b", ProvisioningState: "Succeeded", PowerState: "deallocated", Spot: true,
			Tags: map[string]string{"oyzu-manager": "7"}},
		"oyzu-c": {Name: "oyzu-c", ProvisioningState: "Deleting", Tags: map[string]string{"oyzu-manager": "7"}},
		"other":  {Name: "other", ProvisioningState: "Succeeded", PowerState: "running", Tags: map[string]string{"oyzu-manager": "8"}},
	}}
	c := newCloud(t, api, idtokentest.New(t, "k"))
	ctx := context.Background()
	got, err := c.List(ctx, "7")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %+v, %v", got, err)
	}
	d, err := c.Describe(ctx, []string{"oyzu-a", "oyzu-b", "gone"})
	if err != nil || len(d) != 2 {
		t.Fatalf("describe = %v, %v", d, err)
	}
	if a := d["oyzu-a"]; a.State != vm.StateRunning || a.Address != "10.1.0.4" || a.Tags[vm.TagJob] != "41" {
		t.Fatalf("running VM: %+v", a)
	}
	if b := d["oyzu-b"]; b.State != vm.StateStopping || !b.Preempted {
		t.Fatalf("evicted spot VM: %+v", b)
	}
	if err := c.Tag(ctx, "oyzu-a", map[string]string{vm.TagJob: "42"}); err != nil || api.merged["oyzu-a"]["oyzu-job"] != "42" {
		t.Fatalf("tag: %v, %v", api.merged, err)
	}
	if err := c.Destroy(ctx, "gone"); err != nil {
		t.Fatalf("destroying a deleted VM: %v", err)
	}
}

func token(t *testing.T, s *idtokentest.Signer, mod func(c map[string]any)) vm.Proof {
	t.Helper()
	now := time.Now()
	c := map[string]any{
		"iss": "https://sts.windows.net/" + tenant + "/", "aud": "api://oyzu-pool-manager", "tid": tenant,
		"oid": "principal-a", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"xms_mirid": "/subscriptions/" + sub + "/resourcegroups/oyzu-builds/providers/Microsoft.Compute/virtualMachines/oyzu-a",
	}
	if mod != nil {
		mod(c)
	}
	return vm.Proof{Document: []byte(s.Sign(t, c))}
}

func TestVerifyIdentity(t *testing.T) {
	s := idtokentest.New(t, "k")
	api := &fakeARM{vms: map[string]VM{"oyzu-a": {Name: "oyzu-a", PrincipalID: "PRINCIPAL-A",
		ImageID: strings.ToLower(image), Tags: map[string]string{tagImage: image}}}}
	c := newCloud(t, api, s)
	ctx := context.Background()
	id, err := c.VerifyIdentity(ctx, token(t, s, nil))
	if err != nil || id.InstanceID != "oyzu-a" || id.Image != image {
		t.Fatalf("verify = %+v, %v", id, err)
	}
	v2 := token(t, s, func(c map[string]any) { c["iss"] = "https://login.microsoftonline.com/" + tenant + "/v2.0" })
	if _, err := c.VerifyIdentity(ctx, v2); err != nil {
		t.Fatalf("v2 token: %v", err)
	}
	mirid := func(rid string) func(map[string]any) { return func(c map[string]any) { c["xms_mirid"] = rid } }
	for name, p := range map[string]vm.Proof{
		"other tenant":           token(t, s, func(c map[string]any) { c["tid"] = "evil" }),
		"other tenant's issuer":  token(t, s, func(c map[string]any) { c["iss"] = "https://sts.windows.net/evil/" }),
		"other audience":         token(t, s, func(c map[string]any) { c["aud"] = "https://management.azure.com/" }),
		"other subscription":     token(t, s, mirid("/subscriptions/other/resourcegroups/oyzu-builds/providers/Microsoft.Compute/virtualMachines/oyzu-a")),
		"other resource group":   token(t, s, mirid("/subscriptions/"+sub+"/resourcegroups/elsewhere/providers/Microsoft.Compute/virtualMachines/oyzu-a")),
		"user-assigned identity": token(t, s, mirid("/subscriptions/"+sub+"/resourcegroups/oyzu-builds/providers/Microsoft.ManagedIdentity/userAssignedIdentities/executor")),
		"recreated VM":           token(t, s, func(c map[string]any) { c["oid"] = "principal-old" }),
		"unknown VM":             token(t, s, mirid("/subscriptions/"+sub+"/resourcegroups/oyzu-builds/providers/Microsoft.Compute/virtualMachines/oyzu-z")),
		"other signer":           token(t, idtokentest.New(t, "k"), nil),
	} {
		if _, err := c.VerifyIdentity(ctx, p); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestFactsFromTheCatalogue(t *testing.T) {
	c := newCloud(t, &fakeARM{}, idtokentest.New(t, "k"))
	f, err := c.Facts(context.Background(), vm.Spec{Shape: "Standard_D4s_v5"})
	if err != nil {
		t.Fatal(err)
	}
	if f[manager.FactArch] != "amd64" || f[manager.FactCPU] != "4" || f[manager.FactMemory] != "16384Mi" {
		t.Fatalf("facts: %v", f)
	}
}

// The generic VM driver runs a job end to end on Azure with only the adapter
// differing from AWS: boot, check in with a managed identity token, claim
// into the ready slot, hand over the startup token once, exit, delete.
func TestDriverRunsAJobOnAzure(t *testing.T) {
	s := idtokentest.New(t, "k")
	api := &fakeARM{}
	d := &vm.Driver{Cloud: newCloud(t, api, s), Pool: "vms", Manager: 7, Warm: 1, Max: 1, PollInterval: time.Millisecond,
		Spec: vm.Spec{Image: image, Shape: "Standard_D4s_v5"}}
	ctx := context.Background()
	if _, err := d.Capacity(ctx); err != nil {
		t.Fatal(err)
	}
	var inst VM
	deadline := time.Now().Add(5 * time.Second)
	for {
		api.mu.Lock()
		for _, v := range api.vms {
			inst = v
		}
		api.mu.Unlock()
		if inst.Name != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no VM was created")
		}
		time.Sleep(5 * time.Millisecond)
	}
	proof := token(t, s, func(c map[string]any) {
		c["oid"] = inst.PrincipalID
		c["xms_mirid"] = "/subscriptions/" + sub + "/resourceGroups/oyzu-builds/providers/Microsoft.Compute/virtualMachines/" + inst.Name
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
	addr := inst.PrivateIP + ":40000"
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
	if _, ok := api.vms[inst.Name]; ok || api.merged[inst.Name]["oyzu-job"] != "21" {
		t.Fatalf("after teardown: VMs %v, tags %v", api.vms, api.merged)
	}
}
