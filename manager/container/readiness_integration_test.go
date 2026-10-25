package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/readiness"
	"github.com/oyzuai/fleet/runnerclient"
)

// This proof needs a real Docker engine and the repository's pinned executor
// image. Unit fakes cannot qualify a boundary. tooling/readiness-container-proof.sh
// supplies disposable, credential-free fixtures and removes them on exit.
func TestReadinessDockerBoundaryAndGatewayReplacement(t *testing.T) {
	image := os.Getenv("FLEET_READINESS_IMAGE")
	if image == "" {
		t.Skip("run oyzu run readiness-container-proof for real container qualification")
	}
	engine, err := NewDocker("", DockerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	observed := &readinessProofEngine{Docker: engine}
	d := &Driver{Engine: observed, Image: image, Command: []string{"/executor"}, Server: "http://127.0.0.1:1", Pool: "readiness-proof", Manager: 9876501, Slots: 1, Egress: EgressEnforce, StopGrace: time.Second}
	if err = d.Check(); err != nil {
		t.Fatal(err)
	}
	present, err := engine.ImagePresent(ctx, image)
	if err != nil || !present {
		t.Fatalf("pinned image: %v %v", present, err)
	}
	d.pulled = true
	d.EnableReadiness()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		containers, _ := engine.ListContainers(cleanup, map[string]string{LabelManager: d.managerLabel(), LabelPool: d.Pool})
		for _, c := range containers {
			if err := engine.RemoveContainer(cleanup, c.ID); err != nil {
				t.Error(err)
			}
		}
		networks, _ := engine.ListNetworks(cleanup, map[string]string{LabelManager: d.managerLabel(), LabelPool: d.Pool})
		volumes, _ := engine.ListVolumes(cleanup, map[string]string{LabelManager: d.managerLabel(), LabelPool: d.Pool})
		for _, v := range volumes {
			if err := engine.RemoveVolume(cleanup, v.Name); err != nil {
				t.Error(err)
			}
		}
		for _, n := range networks {
			if err := engine.RemoveNetwork(cleanup, n.Name); err != nil {
				t.Error(err)
			}
		}
	})
	descriptor := readiness.Descriptor{URL: os.Getenv("FLEET_READINESS_CANARY_URL"), DNSAddress: os.Getenv("FLEET_READINESS_CANARY_DNS"), DNSName: "readiness.oyzu.test"}
	if err = descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := d.ReadinessBoundary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	challenge := readiness.Challenge{ID: "11111111-1111-4111-8111-111111111111", Session: "22222222-2222-4222-8222-222222222222", Generation: 2, Fingerprint: b.Fingerprint(), Suite: readiness.Suite, Nonce: hex.EncodeToString(nonce[:]), Descriptor: descriptor, Dispatched: time.Now(), Deadline: time.Now().Add(90 * time.Second)}
	result := d.ProbeReadiness(ctx, challenge)
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "passed" {
		t.Fatalf("actual container did not qualify: %+v", result)
	}
	binding := &readiness.Binding{Challenge: challenge.ID, Session: challenge.Session, Generation: challenge.Generation, Fingerprint: challenge.Fingerprint, Evidence: "33333333-3333-4333-8333-333333333333", ValidUntil: time.Now().Add(time.Minute)}
	d.SetReadiness(binding)
	if err = d.CheckReadiness(ctx, binding); err != nil {
		t.Fatal(err)
	}
	// Exercise a deliberately ineffective boundary with the actual probe
	// executable. The public canary is reachable directly from the normal
	// bridge, so both direct TCP and DNS are observed bypasses, regardless
	// of whether a proxy refused some other request.
	faultName := "oyzu-9876501-probe-ineffective-boundary"
	faultChallenge := challenge
	faultChallenge.ID = "77777777-7777-4777-8777-777777777777"
	faultRaw, err := json.Marshal(faultChallenge)
	if err != nil {
		t.Fatal(err)
	}
	faultID, err := engine.CreateContainer(ctx, faultName, Spec{Image: d.Image, Cmd: []string{"/executor", "gateway", "probe-readiness", "--challenge", string(faultRaw), "--proxy", descriptor.URL, "--control", "127.0.0.1:1"}, User: d.user(), Network: defaultNetwork, ReadOnly: true, PidsLimit: 256, Labels: map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel()}})
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.StartContainer(ctx, faultID); err != nil {
		t.Fatal(err)
	}
	if code, err := engine.WaitContainer(ctx, faultID); err != nil || code != 0 {
		t.Fatalf("ineffective boundary probe: %d %v", code, err)
	}
	faultOutput, err := engine.ContainerLogs(ctx, faultID, 1)
	if err != nil {
		t.Fatal(err)
	}
	var bypass readiness.Result
	if err = json.Unmarshal(faultOutput, &bypass); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"direct-egress", "dns-confinement"} {
		failed := false
		for _, check := range bypass.Checks {
			failed = failed || (check.Name == name && check.Outcome == "failed")
		}
		if !failed {
			t.Fatalf("reachable %s was not a definitive failure: %+v", name, bypass)
		}
	}
	if err = engine.RemoveContainer(ctx, faultID); err != nil {
		t.Fatal(err)
	}

	// The ordinary driver must distinguish missing positive prerequisites
	// from an observed bypass and may not manufacture a new success.
	missing := challenge
	missing.ID = "88888888-8888-4888-8888-888888888888"
	missing.Descriptor.DNSName = "absent.readiness.oyzu.test"
	missing.Deadline = time.Now().Add(30 * time.Second)
	inconclusive := d.ProbeReadiness(ctx, missing)
	if inconclusive.Outcome != "inconclusive" {
		t.Fatalf("missing positive DNS fixture: %+v", inconclusive)
	}
	if !binding.ValidUntil.Equal(d.localBinding.ValidUntil) {
		t.Fatal("inconclusive probe extended prior successful evidence")
	}
	facts, err := d.Facts(ctx)
	if err != nil || facts[manager.FactEgress] != manager.EgressEnforced || facts[manager.FactUntrusted] != manager.UntrustedAccepted {
		t.Fatalf("inconclusive refresh removed a still-current accepted capability: %v %v", facts, err)
	}
	// Inject one failed cleanup operation around an otherwise real probe.
	// Qualification cannot turn a measured pass into a pass with leaked resources.
	cleanupChallenge := challenge
	cleanupChallenge.ID = "99999999-9999-4999-8999-999999999999"
	cleanupChallenge.Deadline = time.Now().Add(30 * time.Second)
	cleanupNetwork := "oyzu-9876501-probe-" + cleanupChallenge.ID
	observed.failNetwork = cleanupNetwork
	cleanupResult := d.ProbeReadiness(ctx, cleanupChallenge)
	if cleanupResult.Outcome != "inconclusive" || observed.failNetwork != "" {
		t.Fatalf("failed cleanup manufactured a pass: %+v", cleanupResult)
	}
	if d.localBinding == nil || !binding.ValidUntil.Equal(d.localBinding.ValidUntil) {
		t.Fatal("cleanup failure changed the prior evidence deadline")
	}
	if err = engine.RemoveNetwork(ctx, cleanupNetwork); err != nil {
		t.Fatal("remove the deliberately retained test network", err)
	}
	// Exercise the ordinary typed Start path. The bootstrap must already
	// have its observed namespace before the one-use handoff archive arrives.
	// This marker is deliberately not a valid server credential.
	h, err := d.Start(ctx, "0", runnerclient.Claim{JobID: 42, Attempt: 1, StartupToken: "fixture-startup-marker", Readiness: binding, Egress: runnerclient.ClaimEgress{Allow: []runnerclient.EgressAllow{{Host: "127.0.0.1", Port: 1}}}})
	if err != nil {
		t.Fatal("typed bootstrap handoff", err)
	}
	if observed.handoffs != 1 {
		t.Fatal("typed bootstrap did not receive its checked allocation handoff")
	}
	if err = d.Teardown(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Inspect a real running allocation, then attach an extra network after
	// startup. A fresh server response carrying old evidence cannot restore it.
	j := &job{name: "oyzu-9876501-allocation-proof"}
	labels := map[string]string{LabelPool: d.Pool, LabelManager: d.managerLabel(), LabelJob: "allocation-proof"}
	env, dns, err := d.openSandbox(ctx, j, labels, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	j.dns = dns
	sysctls, err := d.ipv6Sysctls(ctx, labels)
	if err != nil {
		t.Fatal(err)
	}
	j.id, err = engine.CreateContainer(ctx, j.name, Spec{Image: d.Image, Cmd: []string{"/executor", "gateway", "readiness-canary", "--http", ":8081", "--dns", ":8054"}, User: d.user(), Network: j.network, Env: env, DNS: dns, Labels: labels, ReadOnly: true, PidsLimit: 64, Sysctls: sysctls})
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.StartContainer(ctx, j.id); err != nil {
		t.Fatal(err)
	}
	d.inUse = map[manager.SlotID]*job{"proof": j}
	handle := manager.Handle{Slot: "proof", Ref: j.name}
	if err = d.CheckReadinessAllocation(ctx, handle, binding); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ConnectNetwork(ctx, "bridge", j.id); err != nil {
		t.Fatal(err)
	}
	if err = d.checkAllocation(ctx, j.id, j.dns, j.networkID,false); err == nil {
		t.Fatal("actual extra network was accepted")
	}
	if err = engine.DisconnectNetwork(ctx, j.network, j.id); err != nil {
		t.Fatal(err)
	}
	if err = d.CheckReadinessAllocation(ctx, handle, binding); err == nil {
		t.Fatal("a single replacement network inherited the qualified namespace")
	}
	d.SetReadiness(binding)
	if err = d.CheckReadiness(ctx, binding); err == nil {
		t.Fatal("old evidence restored a locally failed allocation")
	}
	if err = engine.RemoveContainer(ctx, j.id); err != nil {
		t.Fatal(err)
	}
	if err = d.closeSandbox(ctx, j); err != nil {
		t.Fatal(err)
	}
	delete(d.inUse, "proof")
	challenge.ID = "55555555-5555-4555-8555-555555555555"
	challenge.Deadline = time.Now().Add(90 * time.Second)
	result = d.ProbeReadiness(ctx, challenge)
	if result.Outcome != "passed" {
		t.Fatalf("clean replacement allocation: %+v", result)
	}
	binding.Challenge = challenge.ID
	binding.Evidence = "66666666-6666-4666-8666-666666666666"
	d.SetReadiness(binding)
	if err = d.CheckReadiness(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err = engine.RemoveContainer(ctx, b.Gateway); err != nil {
		t.Fatal(err)
	}
	if err = d.CheckReadiness(ctx, binding); err == nil {
		t.Fatal("replaced gateway accepted the previous assignment")
	}
	replacement, err := d.ReadinessBoundary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Gateway == b.Gateway || replacement.Fingerprint() == b.Fingerprint() {
		t.Fatal("gateway replacement did not change boundary identity")
	}
	challenge.Generation++
	challenge.Fingerprint = replacement.Fingerprint()
	challenge.ID = "44444444-4444-4444-8444-444444444444"
	challenge.Deadline = time.Now().Add(90 * time.Second)
	result = d.ProbeReadiness(ctx, challenge)
	if result.Outcome != "passed" {
		t.Fatalf("replacement measurement: %+v", result)
	}
	applied, err := d.ApplyReadinessMode(ctx, "report")
	if err != nil || !applied {
		t.Fatalf("mode change: %v %v", applied, err)
	}
	if err = d.CheckReadiness(ctx, binding); err == nil {
		t.Fatal("report mode accepted old enforcing assignment")
	}
	t.Log("real container: seven checks passed; ineffective boundary exposed direct TCP and DNS bypasses as failures; missing positive fixture was inconclusive without extending evidence; checked bootstrap handoff; live extra/replacement networks fenced use and stale restore; clean boundary remeasured; gateway replacement fenced old assignment; mode change fenced old authority")
}

// The real engine is observed at the credential handoff point. A test fake
// returning success from StartContainer cannot establish this ordering.
type readinessProofEngine struct {
	*Docker
	handoffs    int
	failNetwork string
}

func (e *readinessProofEngine) RemoveNetwork(ctx context.Context, name string) error {
	if name == e.failNetwork {
		e.failNetwork = ""
		return errors.New("task-owned cleanup fault")
	}
	return e.Docker.RemoveNetwork(ctx, name)
}

func (e *readinessProofEngine) CopyFiles(ctx context.Context, id, path string, archive []byte) error {
	state, err := e.Docker.InspectContainer(ctx, id)
	if err != nil {
		return err
	}
	if !state.Running {
		return errors.New("startup handoff preceded the trusted bootstrap")
	}
	allocation, err := e.Docker.InspectReadinessAllocation(ctx, id)
	if err != nil {
		return err
	}
	if allocation.Networks != 1 || len(allocation.NetworkIDs) != 1 || allocation.NetworkIDs[0] == "" {
		return errors.New("startup handoff preceded actual namespace allocation")
	}
	e.handoffs++
	return e.Docker.CopyFiles(ctx, id, path, archive)
}
