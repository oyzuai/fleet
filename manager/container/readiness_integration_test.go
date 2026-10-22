package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/oyzuai/fleet/readiness"
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
	d := &Driver{Engine: engine, Image: image, Command: []string{"/executor"}, Server: "http://runs.invalid", Pool: "readiness-proof", Manager: 9876501, Slots: 1, Egress: EgressEnforce}
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
		containers, _ := engine.ListContainers(cleanup, map[string]string{LabelManager: d.managerLabel()})
		for _, c := range containers {
			if err := engine.RemoveContainer(cleanup, c.ID); err != nil {
				t.Error(err)
			}
		}
		networks, _ := engine.ListNetworks(cleanup, map[string]string{LabelManager: d.managerLabel()})
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
	binding := &readiness.Binding{Session: challenge.Session, Generation: challenge.Generation, Fingerprint: challenge.Fingerprint, Evidence: "33333333-3333-4333-8333-333333333333", ValidUntil: time.Now().Add(time.Minute)}
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
	t.Log("real container: seven checks passed; gateway replacement fenced the old assignment; replacement remeasured; mode change fenced old authority")
}
