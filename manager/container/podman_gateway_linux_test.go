//go:build linux

package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

type boundedGatewayEngine struct {
	Engine
	containers []string
	volumes    []string
}

type harmlessGatewayEngine struct{ *boundedGatewayEngine }

func (e *harmlessGatewayEngine) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	if spec.Volume != "" {
		spec.Cmd = []string{"/bin/true"}
	}
	return e.boundedGatewayEngine.CreateContainer(ctx, name, spec)
}

func (e *boundedGatewayEngine) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	err := e.Engine.CreateVolume(ctx, name, labels)
	if err == nil {
		e.volumes = append(e.volumes, name)
	}
	return err
}

func TestPodmanDriverJobRegistrationLifecycle(t *testing.T) {
	socket, image := os.Getenv("FLEET_PODMAN_PROOF_SOCKET"), os.Getenv("FLEET_PODMAN_GATEWAY_IMAGE")
	if socket == "" || image == "" {
		t.Skip("dedicated Podman job-start proof needs explicit socket and immutable local image")
	}
	if os.Geteuid() != 1002 || !strings.HasPrefix(socket, "/run/user/1002/") || !strings.HasPrefix(image, "localhost/oyzu-pool-executor@sha256:") {
		t.Fatal("proof restricted to dedicated uid1002 and immutable local executor image")
	}
	for i := 0; i < 2; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			engine, err := NewDocker("unix://"+socket, DockerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			bounded := &boundedGatewayEngine{Engine: engine}
			d := &Driver{Engine: &harmlessGatewayEngine{bounded}, Image: image, Command: []string{"oyzu-executor"}, Manager: time.Now().UnixNano(), Pool: "oyzu-pool-slice1-proof", Egress: EgressEnforce, Server: "https://example.invalid", pulled: true}
			t.Cleanup(func() {
				cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
				defer done()
				for _, id := range bounded.containers {
					if err := engine.RemoveContainer(cleanup, id); err != nil {
						t.Error(err)
					}
				}
				networks, err := bounded.ListNetworks(cleanup, map[string]string{LabelManager: d.managerLabel()})
				if err != nil {
					t.Error(err)
				}
				for _, network := range networks {
					if err := engine.RemoveNetwork(cleanup, network.Name); err != nil {
						t.Error(err)
					}
				}
				for _, volume := range bounded.volumes {
					if err := engine.RemoveVolume(cleanup, volume); err != nil {
						t.Error(err)
					}
				}
			})
			if err := d.probe(ctx); err != nil {
				t.Fatal(err)
			}
			if i == 1 {
				// Native CLI reads can synchronize runtime state separately from
				// the long-lived API service. Reproduce the observer's interleaving
				// only against this proof's own objects and test manager identity.
				// First prove native inspection uses the same object/store as the
				// API. A missing binary, wrong store or unrelated template error
				// must not pass as evidence of CLI/API interleaving.
				inspected, err := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{json .ID}}", d.gatewayName()).CombinedOutput()
				var nativeID string
				if err != nil || json.Unmarshal(inspected, &nativeID) != nil || nativeID != d.gw.id { t.Fatalf("native inspection did not find own API object: id=%q err=%v output=%s", nativeID, err, inspected) }
				invalid, err := exec.CommandContext(ctx, "podman", "inspect", "--format", "{{json .Id}} {{json .OCIConfigPath}}", d.gatewayName()).CombinedOutput()
				var templateExit *exec.ExitError
				if !errors.As(err, &templateExit) || !strings.Contains(string(invalid), "<.Id>") || !strings.Contains(string(invalid), "can't evaluate field Id") { t.Fatalf("expected specific invalid .Id template failure: %v %s", err, invalid) }
				pollCtx, stop := context.WithCancel(ctx)
				observed := make(chan struct{}, 1)
				readErrors := make(chan error, 1)
				var readers sync.WaitGroup
				readers.Add(1)
				go func() {
					defer readers.Done()
					ticker := time.NewTicker(250 * time.Millisecond)
					defer ticker.Stop()
					for {
						output, err := exec.CommandContext(pollCtx, "podman", "ps", "-a", "--no-trunc", "--filter", "label="+LabelManager+"="+d.managerLabel(), "--filter", "label="+LabelJob, "--format", "{{.ID}}").CombinedOutput()
						if err != nil {
							if pollCtx.Err() == nil { readErrors <- fmt.Errorf("native filtered ps failed: %w: %s", err, output) }
							return
						}
						select { case observed <- struct{}{}: default: }
						select {
						case <-pollCtx.Done():
							return
						case <-ticker.C:
						}
					}
				}()
				defer func() { stop(); readers.Wait(); select { case err := <-readErrors: t.Error(err); default: } }()
				select {
				case <-observed:
				case err := <-readErrors: t.Fatal(err)
				case <-ctx.Done(): t.Fatal("native filtered ps never completed successfully")
				}
				if err := d.gw.control.Health(ctx); err != nil {
					t.Fatalf("native CLI reads broke own gateway before Start: %v", err)
				}
			}
			claim := runnerclient.Claim{JobID: 5, Attempt: 1, StartupToken: "test-only-never-spent", Egress: runnerclient.ClaimEgress{Allow: []runnerclient.EgressAllow{{Host: "example.invalid", Port: 443}}}}
			h, err := d.Start(ctx, manager.SlotID("0"), claim)
			tornDown := false
			if h.Ref != "" {
				defer func() {
					if !tornDown {
						if err := d.Teardown(context.WithoutCancel(ctx), h); err != nil {
							t.Error(err)
						}
					}
				}()
			}
			if err != nil {
				t.Fatalf("actual Start registration: %v", err)
			}
			exit, err := d.Wait(ctx, h)
			if err != nil || exit.Code != 0 {
				t.Fatalf("harmless job wait: %+v %v", exit, err)
			}
			if err := d.Teardown(ctx, h); err != nil {
				t.Fatal(err)
			}
			tornDown = true
			if err := d.gw.control.Health(ctx); err != nil {
				t.Fatalf("management transport lost after actual job teardown: %v", err)
			}
			t.Log("actual workspace-volume/Start/Wait/Teardown retained authenticated gateway registration")
		})
	}
}

func matchingProofLabels(actual, requested map[string]string) bool {
	for key, value := range requested {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func (e *boundedGatewayEngine) ListContainers(ctx context.Context, labels map[string]string) ([]Summary, error) {
	items, err := e.Engine.ListContainers(ctx, labels)
	for _, item := range items {
		if !matchingProofLabels(item.Labels, labels) {
			return nil, fmt.Errorf("engine container filter returned foreign object %s", item.Name)
		}
	}
	return items, err
}

func (e *boundedGatewayEngine) ListNetworks(ctx context.Context, labels map[string]string) ([]Network, error) {
	items, err := e.Engine.ListNetworks(ctx, labels)
	for _, item := range items {
		if !matchingProofLabels(item.Labels, labels) {
			return nil, fmt.Errorf("engine network filter returned foreign object %s", item.Name)
		}
	}
	return items, err
}

func (e *boundedGatewayEngine) ListVolumes(ctx context.Context, labels map[string]string) ([]Volume, error) {
	items, err := e.Engine.ListVolumes(ctx, labels)
	for _, item := range items {
		if !matchingProofLabels(item.Labels, labels) {
			return nil, fmt.Errorf("engine volume filter returned foreign object %s", item.Name)
		}
	}
	return items, err
}

func (e *boundedGatewayEngine) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	spec.MemoryBytes, spec.NanoCPUs = 64<<20, 500000000
	if spec.Labels[LabelRole] == roleGateway {
		spec.MemoryBytes = 128 << 20
	}
	id, err := e.Engine.CreateContainer(ctx, name, spec)
	if err == nil {
		e.containers = append(e.containers, id)
	}
	return id, err
}

func TestPodmanDriverGatewayProbeCleanup(t *testing.T) {
	socket, image := os.Getenv("FLEET_PODMAN_PROOF_SOCKET"), os.Getenv("FLEET_PODMAN_GATEWAY_IMAGE")
	if socket == "" || image == "" {
		t.Skip("dedicated Podman driver probe needs explicit socket and immutable local image")
	}
	if os.Geteuid() != 1002 || !strings.HasPrefix(socket, "/run/user/1002/") || !strings.HasPrefix(image, "localhost/oyzu-pool-executor@sha256:") {
		t.Fatal("proof restricted to dedicated uid1002 and immutable local executor image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	engine, err := NewDocker("unix://"+socket, DockerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bounded := &boundedGatewayEngine{Engine: engine}
	d := &Driver{Engine: bounded, Image: image, Command: []string{"oyzu-executor"}, Manager: time.Now().UnixNano(), Pool: "oyzu-pool-slice1-proof", Egress: EgressEnforce}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		for _, id := range bounded.containers {
			if err := engine.RemoveContainer(cleanup, id); err != nil {
				t.Error(err)
			}
		}
		networks, err := engine.ListNetworks(cleanup, map[string]string{LabelManager: d.managerLabel()})
		if err != nil {
			t.Error(err)
			return
		}
		for _, network := range networks {
			if network.Labels[LabelManager] != d.managerLabel() || network.Labels[LabelPool] != d.Pool {
				t.Errorf("refusing cleanup of foreign network %s", network.Name)
				continue
			}
			if err := engine.RemoveNetwork(cleanup, network.Name); err != nil {
				t.Error(err)
			}
		}
	})
	for i := 0; i < 2; i++ {
		if err := d.probe(ctx); err != nil {
			t.Fatalf("real driver probe cycle%d: %v", i, err)
		}
		if err := d.gw.control.Health(ctx); err != nil {
			t.Fatalf("management transport lost after probe cycle%d: %v", i, err)
		}
		if err := d.Reap(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if err := d.gw.control.Health(ctx); err != nil {
			t.Fatalf("management transport lost after Reap cycle%d: %v", i, err)
		}
		t.Logf("real probe cleanup and Reap retained authenticated gateway control cycle%d", i)
	}
}

// This opt-in proof uses only a dedicated gateway and two temporary internal
// networks, never a job or the production manager's gateway/token.
func TestPodmanGatewayRegistrationAfterNetworkCleanup(t *testing.T) {
	socket, image := os.Getenv("FLEET_PODMAN_PROOF_SOCKET"), os.Getenv("FLEET_PODMAN_GATEWAY_IMAGE")
	if socket == "" || image == "" {
		t.Skip("dedicated Podman gateway proof needs explicit socket and immutable local image")
	}
	if os.Geteuid() != 1002 || !strings.HasPrefix(socket, "/run/user/1002/") || !strings.HasPrefix(image, "localhost/oyzu-pool-executor@sha256:") {
		t.Fatal("proof restricted to dedicated uid1002 and immutable local executor image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	engine, err := NewDocker("unix://"+socket, DockerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("oyzu-pool-gateway-proof-%d", time.Now().UnixNano())
	labels := map[string]string{LabelPool: "oyzu-pool-slice1-proof", LabelManager: "gateway-registration"}
	// This token belongs solely to the disposable test gateway.
	token := fmt.Sprintf("test-only-%d", time.Now().UnixNano())
	id, err := engine.CreateContainer(ctx, name, Spec{Image: image, Cmd: []string{"oyzu-executor", "gateway", "--mode", "enforce", "--pool", "proof", "--proxy", ":3128", "--control", ":9091", "--control-interface", "eth0"}, User: "1000:1000", WorkDir: "/work", Network: defaultNetwork, PidsLimit: 64, MemoryBytes: 128 << 20, NanoCPUs: 500000000, ReadOnly: true, Labels: labels, Env: []string{egressgate.TokenEnv + "=" + token}, Publish: []int{gatewayControlPort}, Sysctls: map[string]string{"net.ipv4.ip_unprivileged_port_start": "53"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := engine.RemoveContainer(cleanup, id); err != nil {
			t.Error(err)
		}
	})
	if err := engine.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	port, err := engine.PublishedPort(ctx, id, gatewayControlPort)
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	client := egressgate.NewClient(base, token)
	deadline := time.Now().Add(gatewayReadyWait)
	for {
		err = client.Health(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := engine.ContainerLogs(ctx, id, 10)
			t.Fatalf("gateway startup: %v %s", err, logs)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		network := fmt.Sprintf("%s-%d", name, i)
		n, err := engine.CreateNetwork(ctx, network, NetworkSpec{Internal: true, Labels: labels})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			_ = engine.DisconnectNetwork(cleanup, network, id)
			if err := engine.RemoveNetwork(cleanup, network); err != nil {
				t.Error(err)
			}
		})
		if !n.Internal || n.IPv6 || n.Driver != "bridge" || n.Subnet == "" {
			t.Fatalf("unexpected network: %+v", n)
		}
		if _, err := engine.ConnectNetwork(ctx, network, id); err != nil {
			t.Fatal(err)
		}
		if err := client.Register(ctx, egressgate.Registration{Job: network, Sources: []string{n.Subnet}, Allow: []egressgate.Allow{{Host: "example.invalid", Port: 443}}}); err != nil {
			t.Fatalf("register cycle%d: %v", i, err)
		}
		var status *egressgate.StatusError
		if err := egressgate.NewClient(base, "wrong-test-token").Health(ctx); !errors.As(err, &status) || status.Status != http.StatusUnauthorized {
			t.Fatalf("control authentication lost: %v", err)
		}
		if err := client.Unregister(ctx, network); err != nil {
			t.Fatal(err)
		}
		if err := engine.DisconnectNetwork(ctx, network, id); err != nil {
			t.Fatal(err)
		}
		if err := engine.RemoveNetwork(ctx, network); err != nil {
			t.Fatal(err)
		}
		if err := client.Health(ctx); err != nil {
			t.Fatalf("management transport lost after cleanup cycle%d: %v", i, err)
		}
		t.Logf("authenticated registration and management transport retained after internal-network cycle%d", i)
	}
}
