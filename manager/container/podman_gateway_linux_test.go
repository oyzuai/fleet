//go:build linux

package container

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/egressgate"
)

type boundedGatewayEngine struct {
	Engine
	containers []string
}

func (e *boundedGatewayEngine) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	spec.MemoryBytes, spec.NanoCPUs = 64<<20, 500000000
	if spec.Labels[LabelRole] == roleGateway { spec.MemoryBytes = 128<<20 }
	id, err := e.Engine.CreateContainer(ctx, name, spec)
	if err == nil { e.containers = append(e.containers, id) }
	return id, err
}

func TestPodmanDriverGatewayProbeCleanup(t *testing.T) {
	socket, image := os.Getenv("FLEET_PODMAN_PROOF_SOCKET"), os.Getenv("FLEET_PODMAN_GATEWAY_IMAGE")
	if socket == "" || image == "" { t.Skip("dedicated Podman driver probe needs explicit socket and immutable local image") }
	if os.Geteuid() != 1002 || !strings.HasPrefix(socket, "/run/user/1002/") || !strings.HasPrefix(image, "localhost/oyzu-pool-executor@sha256:") { t.Fatal("proof restricted to dedicated uid1002 and immutable local executor image") }
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	engine, err := NewDocker("unix://"+socket, DockerOptions{})
	if err != nil { t.Fatal(err) }
	bounded := &boundedGatewayEngine{Engine: engine}
	d := &Driver{Engine: bounded, Image: image, Command: []string{"oyzu-executor"}, Manager: time.Now().UnixNano(), Pool: "oyzu-pool-slice1-proof", Egress: EgressEnforce}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		for _, id := range bounded.containers { if err := engine.RemoveContainer(cleanup, id); err != nil { t.Error(err) } }
		networks, err := engine.ListNetworks(cleanup, map[string]string{LabelManager: d.managerLabel()})
		if err != nil { t.Error(err); return }
		for _, network := range networks { if err := engine.RemoveNetwork(cleanup, network.Name); err != nil { t.Error(err) } }
	})
	for i := 0; i < 2; i++ {
		if err := d.probe(ctx); err != nil { t.Fatalf("real driver probe cycle%d: %v", i, err) }
		if err := d.gw.control.Health(ctx); err != nil { t.Fatalf("management transport lost after probe cycle%d: %v", i, err) }
		if err := d.Reap(ctx, nil); err != nil { t.Fatal(err) }
		if err := d.gw.control.Health(ctx); err != nil { t.Fatalf("management transport lost after Reap cycle%d: %v", i, err) }
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
