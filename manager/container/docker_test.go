package container

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateBodyIsolatesTheJob(t *testing.T) {
	b := createBody(Spec{
		Image: "img", Cmd: []string{"oyzu-executor"}, User: "1000:1000", Volume: "v-work", WorkDir: "/work",
		NanoCPUs: 2e9, MemoryBytes: 1 << 30, PidsLimit: 4096, Network: "bridge",
	})
	hc := b.HostConfig
	if hc.Privileged || !slices.Equal(hc.CapDrop, []string{"ALL"}) ||
		!hc.sandbox().applied() {
		t.Fatalf("privileges: %+v", hc)
	}
	if len(hc.Mounts) != 1 || hc.Mounts[0] != (mount{Type: "volume", Source: "v-work", Target: "/work"}) {
		t.Fatalf("mounts = %+v", hc.Mounts)
	}
	if hc.NetworkMode != "bridge" || hc.MemorySwap != 1<<30 || hc.PidsLimit != 4096 || hc.NanoCpus != 2e9 {
		t.Fatalf("limits: %+v", hc)
	}
	raw, _ := json.Marshal(b)
	for _, banned := range []string{"docker.sock", "podman.sock", "Binds", "CapAdd", `"host"`, "Devices"} {
		if strings.Contains(string(raw), banned) {
			t.Fatalf("create body mentions %s: %s", banned, raw)
		}
	}
}

// engineStub records requests and answers them from routes.
type engineStub struct {
	mu   sync.Mutex
	seen []string
	body map[string][]byte
}

func newStub(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) (*Docker, *engineStub) {
	s := &engineStub{body: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/"+apiVersion)
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, key+"?"+r.URL.RawQuery)
		s.body[key] = b
		s.mu.Unlock()
		if h, ok := routes[key]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no such thing"}`))
	}))
	t.Cleanup(srv.Close)
	d, err := NewDocker("tcp://"+strings.TrimPrefix(srv.URL, "http://"), DockerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

func reply(code int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

func TestDockerClient(t *testing.T) {
	ctx := context.Background()
	d, s := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /info":                      reply(200, `{"OSType":"linux","Architecture":"aarch64","NCPU":4,"MemTotal":1024}`),
		"POST /containers/create":        reply(201, `{"Id":"abc"}`),
		"PUT /containers/abc/archive":    reply(200, ``),
		"POST /containers/abc/start":     reply(204, ``),
		"POST /containers/abc/wait":      reply(200, `{"StatusCode":2}`),
		"GET /containers/abc/json":       reply(200, `{"State":{"Running":false,"ExitCode":2,"OOMKilled":true}}`),
		"POST /containers/abc/stop":      reply(304, ``),
		"GET /containers/json":           reply(200, `[{"Id":"abc","Names":["/oyzu-1"],"Labels":{"a":"b"},"State":"exited"}]`),
		"POST /images/create":            reply(200, `{"status":"Pulling"}`+"\n"+`{"error":"manifest unknown"}`),
		"GET /volumes":                   reply(200, `{"Volumes":[{"Name":"v","Labels":{"a":"b"}}]}`),
		"GET /images/ghcr.io/o/e:1/json": reply(200, `{}`),
	})
	info, err := d.Info(ctx)
	if err != nil || info.Architecture != "aarch64" || info.NCPU != 4 {
		t.Fatalf("Info = %+v, %v", info, err)
	}
	if ok, err := d.ImagePresent(ctx, "ghcr.io/o/e:1"); !ok || err != nil {
		t.Fatalf("ImagePresent(present) = %v, %v", ok, err)
	}
	if ok, err := d.ImagePresent(ctx, "ghcr.io/o/missing:1"); ok || err != nil {
		t.Fatalf("ImagePresent(missing) = %v, %v", ok, err)
	}
	if err := d.PullImage(ctx, "ghcr.io/o/e:1"); err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("PullImage = %v; a failure in the stream must be an error", err)
	}
	id, err := d.CreateContainer(ctx, "oyzu-1", Spec{Image: "img", Volume: "v", WorkDir: "/work", Network: "bridge"})
	if err != nil || id != "abc" {
		t.Fatalf("CreateContainer = %q, %v", id, err)
	}
	var sent containerConfig
	if err := json.Unmarshal(s.body["POST /containers/create"], &sent); err != nil || sent.HostConfig.Privileged ||
		!slices.Equal(sent.HostConfig.CapDrop, []string{"ALL"}) {
		t.Fatalf("create body = %s", s.body["POST /containers/create"])
	}
	if err := d.CopyFiles(ctx, id, "/", []byte("tar")); err != nil {
		t.Fatal(err)
	}
	if err := d.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	if code, err := d.WaitContainer(ctx, id); code != 2 || err != nil {
		t.Fatalf("WaitContainer = %d, %v", code, err)
	}
	if st, err := d.InspectContainer(ctx, id); !st.OOMKilled || st.ExitCode != 2 || err != nil {
		t.Fatalf("InspectContainer = %+v, %v", st, err)
	}
	if err := d.StopContainer(ctx, id, 30*time.Second); err != nil {
		t.Fatalf("StopContainer on a stopped container = %v", err)
	}
	if err := d.RemoveContainer(ctx, "gone"); err != nil {
		t.Fatalf("RemoveContainer on a missing container = %v", err)
	}
	if err := d.RemoveVolume(ctx, "gone"); err != nil {
		t.Fatalf("RemoveVolume on a missing volume = %v", err)
	}
	cs, err := d.ListContainers(ctx, map[string]string{"a": "b"})
	if err != nil || len(cs) != 1 || cs[0].Name != "oyzu-1" || cs[0].Labels["a"] != "b" {
		t.Fatalf("ListContainers = %+v, %v", cs, err)
	}
	vs, err := d.ListVolumes(ctx, map[string]string{"a": "b"})
	if err != nil || len(vs) != 1 || vs[0].Name != "v" {
		t.Fatalf("ListVolumes = %+v, %v", vs, err)
	}

	want := []string{
		"POST /containers/create?name=oyzu-1",
		"PUT /containers/abc/archive?path=%2F",
		"POST /containers/abc/wait?condition=not-running",
		"POST /containers/abc/stop?t=30",
		"DELETE /containers/gone?force=1&v=1",
		`GET /containers/json?all=1&filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D`,
	}
	for _, w := range want {
		if !slices.Contains(s.seen, w) {
			t.Errorf("no request %s in %q", w, s.seen)
		}
	}
}

func TestNewDockerRefusesPlaintextToAnotherHost(t *testing.T) {
	_, err := NewDocker("tcp://docker.example:2375", DockerOptions{})
	if err == nil || !strings.Contains(err.Error(), "--engine-allow-plaintext") {
		t.Fatalf("plain HTTP to another host = %v", err)
	}
	for _, host := range []string{"tcp://127.0.0.1:2375", "tcp://localhost:2375", "tcp://[::1]:2375"} {
		d, err := NewDocker(host, DockerOptions{})
		if err != nil || !strings.HasPrefix(d.base, "http://") {
			t.Fatalf("%s: %v", host, err)
		}
	}
	d, err := NewDocker("tcp://docker.example:2375", DockerOptions{AllowPlaintext: true})
	if err != nil || d.base != "http://docker.example:2375/"+apiVersion {
		t.Fatalf("opted-in plain HTTP = %+v, %v", d, err)
	}
	if _, err := NewDocker("unix:///run/podman/podman.sock", DockerOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDocker("ssh://docker.example", DockerOptions{}); err == nil {
		t.Fatal("accepted an ssh engine")
	}
}

func TestContainerLogsDemultiplexes(t *testing.T) {
	frame := func(stream byte, s string) []byte {
		n := len(s)
		return append([]byte{stream, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, s...)
	}
	body := append(frame(1, "out line\n"), frame(2, "err line\n")...)
	d, s := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /containers/c1/logs": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) },
	})
	got, err := d.ContainerLogs(context.Background(), "c1", 40)
	if err != nil || string(got) != "out line\nerr line\n" {
		t.Fatalf("ContainerLogs = %q, %v", got, err)
	}
	if q := s.seen[0]; !strings.Contains(q, "tail=40") || !strings.Contains(q, "stderr=1") {
		t.Fatalf("request = %s", q)
	}
	if got := demux([]byte("plain text")); string(got) != "plain text" {
		t.Fatalf("demux of a TTY stream = %q", got)
	}
}

func TestPipePath(t *testing.T) {
	for in, want := range map[string]string{
		"npipe:////./pipe/docker_engine": `\\.\pipe\docker_engine`,
		"npipe://./pipe/podman":          `\\.\pipe\podman`,
	} {
		u, _ := url.Parse(in)
		if got := pipePath(u); got != want {
			t.Errorf("pipePath(%s) = %s, want %s", in, got, want)
		}
	}
}

// writePKI writes a CA, a server certificate for 127.0.0.1 and a client
// certificate, the way DOCKER_CERT_PATH holds them, and returns the server's
// TLS config, which requires a client certificate from the CA.
func writePKI(t *testing.T, dir string) *tls.Config {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	caKey := newKey()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, usage x509.ExtKeyUsage, ips []net.IP) ([]byte, *ecdsa.PrivateKey) {
		k := newKey()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	writePEM := func(name, typ string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePEM("ca.pem", "CERTIFICATE", caDER)
	clientDER, clientKey := issue(2, x509.ExtKeyUsageClientAuth, nil)
	writePEM("cert.pem", "CERTIFICATE", clientDER)
	kb, _ := x509.MarshalECPrivateKey(clientKey)
	writePEM("key.pem", "EC PRIVATE KEY", kb)
	serverDER, serverKey := issue(3, x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
		ClientCAs:    pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
}

func TestDockerUsesTLSClientCertificates(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client certificate", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"OSType":"linux","Architecture":"x86_64","NCPU":2}`))
	}))
	srv.TLS = writePKI(t, dir)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host := "tcp://" + strings.TrimPrefix(srv.URL, "https://")

	d, err := NewDocker(host, DockerOptions{CertPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	info, err := d.Info(context.Background())
	if err != nil || info.NCPU != 2 {
		t.Fatalf("Info over TLS = %+v, %v", info, err)
	}
	// Without ca.pem the server's certificate is checked against the system
	// roots, which do not hold the test CA: verification is never skipped.
	other := t.TempDir()
	for _, f := range []string{"cert.pem", "key.pem"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		_ = os.WriteFile(filepath.Join(other, f), b, 0o600)
	}
	d, err = NewDocker(host, DockerOptions{CertPath: other})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Info(context.Background()); err == nil {
		t.Fatal("trusted a server certificate from an unknown CA")
	}
}

func TestEngineCallsHaveADeadline(t *testing.T) {
	release := make(chan struct{})
	d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /containers/create": func(http.ResponseWriter, *http.Request) { <-release },
	})
	// Registered after the stub, so it runs before the server's Close waits
	// for the hung handler.
	t.Cleanup(func() { close(release) })
	d.callTimeout = 50 * time.Millisecond
	start := time.Now()
	_, err := d.CreateContainer(context.Background(), "c", Spec{})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a hung create returned %v after %s", err, time.Since(start))
	}
}

func TestCreateBodyForASandboxedJobAndTheGateway(t *testing.T) {
	b := createBody(Spec{
		Image: "img", Cmd: []string{"oyzu-executor", "gateway"}, User: "1000:1000", Network: "oyzu-7-job-1",
		Env: []string{"HTTPS_PROXY=http://10.0.0.2:3128"}, DNS: []string{"10.0.0.2"}, ReadOnly: true,
		Sysctls: map[string]string{"net.ipv4.ip_unprivileged_port_start": "53"}, Publish: []int{9091},
	})
	hc := b.HostConfig
	if len(hc.Mounts) != 0 || !hc.ReadonlyRootfs || !slices.Equal(hc.Dns, []string{"10.0.0.2"}) ||
		hc.Sysctls["net.ipv4.ip_unprivileged_port_start"] != "53" {
		t.Fatalf("host config = %+v", hc)
	}
	if pb := hc.PortBindings["9091/tcp"]; len(pb) != 1 || pb[0].HostIp != "127.0.0.1" || pb[0].HostPort != "" {
		t.Fatalf("the control port must be published on loopback only: %+v", hc.PortBindings)
	}
	if _, ok := b.ExposedPorts["9091/tcp"]; !ok || !slices.Contains(b.Env, "HTTPS_PROXY=http://10.0.0.2:3128") || hc.Privileged {
		t.Fatalf("config = %+v", b)
	}
}

func TestDockerNetworks(t *testing.T) {
	ctx := context.Background()
	d, s := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /networks/create": reply(201, `{"Id":"n1"}`),
		"GET /networks/n1": reply(200, `{"Id":"n1","Name":"oyzu-7-job-1","Labels":{"a":"b"},`+
			`"IPAM":{"Config":[{"Subnet":"fd00::/64"},{"Subnet":"172.30.0.0/16"}]}}`),
		"GET /networks":                   reply(200, `[{"Id":"n1","Name":"oyzu-7-job-1","Labels":{"a":"b"},"IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]}}]`),
		"POST /networks/n1/connect":       reply(200, ``),
		"POST /networks/n1/disconnect":    reply(200, ``),
		"GET /containers/gw/json":         reply(200, `{"NetworkSettings":{"Networks":{"n1":{"IPAddress":"172.30.0.2"}},"Ports":{"9091/tcp":[{"HostIp":"127.0.0.1","HostPort":"49153"}]}}}`),
		"DELETE /networks/n1":             reply(204, ``),
		"POST /networks/gone/disconnect":  reply(404, `{"message":"no such container"}`),
		"POST /networks/other/disconnect": reply(403, `{"message":"container gw is not connected to network other"}`),
	})
	n, err := d.CreateNetwork(ctx, "oyzu-7-job-1", NetworkSpec{Internal: true, Labels: map[string]string{"a": "b"}})
	if err != nil || n.ID != "n1" || n.Subnet != "172.30.0.0/16" {
		t.Fatalf("CreateNetwork = %+v, %v", n, err)
	}
	var sent map[string]any
	if err := json.Unmarshal(s.body["POST /networks/create"], &sent); err != nil || sent["Internal"] != true || sent["Driver"] != "bridge" {
		t.Fatalf("create body = %s", s.body["POST /networks/create"])
	}
	if ip, err := d.ConnectNetwork(ctx, "n1", "gw"); err != nil || ip != "172.30.0.2" {
		t.Fatalf("ConnectNetwork = %q, %v", ip, err)
	}
	if port, err := d.PublishedPort(ctx, "gw", 9091); err != nil || port != 49153 {
		t.Fatalf("PublishedPort = %d, %v", port, err)
	}
	if _, err := d.PublishedPort(ctx, "gw", 1); err == nil {
		t.Fatal("PublishedPort invented a port")
	}
	if ns, err := d.ListNetworks(ctx, map[string]string{"a": "b"}); err != nil || len(ns) != 1 || ns[0].Subnet != "172.30.0.0/16" {
		t.Fatalf("ListNetworks = %+v, %v", ns, err)
	}
	for _, name := range []string{"n1", "gone", "other"} {
		if err := d.DisconnectNetwork(ctx, name, "gw"); err != nil {
			t.Errorf("DisconnectNetwork(%s) = %v", name, err)
		}
	}
	if err := d.RemoveNetwork(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveNetwork(ctx, "missing"); err != nil {
		t.Fatalf("RemoveNetwork on a missing network = %v", err)
	}
}

func TestDockerOmitsIPv6SysctlsOnlyOnAnIPv6LessKernel(t *testing.T) {
	ctx := context.Background()
	spec := Spec{Image: "img", Network: "bridge", Sysctls: map[string]string{
		"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1", "net.ipv4.ip_unprivileged_port_start": "53",
	}}
	for _, noIPv6 := range []bool{false, true} {
		d, s := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
			"POST /containers/create": reply(201, `{"Id":"abc"}`),
		})
		d.noIPv6 = noIPv6
		if _, err := d.CreateContainer(ctx, "oyzu-1", spec); err != nil {
			t.Fatal(err)
		}
		var sent containerConfig
		if err := json.Unmarshal(s.body["POST /containers/create"], &sent); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"net.ipv4.ip_unprivileged_port_start": "53"}
		if !noIPv6 {
			want = spec.Sysctls
		}
		if !maps.Equal(sent.HostConfig.Sysctls, want) {
			t.Fatalf("noIPv6=%v: sysctls = %v, want %v", noIPv6, sent.HostConfig.Sysctls, want)
		}
	}
	if len(spec.Sysctls) != 3 {
		t.Fatal("the caller's spec must not be changed")
	}
	if got := withoutIPv6Disable(map[string]string{"net.ipv6.conf.all.disable_ipv6": "1"}); got != nil {
		t.Fatalf("only IPv6 settings leave no sysctls, got %v", got)
	}
}
