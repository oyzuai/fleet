package container

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
		!slices.Equal(hc.SecurityOpt, []string{"no-new-privileges:true"}) {
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
	d, err := NewDocker("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
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

func TestNewDockerRefusesNamedPipes(t *testing.T) {
	if _, err := NewDocker("npipe:////./pipe/docker_engine"); err == nil {
		t.Fatal("accepted a named pipe")
	}
	if _, err := NewDocker("unix:///run/podman/podman.sock"); err != nil {
		t.Fatal(err)
	}
}
