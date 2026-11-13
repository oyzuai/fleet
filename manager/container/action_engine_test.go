package container

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestActionEnginePreservesSeparatedLogsAndRejectsTruncation(t *testing.T) {
	frame := func(stream byte, s string) []byte {
		b := make([]byte, 8)
		b[0] = stream
		binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
		return append(b, []byte(s)...)
	}
	for _, broken := range []bool{false, true} {
		d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /containers/action/logs": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("tail") != "" {
				t.Error("action logs were tailed")
			}
			b := append(frame(1, "out"), frame(2, "err")...)
			if broken {
				b = b[:len(b)-1]
			}
			w.Write(b)
		}})
		out, stderr, err := d.ContainerOutput(context.Background(), "action")
		if broken {
			if err == nil {
				t.Fatal("accepted truncated logs")
			}
		} else if err != nil || string(out) != "out" || string(stderr) != "err" {
			t.Fatalf("logs: %q %q %v", out, stderr, err)
		}
	}
}

func TestActionEngineVerifiesActualAllocation(t *testing.T) {
	a := testAction()
	spec := Spec{Image: a.Image, Entrypoint: []string{"tool"}, Cmd: []string{}, User: "1000:1000", Volume: "private", VolumePath: "/work", VolumeNoCopy: true, WorkDir: "/work/sub", Network: "none", ReadOnly: true, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32}
	body := createBody(spec)
	if body.Entrypoint[0] != "tool" || body.HostConfig.Mounts[0].Target != "/work" || body.HostConfig.Mounts[0].VolumeOptions == nil || !body.HostConfig.Mounts[0].VolumeOptions.NoCopy {
		t.Fatal("image entrypoint or volume copy not overridden")
	}
	for _, unsafe := range []bool{false, true} {
		d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /containers/action/json": func(w http.ResponseWriter, r *http.Request) {
			mounts := []map[string]any{{"Type": "volume", "Name": "private", "Destination": "/work", "RW": true}}
			if unsafe {
				mounts = append(mounts, map[string]any{"Type": "bind", "Destination": "/run/engine.sock"})
			}
			json.NewEncoder(w).Encode(map[string]any{"Config": body, "HostConfig": body.HostConfig, "Mounts": mounts})
		}})
		err := d.VerifyActionContainer(context.Background(), "action", spec)
		if (err != nil) != unsafe {
			t.Fatalf("allocation acceptance: %v", err)
		}
	}
}

func TestActionEngineReadinessRefusesMissingIsolation(t *testing.T) {
	for _, profile := range []string{"linux-seccomp", "windows", "linux-no-seccomp", "linux-no-limits"} {
		d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /info": func(w http.ResponseWriter, r *http.Request) {
			info := Info{OSType: "linux", MemoryLimit: true, CpuCfsQuota: true, CpuCfsPeriod: true, PidsLimit: true,
				SecurityOptions: []string{"name=seccomp,profile=builtin"}}
			if profile == "linux-no-limits" {
				info.MemoryLimit = false
			}
			if profile == "windows" {
				info.OSType = "windows"
			}
			if profile == "linux-no-seccomp" {
				info.SecurityOptions = nil
			}
			json.NewEncoder(w).Encode(info)
		}})
		err := d.ActionReady(context.Background())
		if (err == nil) != (profile == "linux-seccomp") {
			t.Fatalf("readiness %s: %v", profile, err)
		}
	}
}

func TestActionEngineRejectsOversizedLogs(t *testing.T) {
	d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /containers/action/logs": func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 8)
		b[0] = 1
		binary.BigEndian.PutUint32(b[4:], runnerclient.MaxActionLogs+1)
		w.Write(b)
		w.Write([]byte(strings.Repeat("x", runnerclient.MaxActionLogs+1)))
	}})
	if _, _, err := d.ContainerOutput(context.Background(), "action"); err == nil {
		t.Fatal("accepted oversized logs")
	}
}
