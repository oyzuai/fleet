package container

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func actionLogFrame(stream byte, s string) []byte {
	b := make([]byte, 8, 8+len(s))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(s)))
	return append(b, s...)
}

func attachActionFrames(t *testing.T, w http.ResponseWriter, r *http.Request, b []byte) {
	t.Helper()
	if r.URL.Query().Get("logs") != "0" || r.URL.Query().Get("stream") != "1" || r.Header.Get("Upgrade") != "tcp" {
		t.Error("action output did not attach to the live stream")
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()
	rw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	rw.Write(b)
	rw.Flush()
}

func TestActionEnginePreservesSeparatedLogsAndRejectsTruncation(t *testing.T) {
	for _, broken := range []bool{false, true} {
		d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"POST /containers/action/attach": func(w http.ResponseWriter, r *http.Request) {
			b := append(actionLogFrame(1, "out"), actionLogFrame(2, "err")...)
			if broken {
				b = b[:len(b)-1]
			}
			attachActionFrames(t, w, r, b)
		}})
		stream, err := d.AttachActionOutput(context.Background(), "action")
		if err != nil {
			t.Fatal(err)
		}
		out, stderr, err := readActionOutput(stream)
		stream.Close()
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
	spec := Spec{Image: a.Image, Entrypoint: []string{"tool"}, Cmd: []string{}, User: "1000:1000", Volume: "private", VolumePath: "/work", VolumeNoCopy: true, WorkDir: "/work/sub", Network: "none", ReadOnly: true, NanoCPUs: 1e9, MemoryBytes: 64 << 20, PidsLimit: 32, ActionUser: true}
	body := createBody(spec)
	if body.Entrypoint[0] != "tool" || body.HostConfig.Mounts[0].Target != "/work" || body.HostConfig.Mounts[0].VolumeOptions == nil || !body.HostConfig.Mounts[0].VolumeOptions.NoCopy {
		t.Fatal("image entrypoint or volume copy not overridden")
	}
	if body.HostConfig.LogConfig.Type != "json-file" || body.HostConfig.LogConfig.Config["max-size"] != strconv.Itoa(runnerclient.MaxActionLogs) || body.HostConfig.LogConfig.Config["max-file"] != "1" || body.HostConfig.Init == nil || *body.HostConfig.Init || body.HostConfig.RestartPolicy.Name != "no" || body.Healthcheck == nil || !reflect.DeepEqual(body.Healthcheck.Test, []string{"NONE"}) {
		t.Fatalf("unbounded logs or inherited lifecycle controls: %+v", body)
	}
	for _, test := range []struct {
		name   string
		change func(*containerConfig)
	}{
		{"valid", nil},
		{"extra mount", nil},
		{"default log driver", func(b *containerConfig) { b.HostConfig.LogConfig.Type = "" }},
		{"missing log bounds", func(b *containerConfig) { b.HostConfig.LogConfig.Config = nil }},
		{"oversized logs", func(b *containerConfig) {
			b.HostConfig.LogConfig.Config["max-size"] = strconv.Itoa(runnerclient.MaxActionLogs * 2)
		}},
		{"extra log files", func(b *containerConfig) { b.HostConfig.LogConfig.Config["max-file"] = "2" }},
		{"inherited init", func(b *containerConfig) { b.HostConfig.Init = nil }},
		{"enabled init", func(b *containerConfig) { enabled := true; b.HostConfig.Init = &enabled }},
		{"image healthcheck", func(b *containerConfig) { b.Healthcheck.Test = []string{"CMD", "unexpected"} }},
		{"restart enabled", func(b *containerConfig) { b.HostConfig.RestartPolicy.Name = "always" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /containers/action/json": func(w http.ResponseWriter, r *http.Request) {
				body := createBody(spec)
				if test.change != nil {
					test.change(&body)
				}
				mounts := []map[string]any{{"Type": "volume", "Name": "private", "Destination": "/work", "RW": true}}
				if test.name == "extra mount" {
					mounts = append(mounts, map[string]any{"Type": "bind", "Destination": "/run/engine.sock"})
				}
				json.NewEncoder(w).Encode(map[string]any{"Config": body, "HostConfig": body.HostConfig, "Mounts": mounts})
			}})
			err := d.VerifyActionContainer(context.Background(), "action", spec)
			if (err != nil) != (test.name != "valid") {
				t.Fatalf("allocation acceptance: %v", err)
			}
		})
	}
}

func TestActionEngineReadinessRefusesMissingIsolation(t *testing.T) {
	for _, profile := range []string{"linux-seccomp", "windows", "linux-no-seccomp", "linux-no-limits"} {
		d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"GET /info": func(w http.ResponseWriter, r *http.Request) {
			info := Info{OSType: "linux", Architecture: "x86_64", MemoryLimit: true, CpuCfsQuota: true, CpuCfsPeriod: true, PidsLimit: true,
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
	d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"POST /containers/action/attach": func(w http.ResponseWriter, r *http.Request) {
		attachActionFrames(t, w, r, actionLogFrame(1, strings.Repeat("x", runnerclient.MaxActionLogs+1)))
	}})
	stream, err := d.AttachActionOutput(context.Background(), "action")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, _, err := readActionOutput(stream); err == nil {
		t.Fatal("accepted oversized logs")
	}
}

func TestActionOutputShortLinesAndExactLimitNeverReset(t *testing.T) {
	for _, size := range []int{200 << 10, runnerclient.MaxActionLogs, runnerclient.MaxActionLogs + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			frames := bytes.Repeat(actionLogFrame(1, "\n"), size)
			out, stderr, err := readActionOutput(bytes.NewReader(frames))
			if size > runnerclient.MaxActionLogs {
				if err == nil || out != nil || stderr != nil {
					t.Fatal("accepted oversized short-line stream")
				}
			} else if err != nil || len(out) != size || len(stderr) != 0 {
				t.Fatalf("short-line output was lost: bytes=%d err=%v", len(out), err)
			}
		})
	}
}

func TestActionAttachmentCancellationUnblocksUpgradedRead(t *testing.T) {
	done := make(chan struct{})
	d, _ := newStub(t, map[string]func(http.ResponseWriter, *http.Request){"POST /containers/action/attach": func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		rw.Flush()
		io.Copy(io.Discard, conn)
		close(done)
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := d.AttachActionOutput(ctx, "action")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cancel()
	if _, _, err := readActionOutput(stream); err == nil {
		t.Fatal("canceled output read succeeded")
	}
	<-done
}

func TestActionVolumeRequiresExactTmpfsBoundsAndOwnership(t *testing.T) {
	labels := map[string]string{"oyzu.io/action": "private", "oyzu.io/action-role": "workspace"}
	for _, unsafe := range []bool{false, true} {
		d, stub := newStub(t, map[string]func(http.ResponseWriter, *http.Request){
			"POST /volumes/create": reply(http.StatusCreated, `{"Name":"private"}`),
			"GET /volumes/private": func(w http.ResponseWriter, r *http.Request) {
				options := workspaceOptions(4096, 64)
				if unsafe {
					options = nil
				}
				json.NewEncoder(w).Encode(Volume{Name: "private", Driver: "local", Labels: labels, Options: options})
			},
		})
		if err := d.CreateActionVolume(context.Background(), "private", labels, 4096, 64); (err != nil) != unsafe {
			t.Fatalf("volume acceptance: %v", err)
		}
		// newStub consumes and records the body before dispatching its handler.
		var body struct {
			Name, Driver       string
			DriverOpts, Labels map[string]string
		}
		stub.mu.Lock()
		raw := append([]byte{}, stub.body["POST /volumes/create"]...)
		stub.mu.Unlock()
		if err := json.Unmarshal(raw, &body); err != nil || body.Name != "private" || body.Driver != "local" || !reflect.DeepEqual(body.DriverOpts, workspaceOptions(4096, 64)) || !reflect.DeepEqual(body.Labels, labels) {
			t.Fatalf("unbounded or unowned volume request: %+v %v", body, err)
		}
	}
	spec := holderSpec(testAction().Image, "work", "bootstrap", labels)
	body := createBody(spec)
	if !spec.VolumeReadOnly || body.HostConfig.Init == nil || *body.HostConfig.Init || body.HostConfig.LogConfig.Type != "none" || body.HostConfig.RestartPolicy.Name != "no" || body.Healthcheck == nil || len(body.HostConfig.Mounts) != 2 || !body.HostConfig.Mounts[1].ReadOnly || body.HostConfig.MemorySwap != runnerclient.ActionHolderMemory {
		t.Fatalf("unsafe holder %+v", body)
	}
}
