//go:build unix

package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/runnerclient"
)

func runtimeProxyRig(t *testing.T, fixture http.Handler) (*egressProxy, string) {
	t.Helper()
	upstream := httptest.NewServer(fixture)
	t.Cleanup(upstream.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gateway := egressgate.New(egressgate.Config{Pool: "runtime-proof", Resolver: staticResolver{"allowed.example": "93.184.216.34", "denied.example": "93.184.216.35"}, Log: log,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
		}})
	t.Cleanup(gateway.Close)
	if err := gateway.Register(egressgate.Registration{Job: "17", Sources: []string{"127.0.0.0/8"}, Allow: []egressgate.Allow{{Host: "allowed.example", Port: 80}}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.ProxyHandler())
	t.Cleanup(server.Close)
	proxy, err := startEgress(runnerclient.Egress{}, nil, func(...string) {}, log, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.stop)
	dir, err := os.MkdirTemp("", "oyzu-runtime-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	stop, err := proxy.startRuntimeProxy(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return proxy, dir
}

func TestRuntimeSocketRetainsActualGatewayDenial(t *testing.T) {
	var receipts atomic.Int64
	_, dir := runtimeProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential reached destination")
		}
		receipts.Add(1)
		w.WriteHeader(201)
	}))
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "runtime.invalid"}), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "egress.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, test := range []struct {
		host string
		want int
	}{{"allowed.example", 201}, {"denied.example", 403}} {
		response, err := client.Get("http://" + test.host + "/receipt")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Fatalf("%s: status %d", test.host, response.StatusCode)
		}
	}
	if receipts.Load() != 1 {
		t.Fatalf("unexpected destination calls: %d", receipts.Load())
	}
}

// The selected qualification must run the compiled candidate and a real native
// Go test. Routine unit runs do not provision this separate integration proof.
func TestNativeRuntimeInputs(t *testing.T) {
	cli := os.Getenv("FLEET_NATIVE_CLI")
	if cli == "" {
		if os.Getenv("FLEET_RUNTIME_PROOF_REQUIRED") == "1" {
			t.Fatal("FLEET_NATIVE_CLI must identify the compiled candidate")
		}
		t.Skip("select runtime-inputs-proof with a compiled candidate")
	}
	if !filepath.IsAbs(cli) {
		t.Fatal("candidate CLI path must be absolute")
	}
	project := t.TempDir()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(raw[:])
	var receipts atomic.Int64
	_, private := runtimeProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/receipt" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(403)
			return
		}
		receipts.Add(1)
		w.WriteHeader(201)
		fmt.Fprint(w, "native-authenticated-receipt")
	}))
	files := map[string]string{
		"go.mod":       "module example.invalid/runtime-input\n\ngo 1.24.0\n",
		"main.go":      "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"runtime file proof\") }\n",
		"build.yaml":   "builds:\n  proof:\n    uses: go/app\n    path: .\n",
		"oyzu.toml":    "[tools]\ngo = \"1.24\"\n",
		"main_test.go": nativeRuntimeInputTest,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(project, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := os.ReadFile(filepath.Join("..", "oyzu.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(project, "oyzu.lock"), lock, 0600); err != nil {
		t.Fatal(err)
	}
	command := func(input []byte, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Dir = project
		cmd.Stdin = bytes.NewReader(input)
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		if err != nil {
			t.Logf("candidate %v failed: %s", args, strings.ReplaceAll(diagnostic.String(), token, "[redacted]"))
		}
		return out.Bytes(), err
	}
	if _, err = command(nil, "--root", project, "exec", "--", "gofmt", "-w", "main_test.go"); err != nil {
		t.Fatal(err)
	}
	prepare, _ := json.Marshal(map[string]any{"root": project, "targets": []string{"proof"}})
	plan, err := command(prepare, "__oyzu-build-worker", "prepare")
	if err != nil {
		t.Fatal(err)
	}
	var planRecord map[string]any
	if json.Unmarshal(plan, &planRecord) != nil || planRecord["kind"] != "build-plan" {
		t.Fatal("candidate did not return an actual executable plan")
	}
	value, _ := json.Marshal(map[string]string{"Token": token, "URL": "http://allowed.example/receipt"})
	if err = os.WriteFile(filepath.Join(private, "BUILD_TOKEN_FILE"), value, 0400); err != nil {
		t.Fatal(err)
	}
	identity := assignmentRef{Job: 17, Attempt: 1}
	inputs := &runtimeInputs{Assignment: identity, Directory: private, Files: []string{"BUILD_TOKEN_FILE"}, HTTPProxy: true}
	run := func(runtime *runtimeInputs, expected int) (map[string]any, []byte) {
		request, _ := json.Marshal(map[string]any{"root": project, "targets": []string{"proof"}, "admittedPlan": json.RawMessage(plan), "assignment": identity, "runtime_inputs": runtime})
		out, err := command(request, "__oyzu-build-worker", "execute")
		if expected == 0 && err != nil || expected != 0 && err == nil {
			t.Fatalf("unexpected native execution status: %v", err)
		}
		var manifest map[string]any
		if json.Unmarshal(out, &manifest) != nil {
			t.Fatal("candidate did not return a finalized native manifest")
		}
		return manifest, out
	}
	manifest, summary := run(inputs, 0)
	if manifest["status"] != "succeeded" || receipts.Load() != 1 {
		t.Fatal("real native Secret consumption did not complete")
	}
	if bytes.Contains(summary, []byte(token)) {
		t.Fatal("private value leaked into manifest")
	}
	reports, _ := manifest["reports"].([]any)
	passed := false
	for _, entry := range reports {
		report, _ := entry.(map[string]any)
		if report["format"] == "junit" {
			s, _ := report["summary"].(map[string]any)
			passed = s["passed"] == float64(1) && s["failed"] == float64(0) && s["skipped"] == float64(0)
		}
	}
	if !passed {
		t.Fatal("native test did not produce its required non-skipped report")
	}
	// Validate the usable result before the fixture's temporary tree is removed.
	artifacts, _ := manifest["artifacts"].([]any)
	var executable string
	for _, entry := range artifacts {
		artifact, _ := entry.(map[string]any)
		if artifact["name"] != "primary" || artifact["kind"] != "file" {
			continue
		}
		path, _ := artifact["path"].(string)
		if path == "" || filepath.IsAbs(path) || !filepath.IsLocal(path) {
			t.Fatal("invalid native artifact path")
		}
		executable = filepath.Join(project, "dist", filepath.FromSlash(path))
		data, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		if artifact["digest"] != digest || artifact["size"] != float64(len(data)) {
			t.Fatal("native artifact does not match its accepted manifest")
		}
	}
	if executable == "" {
		t.Fatal("native application artifact is absent")
	}
	applicationOutput, err := command(nil, "--root", project, "exec", "--", executable)
	if err != nil || string(applicationOutput) != "runtime file proof\n" {
		t.Fatal("accepted application did not execute with its expected result")
	}
	if err = filepath.WalkDir(filepath.Join(project, "dist"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(token)) {
			return fmt.Errorf("private value in output")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := receipts.Load()
	denied, _ := run(nil, 1)
	if denied["status"] == "succeeded" || receipts.Load() != before {
		t.Fatal("missing runtime inputs did not refuse the real native test")
	}
	wrong := *inputs
	wrong.Assignment.Attempt++
	request, _ := json.Marshal(map[string]any{"root": project, "targets": []string{"proof"}, "admittedPlan": json.RawMessage(plan), "assignment": identity, "runtime_inputs": wrong})
	if _, err = command(request, "__oyzu-build-worker", "execute"); err == nil {
		t.Fatal("mismatched runtime assignment accepted")
	}
	if receiptPath := os.Getenv("FLEET_RUNTIME_PROOF_RECEIPT"); receiptPath != "" {
		if !filepath.IsAbs(receiptPath) {
			t.Fatal("receipt path must be absolute")
		}
		receipt, err := json.MarshalIndent(map[string]any{
			"plan": planRecord, "manifest": manifest,
			"application_stdout": string(applicationOutput), "authenticated_receipts": receipts.Load(),
			"missing_inputs": "refused", "mismatched_assignment": "refused",
		}, "", "  ")
		if err != nil || len(receipt) > 20*1024*1024 || bytes.Contains(receipt, []byte(token)) {
			t.Fatal("unsafe or oversized proof receipt")
		}
		if err = os.WriteFile(receiptPath, receipt, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("real admitted native file test passed; missing input and assignment mismatch refused; authenticated receipts=%d", receipts.Load())
}

const nativeRuntimeInputTest = `package main

import (
 "context"
 "encoding/json"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "strings"
 "testing"
 "time"
)

func TestPrivateInput(t *testing.T) {
 path := os.Getenv("BUILD_TOKEN_FILE")
 if path == "" { t.Fatal("required runtime file is absent") }
 info, err := os.Stat(path)
 if err != nil || info.Mode().Perm() != 0400 { t.Fatal("private file mode") }
 data, err := os.ReadFile(path)
 if err != nil { t.Fatal("private file unavailable") }
 defer clear(data)
 var input struct { Token string; URL string }
 if json.Unmarshal(data, &input) != nil { t.Fatal("invalid private input") }
 socket := os.Getenv("OYZU_HTTP_PROXY_SOCKET")
 if socket == "" { t.Fatal("required runtime proxy is absent") }
 transport := &http.Transport{
  Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "runtime.invalid"}),
  DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
   return (&net.Dialer{}).DialContext(ctx, "unix", socket)
  },
 }
 defer transport.CloseIdleConnections()
 client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
 request, err := http.NewRequest("POST", input.URL, strings.NewReader("native proof"))
 if err != nil { t.Fatal("fixture request") }
 request.Header.Set("Authorization", "Bearer " + input.Token)
 response, err := client.Do(request)
 if err != nil { t.Fatal("fixture unavailable") }
 defer response.Body.Close()
 receipt, _ := io.ReadAll(io.LimitReader(response.Body, 128))
 if response.StatusCode != 201 || string(receipt) != "native-authenticated-receipt" {
  t.Fatal("fixture refused the current runtime input")
 }
}
`
