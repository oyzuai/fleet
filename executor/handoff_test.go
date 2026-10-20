package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRetriesOnlyRetainedTransferInSameAttempt(t *testing.T) {
	for _, mode := range []string{"success", "cancel-on-finish", "failed-transfer", "invalid-record", "native-failure"} {
		t.Run(mode, func(t *testing.T) {
			job := buildJob("build", "oyzu", "build", "api", "--slice")
			job.Kind, job.SliceTargets = "slice", []string{"api"}
			job.Handoff = "oci://registry.example/account/project/run-handoff/run"
			job.AdmittedPlan = json.RawMessage(`{"kind":"build-plan"}`)
			runs, cfg, gitLog := setup(t, job)
			runs.cancelOnFinish = mode == "cancel-on-finish"
			callsPath := filepath.Join(t.TempDir(), "calls.jsonl")
			t.Setenv("FAKE_OYZU_HANDOFF", mode)
			t.Setenv("FAKE_OYZU_HANDOFF_CALLS", callsPath)
			if err := Run(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(callsPath)
			if err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(bytes.NewReader(calls))
			var operations []string
			for scanner.Scan() {
				var call struct {
					Args  []string
					Input map[string]json.RawMessage
				}
				if err := json.Unmarshal(scanner.Bytes(), &call); err != nil || len(call.Args) != 2 {
					t.Fatalf("invalid actual worker call: %s (%v)", scanner.Bytes(), err)
				}
				operations = append(operations, call.Args[1])
				if call.Args[1] == "retry-handoff" {
					var root, handoff string
					_ = json.Unmarshal(call.Input["root"], &root)
					_ = json.Unmarshal(call.Input["handoff"], &handoff)
					if len(call.Input) != 2 || root != filepath.Join(cfg.WorkDir, filepath.Dir(ManifestPath)) || handoff != job.Handoff {
						t.Fatalf("transfer retry changed assignment or requested execution: %s", scanner.Bytes())
					}
				}
			}
			want := "execute retry-handoff"
			if mode == "native-failure" {
				want = "execute"
			}
			if scanner.Err() != nil || strings.Join(operations, " ") != want {
				t.Fatalf("worker operations %v, want %s (%v)", operations, want, scanner.Err())
			}
			if len(runs.startups) != 1 || runs.finished == nil {
				t.Fatalf("transfer requested a new attempt or failed to finish: %#v", runs.finished)
			}
			gitCalls, _ := os.ReadFile(gitLog)
			if bytes.Count(gitCalls, []byte(`"checkout"`)) != 1 {
				t.Fatalf("transfer repeated checkout: %s", gitCalls)
			}
			onDisk, _ := os.ReadFile(filepath.Join(cfg.WorkDir, filepath.FromSlash(ManifestPath)))
			if !bytes.Contains(onDisk, []byte(`"status":"failed"`)) {
				t.Fatalf("failed invocation was rewritten: %s", onDisk)
			}
			if mode == "cancel-on-finish" {
				if runs.finished.State != "cancelled" || runs.finished.ReasonCode != "" || len(runs.finished.Outputs) != 0 {
					t.Fatalf("completed producer did not confirm cancellation race: %#v", runs.finished)
				}
				return
			}
			if mode != "success" {
				if runs.finished.State != "failed" || len(runs.finished.Outputs) != 0 {
					t.Fatalf("invalid recovery was accepted: %#v", runs.finished)
				}
				if mode == "failed-transfer" && (runs.finished.ReasonCode != "HANDOFF_PUSH_FAILED" || *runs.finished.ExitCode != 1) {
					t.Fatalf("transfer failure lost its classification or actual exit: %#v", runs.finished)
				}
				return
			}
			producer := []byte(`{"schemaVersion":"v1alpha1","kind":"build-manifest","runId":"original-producer","status":"succeeded","artifacts":[]}`)
			wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(producer))
			if runs.finished.State != "succeeded" || len(runs.finished.Outputs) != 1 || runs.finished.Outputs[0].Digest != wantDigest {
				t.Fatalf("retained producer digest was not reported: %#v", runs.finished)
			}
		})
	}
}
