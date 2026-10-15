package executor

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/oyzuai/fleet/runnerclient"
)

func TestSliceInputRetainsAdmittedPlanAndCoupledGroup(t *testing.T) {
	job := runnerclient.Job{Operation: "build", SliceTargets: []string{"shared", "api"},
		Handoff:      "oci://registry.example/account/project/run-handoff/run",
		AdmittedPlan: json.RawMessage(`{"kind":"build-plan","source":{"treeDigest":"sha256:source"},"actions":[{"id":"shared:build","argv":["native","a b"]}]}`)}
	root := t.TempDir()
	input, err := sliceInput(root, job)
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Root         string
		Targets      []string
		Handoff      string
		AdmittedPlan json.RawMessage
	}
	if err := json.Unmarshal(input, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Root != filepath.Clean(root) || len(actual.Targets) != 2 || actual.Targets[0] != "shared" || actual.Targets[1] != "api" || actual.Handoff != job.Handoff || !bytes.Equal(actual.AdmittedPlan, job.AdmittedPlan) {
		t.Fatalf("assignment changed: %s", input)
	}
}

func TestSliceInputRefusesMissingAndPreviewAdmission(t *testing.T) {
	valid := runnerclient.Job{Operation: "build", SliceTargets: []string{"api"},
		Handoff:      "oci://registry.example/account/project/run-handoff/run",
		AdmittedPlan: json.RawMessage(`{"kind":"build-plan"}`)}
	for _, modify := range []func(*runnerclient.Job){
		func(j *runnerclient.Job) { j.AdmittedPlan = nil },
		func(j *runnerclient.Job) { j.AdmittedPlan = json.RawMessage(`{"kind":"build-preview"}`) },
		func(j *runnerclient.Job) { j.AdmittedPlan = json.RawMessage(`{`) },
		func(j *runnerclient.Job) { j.AdmittedPlan = bytes.Repeat([]byte(" "), runnerclient.MaxPlanRecord+1) },
		func(j *runnerclient.Job) { j.SliceTargets = nil },
		func(j *runnerclient.Job) { j.Handoff = "" },
		func(j *runnerclient.Job) { j.Operation = "run" },
	} {
		job := valid
		modify(&job)
		if _, err := sliceInput(t.TempDir(), job); err == nil {
			t.Fatal("incomplete native admission was accepted")
		}
	}
}
