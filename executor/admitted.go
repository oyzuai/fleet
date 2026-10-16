package executor

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/oyzuai/fleet/runnerclient"
)

// sliceInput binds the current assignment to Oyzu's private native execution
// boundary. Oyzu owns source, command, tool and output contract verification;
// Fleet only transports the persisted plan and assigned group before effects.
func sliceInput(workDir string, job runnerclient.Job) ([]byte, error) {
	if job.Operation != "build" || len(job.SliceTargets) == 0 || job.Handoff == "" ||
		len(job.AdmittedPlan) == 0 || len(job.AdmittedPlan) > runnerclient.MaxPlanRecord {
		return nil, errors.New("slice has no bounded admitted plan, group or handoff")
	}
	var identity struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(job.AdmittedPlan, &identity) != nil || identity.Kind != "build-plan" {
		return nil, errors.New("slice requires an admitted executable build-plan")
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return nil, errors.New("slice work directory is unavailable")
	}
	request, err := json.Marshal(struct {
		Root         string          `json:"root"`
		Targets      []string        `json:"targets"`
		Handoff      string          `json:"handoff"`
		AdmittedPlan json.RawMessage `json:"admittedPlan"`
	}{root, job.SliceTargets, job.Handoff, job.AdmittedPlan})
	if err != nil || len(request) > runnerclient.MaxPlanRecord {
		return nil, errors.New("slice execution request is too large")
	}
	return request, nil
}
