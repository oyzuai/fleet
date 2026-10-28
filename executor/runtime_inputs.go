package executor

import (
	"encoding/json"
	"errors"
	"github.com/oyzuai/fleet/runnerclient"
)

// These are client execution inputs, not platform authorization or persisted
// plans. Only the executor supplies them after authenticating the actual job.
type assignmentRef struct {
	Job     int64 `json:"job"`
	Attempt int   `json:"attempt"`
}
type runtimeInputs struct {
	Assignment assignmentRef `json:"assignment"`
	Directory  string        `json:"directory"`
	Files      []string      `json:"files"`
	HTTPProxy  bool          `json:"http_proxy"`
}

func sliceInputWithRuntime(workDir string, job runnerclient.Job, inputs *runtimeInputs) ([]byte, error) {
	input, err := sliceInput(workDir, job)
	if err != nil || inputs == nil {
		return input, err
	}
	identity := assignmentRef{Job: job.ID, Attempt: job.Attempt}
	if identity.Job <= 0 || identity.Attempt <= 0 || identity != inputs.Assignment || inputs.Directory == "" || len(inputs.Files) > 32 {
		return nil, errors.New("runtime inputs do not match the current assignment")
	}
	var body map[string]json.RawMessage
	if err = json.Unmarshal(input, &body); err != nil {
		return nil, err
	}
	body["assignment"], err = json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	body["runtime_inputs"], err = json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
	input, err = json.Marshal(body)
	if err != nil || len(input) > runnerclient.MaxPlanRecord {
		return nil, errors.New("runtime execution request is too large")
	}
	return input, nil
}
