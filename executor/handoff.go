package executor

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/oyzuai/fleet/runnerclient"
)

// The private engine validates and transfers retained bytes, then returns their
// original successful producer record. The failed on-disk invocation stays
// immutable. Runs revalidates this digest through normal contribution admission.
func retainedHandoffOutputs(raw []byte) ([]runnerclient.Output, error) {
	if len(raw) > maxManifest {
		return nil, errors.New("retained handoff result exceeds the manifest limit")
	}
	raw = bytes.TrimSpace(raw)
	var record struct {
		Status string `json:"status"`
		RunID  string `json:"runId"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Status != "succeeded" || record.RunID == "" {
		return nil, errors.New("retained handoff did not return a completed successful producer")
	}
	return manifestOutputs(raw)
}

// A retry does not rewrite the failed transfer receipt. Match its successful
// retained producer to that fresh invocation before acknowledging a finish race.
func retainedNativeCompletion(failed, producer []byte) []byte {
	var before, result struct {
		RunID string `json:"runId"`
	}
	producer = bytes.TrimSpace(producer)
	if json.Unmarshal(failed, &before) != nil || json.Unmarshal(producer, &result) != nil || before.RunID == "" || before.RunID != result.RunID {
		return nil
	}
	return producer
}
