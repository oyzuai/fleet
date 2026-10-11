package manager

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// executorRecord is the file in a job's directory that names the executor
// running there, so a manager restarted after a crash can tell a live
// executor from a dead one before it removes the directory.
const executorRecord = "executor.json"

// survivorPoll is how often an adopted executor is checked for exit.
const survivorPoll = 5 * time.Second

// errProcessGone means no process has the recorded PID.
var errProcessGone = errors.New("no such process")

// record names an executor by PID and the time its process started: a PID
// alone can be reused by an unrelated process, the pair cannot.
type record struct {
	PID     int    `json:"pid"`
	Start   string `json:"start"`
	Job     JobID  `json:"job"`
	Attempt int    `json:"attempt"`
}

func writeRecord(dir string, r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, executorRecord), b)
}

func readRecord(dir string) (record, error) {
	var r record
	b, err := os.ReadFile(filepath.Join(dir, executorRecord))
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.PID <= 0 || r.Start == "" {
		return r, errors.New("the executor record names no process")
	}
	return r, nil
}

// survivorState is what a job directory's executor record says about it.
type survivorState int

const (
	// survivorDead: no record, or its process is gone, or its PID now
	// belongs to another process. The directory can go.
	survivorDead survivorState = iota
	// survivorAlive: the recorded executor is still running.
	survivorAlive
	// survivorUnknown: the process could not be checked. The directory
	// stays, and nothing is killed, until a later reap can tell.
	survivorUnknown
)

// survivor checks a job directory's executor record against the running
// processes.
func survivor(dir string) (survivorState, record, error) {
	r, err := readRecord(dir)
	if errors.Is(err, os.ErrNotExist) {
		return survivorDead, r, nil
	}
	if err != nil {
		// A torn record: the manager died while writing it, right after
		// starting the executor, which may be running.
		return survivorUnknown, r, err
	}
	start, err := processStart(r.PID)
	switch {
	case errors.Is(err, errProcessGone):
		return survivorDead, r, nil
	case err != nil:
		return survivorUnknown, r, err
	case start != r.Start:
		return survivorDead, r, nil
	}
	return survivorAlive, r, nil
}
