package runnerclient

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const ActionOwnerFile = "action-owner.json"
const ActionResourcesFile = "action-resources.json"

// ActionOwner is local trusted control data, never part of the server's action
// assignment or mounted into the child container.
type ActionOwner struct {
	ManagerID int64  `json:"manager_id"`
	JobID     int64  `json:"job_id"`
	Attempt   int    `json:"attempt"`
	Directory string `json:"directory"`
}

func (o ActionOwner) Validate() error {
	if o.ManagerID <= 0 || o.JobID <= 0 || o.Attempt <= 0 || !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory || filepath.Dir(o.Directory) == o.Directory {
		return errors.New("invalid trusted action owner")
	}
	return nil
}

// WriteActionOwner runs in the manager before the executor is started.
func WriteActionOwner(o ActionOwner) error {
	if err := o.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(o.Directory, ActionOwnerFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	return errors.Join(err, closeErr)
}

func ReadActionOwner(directory string) (ActionOwner, error) {
	var o ActionOwner
	root, err := os.OpenRoot(directory)
	if err != nil {
		return o, err
	}
	defer root.Close()
	f, err := root.Open(ActionOwnerFile)
	if err != nil {
		return o, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return o, err
	}
	if len(b) > 8192 {
		return o, errors.New("oversized action owner")
	}
	if err = json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	if err = o.Validate(); err != nil {
		return o, err
	}
	if o.Directory != directory {
		return o, errors.New("action owner directory changed")
	}
	return o, nil
}
