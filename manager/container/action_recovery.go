package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

const actionRecordFile = runnerclient.ActionResourcesFile

var actionResourceName = regexp.MustCompile(`^oyzu-action-[0-9a-f]{32}$`)

type actionRecord struct {
	Owner runnerclient.ActionOwner `json:"owner"`
	Name  string                   `json:"name"`
}

func (r actionRecord) labels() map[string]string {
	return map[string]string{"oyzu.io/action": r.Name, "oyzu.io/action-manager": strconv.FormatInt(r.Owner.ManagerID, 10),
		"oyzu.io/action-job": strconv.FormatInt(r.Owner.JobID, 10), "oyzu.io/action-attempt": strconv.Itoa(r.Owner.Attempt), "oyzu.io/action-owner": r.Owner.Directory}
}

func writeActionRecord(record actionRecord) error {
	if err := record.Owner.Validate(); err != nil {
		return err
	}
	anchor, err := runnerclient.ReadActionOwner(record.Owner.Directory)
	if err != nil {
		return err
	}
	if anchor != record.Owner {
		return errors.New("action owner does not match manager anchor")
	}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(record.Owner.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	// The record is synced before the first engine allocation. A crash during
	// this write cannot leave an unrecorded container or volume.
	f, err := root.OpenFile(actionRecordFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// CleanupAction reconciles only the exact local journal and its full engine
// ownership labels. It is shared by normal exit, process teardown and restart.
func (r *ActionRuntime) CleanupAction(ctx context.Context, owner runnerclient.ActionOwner) error {
	if err := owner.Validate(); err != nil {
		return err
	}
	anchor, err := runnerclient.ReadActionOwner(owner.Directory)
	if err != nil {
		return err
	}
	if anchor != owner {
		return errors.New("action cleanup owner does not match manager anchor")
	}
	root, err := os.OpenRoot(owner.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(actionRecordFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, 8193))
	closeErr := f.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return err
	}
	var record actionRecord
	if len(b) > 8192 || json.Unmarshal(b, &record) != nil || record.Owner != owner || !actionResourceName.MatchString(record.Name) {
		return errors.New("invalid action recovery record")
	}
	if r == nil || r.Engine == nil {
		return errors.New("action recovery engine unavailable")
	}
	labels := record.labels()
	containers, err := r.Engine.ListContainers(ctx, labels)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.Name != record.Name || !actionLabelsMatch(c.Labels, labels) {
			return errors.New("action container ownership differs from journal")
		}
		state, err := r.Engine.InspectContainer(ctx, c.ID)
		if err != nil {
			return err
		}
		if state.Running {
			if err = r.Engine.StopContainer(ctx, c.ID, 5*time.Second); err != nil {
				return fmt.Errorf("stop owned action: %w", err)
			}
			state, err = r.Engine.InspectContainer(ctx, c.ID)
			if err != nil {
				return err
			}
			if state.Running {
				return errors.New("owned action remains running")
			}
		}
		if err = r.Engine.RemoveContainer(ctx, c.ID); err != nil {
			return err
		}
	}
	remaining, err := r.Engine.ListContainers(ctx, labels)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("owned action container remains after cleanup")
	}
	volumes, err := r.Engine.ListVolumes(ctx, labels)
	if err != nil {
		return err
	}
	for _, v := range volumes {
		if v.Name != record.Name || !actionLabelsMatch(v.Labels, labels) {
			return errors.New("action volume ownership differs from journal")
		}
		if err = r.Engine.RemoveVolume(ctx, v.Name); err != nil {
			return err
		}
	}
	volumes, err = r.Engine.ListVolumes(ctx, labels)
	if err != nil {
		return err
	}
	if len(volumes) != 0 {
		return errors.New("owned action volume remains after cleanup")
	}
	return root.Remove(actionRecordFile)
}

func actionLabelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}
