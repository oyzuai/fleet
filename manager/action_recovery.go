package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oyzuai/fleet/runnerclient"
)

func (p *Process) cleanupActionDirectory(ctx context.Context, dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	dir = abs
	_, err = os.Stat(filepath.Join(dir, runnerclient.ActionOwnerFile))
	if errors.Is(err, os.ErrNotExist) {
		if _, recordErr := os.Stat(filepath.Join(dir, runnerclient.ActionResourcesFile)); !errors.Is(recordErr, os.ErrNotExist) {
			return errors.New("action resources lack trusted owner anchor")
		}
		return nil
	}
	if err != nil {
		return err
	}
	owner, err := runnerclient.ReadActionOwner(dir)
	if err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimPrefix(filepath.Base(dir), "job-"), "-", 3)
	if len(parts) != 3 {
		return errors.New("invalid action job directory")
	}
	job, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return err
	}
	attempt, err := strconv.Atoi(parts[1])
	if err != nil {
		return err
	}
	if owner.ManagerID != p.Manager || owner.JobID != job || owner.Attempt != attempt {
		return errors.New("action recovery owner differs from manager/job/attempt")
	}
	if p.ActionCleanup == nil {
		return errors.New("action recovery engine is unavailable")
	}
	if err = p.ActionCleanup(ctx, owner); err != nil {
		return fmt.Errorf("recover action %d/%d: %w", job, attempt, err)
	}
	return nil
}

func (p *Process) blockActionDirectory(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pr := range p.inUse {
		if filepath.Base(pr.dir) == name {
			return
		}
	}
	if _, ok := p.adopted[name]; ok {
		return
	}
	if p.blocked == nil {
		p.blocked = map[string]bool{}
	}
	p.blocked[name] = true
}

func (p *Process) releaseDirectory(dir string) {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for slot, pr := range p.inUse {
		if pr.dir == dir {
			select {
			case <-pr.done:
				delete(p.inUse, slot)
			default:
			}
		}
	}
	delete(p.blocked, filepath.Base(dir))
}
