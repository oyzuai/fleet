package kindrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// Ledgers. A kind that must remember something between operations (the
// execution IDs it has applied, so apply is idempotent per execution ID)
// writes it to OYZU_KIND_LEDGER_DIR instead of its host state directory when
// runs keeps a ledger for the job. The runner fills the directory from runs
// before the kind starts and sends it back once the kind stops, whatever its
// outcome, so a later operation on the same kind and target sees it on any
// host. Like plan files, the runner never reads the files: they go over as
// one tar of the directory's regular files, at most runnerclient.MaxLedger.

// ContainerLedgerDir is where an image kind sees its ledger.
const ContainerLedgerDir = "/var/lib/oyzu/ledger"

// ledgerSaveTimeout bounds sending the ledger back.
const ledgerSaveTimeout = 30 * time.Second

// ledgerDir is the ledger directory of one job.
type ledgerDir struct {
	path      string
	recovery  string
	recovered bool
	keep      bool
	// fetched is the directory as runs gave it, packed, so an unchanged
	// ledger is not sent back.
	fetched []byte
}

func (l *ledgerDir) remove() {
	if l != nil && !l.keep {
		_ = os.RemoveAll(l.path)
	}
}

// ledger makes the job's ledger directory with what runs keeps in it. Nil
// when runs keeps no ledger for the job.
func (r *run) ledger(ctx context.Context) (*ledgerDir, error) {
	if !r.op.Ledger {
		return nil, nil
	}
	dir, err := os.MkdirTemp(r.cfg.SecretsDir, "oyzu-kind-ledger-")
	if err != nil {
		return nil, err
	}
	// record_id identifies the deployment record for this kind and target.
	// Include the repository to avoid crossing tenants on shared runners.
	key := sha256.Sum256([]byte(r.job.Repository + "\x00" + r.op.RecordID))
	if r.op.RecordID == "" {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("ledger requires a target record id")
	}
	l := &ledgerDir{path: dir, recovery: filepath.Join(r.cfg.StateDir, ".ledger-recovery", r.op.Kind.Name, fmt.Sprintf("%x", key))}
	entries, err := os.ReadDir(l.recovery)
	if err != nil && !os.IsNotExist(err) {
		l.remove()
		return nil, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		latest := entries[i]
		if !latest.IsDir() || strings.HasPrefix(latest.Name(), ".") {
			continue
		}
		if err := copyLedger(filepath.Join(l.recovery, latest.Name()), dir); err != nil {
			l.remove()
			return nil, err
		}
		l.recovered = true
		r.events.local("warn", "Using the host's unsaved ledger instead of the fetched ledger: it records work whose save was not confirmed.")
		return l, nil
	}
	archive, found, err := r.cfg.Client.KindLedger(ctx, r.cfg.Token)
	if err != nil {
		l.remove()
		return nil, fmt.Errorf("fetch the kind's ledger: %w", err)
	}
	if found {
		if err := untarFlat(archive, dir); err != nil {
			l.remove()
			return nil, fmt.Errorf("unpack the kind's ledger: %w", err)
		}
	}
	if l.fetched, _, err = tarFlat(dir, runnerclient.MaxLedger); err != nil {
		l.remove()
		return nil, err
	}
	return l, nil
}

// saveLedger sends the ledger back to runs when the kind changed it. It
// runs once the kind has stopped, even after a cancel or a timeout, since a
// command may have finished before the kind was stopped. A ledger that
// cannot be sent is a warning on the job: the result still stands, and the
// next operation on this host prefers its retained copy over runs.
func (r *run) saveLedger(ctx context.Context, l *ledgerDir) {
	r.saveLedgerWithin(ctx, l, ledgerSaveTimeout)
}

func (r *run) saveLedgerWithin(ctx context.Context, l *ledgerDir, budget time.Duration) {
	if l == nil {
		return
	}
	archive, n, err := tarFlat(l.path, runnerclient.MaxLedger)
	if err != nil {
		r.retainLedger(l, err)
		return
	}
	if !l.recovered && bytes.Equal(archive, l.fetched) {
		return
	}
	// Checkpoint before the network call: manager shutdown may interrupt retries.
	checkpointErr := checkpointLedger(l)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()
	if err := retry(ctx, func(ctx context.Context) error { return r.cfg.Client.KindLedgerSave(ctx, r.cfg.Token, archive) }); err != nil {
		if checkpointErr != nil {
			r.retainLedger(l, err)
		} else {
			r.events.local("warn", "The kind's ledger save failed; retained on this host for the next job on this kind and target: "+err.Error())
			r.log.Warn("ledger retained on host; local copy wins next time", "path", l.recovery)
		}
		return
	}
	if err := os.RemoveAll(l.recovery); err != nil {
		r.log.Warn("remove recovered ledger", "error", err)
	}
	r.log.Info("kind ledger kept", "files", n, "bytes", len(archive))
}

// retainLedger keeps failed saves outside the job directory, which the reaper removes.
func (r *run) retainLedger(l *ledgerDir, cause error) {
	if err := checkpointLedger(l); err != nil {
		l.keep = true
		r.log.Error("cannot retain ledger outside job directory", "path", l.path, "error", err)
		r.events.local("error", "The ledger could not be copied to durable storage; its job directory must be preserved: "+err.Error())
		return
	}
	r.events.local("warn", "The kind's ledger save failed; retained on this host for the next job on this kind and target: "+cause.Error())
	r.log.Warn("ledger retained on host; local copy wins next time", "path", l.recovery)
}

func checkpointLedger(l *ledgerDir) error {
	if err := os.MkdirAll(l.recovery, 0o700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(l.recovery, ".pending-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyLedger(l.path, stage); err != nil {
		return err
	}
	return os.Rename(stage, filepath.Join(l.recovery, fmt.Sprintf("%020d", time.Now().UnixNano())))
}

// copyLedger streams regular files without loading them into memory.
func copyLedger(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		err := func() error {
			in, err := os.Open(filepath.Join(src, entry.Name()))
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(filepath.Join(dst, entry.Name()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, in)
			if err == nil {
				err = out.Sync()
			}
			cerr := out.Close()
			if err != nil {
				return err
			}
			return cerr
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
