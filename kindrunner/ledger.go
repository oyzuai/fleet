package kindrunner

import (
	"bytes"
	"context"
	"fmt"
	"os"
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
	path string
	// fetched is the directory as runs gave it, packed, so an unchanged
	// ledger is not sent back.
	fetched []byte
}

func (l *ledgerDir) remove() {
	if l != nil {
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
	l := &ledgerDir{path: dir}
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
// next operation sees the ledger as it was before this one.
func (r *run) saveLedger(ctx context.Context, l *ledgerDir) {
	if l == nil {
		return
	}
	archive, n, err := tarFlat(l.path, runnerclient.MaxLedger)
	if err != nil {
		r.events.local("warn", "The kind's ledger was not kept: "+err.Error())
		return
	}
	if bytes.Equal(archive, l.fetched) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ledgerSaveTimeout)
	defer cancel()
	if err := r.cfg.Client.KindLedgerSave(ctx, r.cfg.Token, archive); err != nil {
		r.events.local("warn", "The kind's ledger was not kept: "+err.Error())
		return
	}
	r.log.Info("kind ledger kept", "files", n, "bytes", len(archive))
}
