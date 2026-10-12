package executor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/egressgate"
)

const (
	// gatewayReadyTimeout is how long a job waits for the manager to register
	// it with the gateway, which it does just after starting the executor.
	gatewayReadyTimeout = time.Minute
	denialPollEvery     = 2 * time.Second
)

// waitGateway returns once the egress gateway knows this job: until then it
// would refuse every request, including the runner's own calls to runs.
func waitGateway(ctx context.Context, gateway string) error {
	jc := egressgate.NewJobClient(gateway)
	deadline := time.Now().Add(gatewayReadyTimeout)
	var last error
	for {
		ok, err := jc.Ready(ctx)
		if ok {
			return nil
		}
		if last = err; last == nil {
			last = fmt.Errorf("the gateway does not know this job")
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return fmt.Errorf("the egress gateway at %s is not ready: %w", gateway, last)
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// denialWatcher reads the gateway's denials for this job while it runs,
// writes each new destination's line to the job log, and keeps them for the
// job summary.
type denialWatcher struct {
	jc   *egressgate.JobClient
	log  *slog.Logger
	emit func(line string)

	mu    sync.Mutex
	after int
	seen  map[string]bool
	// blocked and wouldBlock are the destinations refused, and in report
	// mode allowed anyway.
	blocked, wouldBlock []string
}

func newDenialWatcher(gateway string, emit func(string), log *slog.Logger) *denialWatcher {
	return &denialWatcher{jc: egressgate.NewJobClient(gateway), log: log, emit: emit, seen: map[string]bool{}}
}

// run polls until ctx is done.
func (w *denialWatcher) run(ctx context.Context) {
	t := time.NewTicker(denialPollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.poll(ctx)
		}
	}
}

// poll reads what the gateway recorded since the last poll.
func (w *denialWatcher) poll(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	reply, err := w.jc.Denials(ctx, w.after)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Debug("could not read the gateway's denials", "error", err)
		}
		return
	}
	w.after = reply.Next
	for i, d := range reply.Denials {
		dest := d.Host
		if d.Port != 0 {
			dest = net.JoinHostPort(d.Host, fmt.Sprint(d.Port))
		}
		key := fmt.Sprintf("%s|%s|%v", d.Method, dest, d.WouldBlock)
		if w.seen[key] {
			continue
		}
		w.seen[key] = true
		if d.WouldBlock {
			w.wouldBlock = appendNew(w.wouldBlock, dest)
		} else {
			w.blocked = appendNew(w.blocked, dest)
		}
		if i < len(reply.Lines) {
			w.emit(reply.Lines[i] + "\n")
		}
	}
}

func appendNew(l []string, v string) []string {
	if slices.Contains(l, v) {
		return l
	}
	return append(l, v)
}

// report is the summary's note on blocked destinations, to sit beside the
// proxy's list of the ones contacted.
func (w *denialWatcher) report() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	quote := func(l []string) string {
		l = slices.Clone(l)
		slices.Sort(l)
		for i := range l {
			l[i] = "`" + l[i] + "`"
		}
		return strings.Join(l, ", ")
	}
	var parts []string
	if len(w.blocked) > 0 {
		parts = append(parts, "Network blocked (not on this job's allow list): "+quote(w.blocked)+".")
	}
	if len(w.wouldBlock) > 0 {
		parts = append(parts, "Would be blocked once egress is enforced: "+quote(w.wouldBlock)+".")
	}
	return strings.Join(parts, " ")
}
