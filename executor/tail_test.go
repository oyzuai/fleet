package executor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
	"testing"
)

func TestTailBoundsProgressWithoutNewlines(t *testing.T) {
	var tail tail
	for range 100 {
		tail.Write([]byte(strings.Repeat("x", 4096) + "\r"))
	}
	tail.Write([]byte("last"))
	if len(tail.part) > 64<<10 || !strings.HasSuffix(tail.String(), "last") {
		t.Fatal("partial line unbounded or lost suffix")
	}
	tail.Write([]byte("\n" + strings.Repeat("y", 128<<10) + "\n"))
	for _, line := range tail.lines {
		if len(line) > 64<<10 {
			t.Fatal("completed line unbounded")
		}
	}
}
func TestBuildHeartbeatCancelsAtConfirmedExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	start := time.Now()
	heartbeat(ctx, runnerclient.New(srv.URL, srv.Client()), "token", 10*time.Millisecond, cancel,
		slog.New(slog.NewTextHandler(io.Discard, nil)), start.Add(100*time.Millisecond))
	if !errors.Is(context.Cause(ctx), errLost) || time.Since(start) > time.Second {
		t.Fatal("build kept its expired lease")
	}
}
