package executor

import (
	"os"
	"os/signal"
	"syscall"
)

// HoldWorkspace must be dispatched by every executor entry point before flags,
// environment, logging, credentials or engine initialization.
func HoldWorkspace(args []string) bool {
	if len(args) != 1 || args[0] != "hold-workspace" {
		return false
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	signal.Stop(signals)
	return true
}
