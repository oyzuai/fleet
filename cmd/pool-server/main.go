// pool-server serves one standalone remote build pool. It never executes jobs;
// enrolled Fleet managers provide the configured isolated executors.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oyzuai/fleet/poolserver"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("config", "/etc/oyzu-pool/server.json", "root-owned private JSON configuration (or systemd credential mount)")
	flag.Parse()
	c, err := poolserver.LoadConfig(*config)
	if err != nil {
		return err
	}
	handler, err := poolserver.New(c, poolserver.Options{})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10}
	reap := make(chan error, 1)
	go func() {
		err := handler.Reap(ctx)
		reap <- err
		if err != nil && !errors.Is(err, context.Canceled) {
			stop()
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	stop()
	<-done
	reapErr := <-reap
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if reapErr != nil && !errors.Is(reapErr, context.Canceled) {
		return reapErr
	}
	return nil
}
