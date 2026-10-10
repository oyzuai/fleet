// Command oyzu-executor runs one Oyzu job. A pool manager starts it with the
// job's startup token in a file, or in a variable where files are read-only;
// it is not meant to be run by hand.
//
//	oyzu-executor --server URL (--startup-token-file FILE | --startup-token-env NAME) --work-dir DIR [--oyzu PATH] [--renovate PATH]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oyzuai/fleet/executor"
	"github.com/oyzuai/fleet/runnerclient"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		fmt.Fprintln(os.Stderr, "oyzu-executor:", err)
		os.Exit(1)
	}
}

var version = "dev"

func run(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("oyzu-executor", flag.ContinueOnError)
	server := fs.String("server", "", "the runs URL")
	tokenFile := fs.String("startup-token-file", "", "file holding the job's startup token; deleted once read")
	tokenEnv := fs.String("startup-token-env", "", "variable holding the job's startup token; unset once read")
	workDir := fs.String("work-dir", "", "where the commit is checked out")
	oyzu := fs.String("oyzu", "oyzu", "the oyzu executable")
	git := fs.String("git", "git", "the git executable")
	gitURL := fs.String("git-url", "https://github.com", "the Git host")
	apiURL := fs.String("github-api", "https://api.github.com", "the Git host's REST API, for Renovate")
	renovate := fs.String("renovate", "", "the Renovate executable; renovate jobs fail without it")
	gitAuthor := fs.String("git-author", executor.DefaultGitAuthor, "who lock fix commits are by, \"Name <email>\"")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || (*tokenFile == "") == (*tokenEnv == "") || *workDir == "" {
		return errors.New("oyzu-executor needs --server, --work-dir and one of --startup-token-file or --startup-token-env")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return executor.Run(ctx, executor.Config{
		Client:           runnerclient.New(*server, nil),
		StartupTokenFile: *tokenFile,
		StartupTokenEnv:  *tokenEnv,
		WorkDir:          *workDir,
		GitURL:           *gitURL,
		Git:              *git,
		Oyzu:             *oyzu,
		Renovate:         *renovate,
		GitHubAPI:        *apiURL,
		GitAuthor:        *gitAuthor,
		Log:              log,
	})
}
