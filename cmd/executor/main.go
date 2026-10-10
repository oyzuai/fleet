// Command oyzu-executor runs one Oyzu job. A pool manager starts it with the
// job's startup token in a file, or in a variable where files are read-only;
// it is not meant to be run by hand.
//
//	oyzu-executor --server URL (--startup-token-file FILE | --startup-token-env NAME) --work-dir DIR [--oyzu PATH] [--renovate PATH]
//	              [--kinds-dir DIR] [--kind-state-dir DIR] [--docker PATH]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/oyzuai/fleet/executor"
	"github.com/oyzuai/fleet/kindrunner"
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
	kindsDir := fs.String("kinds-dir", ownDir(), "where the built-in deployment kinds (kind-<name>) are")
	kindState := fs.String("kind-state-dir", kindrunner.DefaultStateDir(), "where kinds keep state between jobs on this host")
	docker := fs.String("docker", "docker", "the docker CLI that image kinds run with")
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
		KindsDir:         *kindsDir,
		KindStateDir:     *kindState,
		Docker:           *docker,
		Log:              log,
	})
}

// ownDir is the directory this executable is in, where pools install the
// built-in kinds beside it.
func ownDir() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(self)
}
