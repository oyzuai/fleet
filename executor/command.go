package executor

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/oyzuai/fleet/readiness"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/kindrunner"
	"github.com/oyzuai/fleet/runnerclient"
	"github.com/oyzuai/fleet/telemetry"
)

// Command runs the oyzu-executor command line, args without the program
// name. It is exported so that an image carrying the executor beside
// built-in kinds (the platform's pool image) can build the same program from
// this module at the version it pins.
func Command(args []string, log *slog.Logger) error {
	if len(args) > 0 && args[0] == "gateway" {
		return egressgate.Command(args[1:], log)
	}
	fs := flag.NewFlagSet("oyzu-executor", flag.ContinueOnError)
	server := fs.String("server", "", "the runs URL")
	tokenFile := fs.String("startup-token-file", "", "file holding the job's startup token; deleted once read")
	tokenEnv := fs.String("startup-token-env", "", "variable holding the job's startup token; unset once read")
	secretsDir := fs.String("secrets-dir", "", "private job temporary directory; defaults to the system temp directory")
	jobDir := fs.String("job-dir", "", "job directory the process manager reaps")
	workDir := fs.String("work-dir", "", "where the commit is checked out")
	oyzu := fs.String("oyzu", "oyzu", "the oyzu executable")
	git := fs.String("git", "git", "the git executable")
	gitURL := fs.String("git-url", "https://github.com", "the Git host")
	apiURL := fs.String("github-api", "https://api.github.com", "the Git host's REST API, for Renovate")
	renovate := fs.String("renovate", "", "the Renovate executable; renovate jobs fail without it")
	gitAuthor := fs.String("git-author", DefaultGitAuthor, "who lock fix commits are by, \"Name <email>\"")
	kindsDir := fs.String("kinds-dir", ownDir(), "where the built-in deployment kinds (kind-<name>) are")
	kindState := fs.String("kind-state-dir", kindrunner.DefaultStateDir(), "where kinds keep state between jobs on this host")
	docker := fs.String("docker", "docker", "the docker CLI that image kinds run with")
	dockerNetwork := fs.String("docker-network", "", "the network image kinds join (docker run --network); Docker's default when empty")
	dockerEnv := fs.String("docker-env", "", "comma-separated names of this process's variables that image kinds also get")
	bindingJSON := fs.String("readiness-binding", "", "server-selected non-secret allocation binding")
	gateway := fs.String("egress-gateway", os.Getenv(EnvEgressGateway), "the pool's egress gateway proxy URL on this job's network; the credential proxy chains through it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || (*tokenFile == "") == (*tokenEnv == "") || *workDir == "" {
		return errors.New("oyzu-executor needs --server, --work-dir and one of --startup-token-file or --startup-token-env")
	}
	if *secretsDir != "" {
		if err := os.MkdirAll(*secretsDir, 0o700); err != nil {
			return err
		}
	}
	var binding *readiness.Binding
	if *bindingJSON != "" {
		if len(*bindingJSON) > 2048 {
			return errors.New("oversized readiness binding")
		}
		binding = &readiness.Binding{}
		if err := json.Unmarshal([]byte(*bindingJSON), binding); err != nil {
			return err
		}
	}
	// Optional telemetry. Read once and removed from the environment, so the
	// build, kinds, Git and Renovate never inherit the endpoint or the
	// manager's trace parent. Off by default; a bad setting disables it.
	tcfg, terr := telemetry.LoadConfig("oyzu-executor", true)
	if terr != nil {
		log.Warn(terr.Error())
	}
	tele := telemetry.Setup(tcfg, log)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tele.Shutdown(c)
	}()
	ctx, stop := signal.NotifyContext(telemetry.WithParent(context.Background(), tcfg.Parent), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, Config{
		Client:           runnerclient.New(*server, nil),
		Readiness:        binding,
		StartupTokenFile: *tokenFile,
		StartupTokenEnv:  *tokenEnv,
		WorkDir:          *workDir,
		SecretsDir:       *secretsDir,
		JobDir:           *jobDir,
		GitURL:           *gitURL,
		Git:              *git,
		Oyzu:             *oyzu,
		Renovate:         *renovate,
		GitHubAPI:        *apiURL,
		GitAuthor:        *gitAuthor,
		KindsDir:         *kindsDir,
		KindStateDir:     *kindState,
		Docker:           *docker,
		DockerNetwork:    *dockerNetwork,
		DockerEnv:        splitList(*dockerEnv),
		EgressGateway:    *gateway,
		Log:              log,
	})
}

// splitList splits a comma-separated list, dropping empty entries.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
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
