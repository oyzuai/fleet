// Command oyzu-pool-manager enrolls this machine as an Oyzu pool manager and runs
// the jobs runs assigns to its pool, each in a fresh oyzu-executor process (the
// process driver) or a fresh container from a pinned executor image (the
// container driver).
//
//	oyzu-pool-manager enroll --server URL --token-file FILE --name NAME
//	oyzu-pool-manager run [--concurrency 1]
//
// The manager's Ed25519 private key is generated here and never leaves the
// state directory. It logs in with the key (private_key_jwt), rotates it every
// 30 days, and hands each runner only a single-use startup token for its job.
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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/container"
	"github.com/oyzuai/fleet/manager/kubernetes"
	"github.com/oyzuai/fleet/runnerclient"
)

const usage = `usage:
  oyzu-pool-manager enroll --server URL --token-file FILE --name NAME [--audience oyzu-runs] [--state-dir DIR]
      Generate this manager's key and enroll it with an enrollment token from
      "runs admin enrollment-token", or move it to a new key with a token from
      "runs admin rekey-token". The token file can be deleted afterwards.
  oyzu-pool-manager run [--state-dir DIR] [--work-dir DIR] [--executor PATH] [--oyzu PATH]
                        [--concurrency 1] [--docker] [--pass-env NAME,...] [--drain-timeout 30m]
                        [--driver process|container|kubernetes] [--image REF] [--engine URL]
                        [--cpus N] [--memory-mib N] [--network bridge] [--user 1000:1000]
                        [--namespace NS] [--runtime-class NAME] [--node-selector K=V,...]
                        [--disk-gib N] [--kube-server URL --kube-token-file FILE --kube-ca FILE]
      Claim and run jobs for the manager's pool until interrupted. The
      container driver runs each job in a fresh container from --image on the
      Docker or Podman engine at --engine (DOCKER_HOST by default), with no
      engine socket and no capabilities. The kubernetes driver runs each job
      in a fresh pod from --image in --namespace, through the manager pod's
      service account unless --kube-server is given; --concurrency caps pods. On the
      first interrupt it claims no more and lets running jobs finish for up
      to --drain-timeout; a second interrupt stops at once.
`

var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		fmt.Fprintln(os.Stderr, "oyzu-pool-manager:", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fs := flag.NewFlagSet("oyzu-pool-manager "+args[0], flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultDir(os.UserConfigDir, "state"), "where the manager's key and state live")
	switch args[0] {
	case "enroll":
		server := fs.String("server", "", "the runs URL")
		tokenFile := fs.String("token-file", "", "file holding the enrollment or rekey token")
		name := fs.String("name", hostname(), "the manager's name")
		audience := fs.String("audience", "oyzu-runs", "the aud runs expects (RUNS_RUNNER_AUDIENCE)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *server == "" || *tokenFile == "" {
			return errors.New("enroll needs --server and --token-file")
		}
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		st, err := manager.Enroll(ctx, runnerclient.New(*server, nil), manager.Store{Dir: *stateDir},
			*server, *audience, strings.TrimSpace(string(b)), *name, time.Now())
		if err != nil {
			return err
		}
		log.Info("enrolled", "manager", st.ManagerID, "pool", st.Pool, "name", st.Name, "key", st.Current.ID, "state_dir", *stateDir)
		return nil

	case "run":
		workDir := fs.String("work-dir", defaultDir(os.UserCacheDir, "jobs"), "one directory per job, removed when it ends")
		executor := fs.String("executor", siblingExecutable("oyzu-executor"), "the oyzu-executor executable")
		oyzu := fs.String("oyzu", "oyzu", "the oyzu executable executors use")
		concurrency := fs.Int("concurrency", 1, "jobs run at once")
		docker := fs.Bool("docker", false, "report that jobs may use this host's Docker or BuildKit (oyzu.io/docker)")
		renovate := fs.String("renovate", "", "the Renovate executable; when set, the pool takes renovate jobs (oyzu.io/renovate)")
		kindState := fs.String("kind-state-dir", "", "process driver: where deployment kinds keep state between jobs; <state-dir>/kinds by default")
		passEnv := fs.String("pass-env", "", "comma-separated extra variables executors inherit")
		drain := fs.Duration("drain-timeout", 30*time.Minute, "how long running jobs may finish after an interrupt")
		driverName := fs.String("driver", "process", "how jobs run: process, container or kubernetes")
		image := fs.String("image", "", "container and kubernetes drivers: the pinned executor image")
		engine := fs.String("engine", os.Getenv("DOCKER_HOST"), "container driver: the engine, unix:///path or tcp://host:port")
		cpus := fs.Float64("cpus", 0, "container and kubernetes drivers: CPUs per job, 0 for no cap")
		memory := fs.Int64("memory-mib", 0, "container and kubernetes drivers: memory per job in MiB, 0 for no cap")
		network := fs.String("network", "bridge", "container driver: the network jobs join")
		user := fs.String("user", "1000:1000", "container driver: the uid:gid jobs run as")
		namespace := fs.String("namespace", "", "kubernetes driver: where job pods run; the manager pod's own by default")
		runtimeClass := fs.String("runtime-class", "", "kubernetes driver: the pods' runtime class, such as kata or gvisor")
		nodeSelector := fs.String("node-selector", "", "kubernetes driver: comma-separated key=value node labels")
		disk := fs.Int64("disk-gib", 0, "kubernetes driver: workspace size per job in GiB, 0 for no cap")
		kubeServer := fs.String("kube-server", "", "kubernetes driver: the API server, when the manager runs outside the cluster")
		kubeToken := fs.String("kube-token-file", "", "kubernetes driver: bearer token file for --kube-server")
		kubeCA := fs.String("kube-ca", "", "kubernetes driver: CA bundle for --kube-server")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store := manager.Store{Dir: *stateDir}
		st, err := store.Load()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("not enrolled yet: run oyzu-pool-manager enroll first")
			}
			return err
		}
		var extra []string
		if *passEnv != "" {
			extra = strings.Split(*passEnv, ",")
		}
		if *kindState == "" {
			*kindState = filepath.Join(*stateDir, "kinds")
		}
		runnerArgs := []string{"--oyzu", *oyzu, "--kind-state-dir", *kindState}
		if *renovate != "" {
			runnerArgs = append(runnerArgs, "--renovate", *renovate)
		}
		var driver manager.Driver
		switch *driverName {
		case "process":
			driver = &manager.Process{
				Runner: *executor, Args: runnerArgs, Server: st.Server, Manager: st.ManagerID,
				WorkDir: *workDir, LogDir: filepath.Join(*stateDir, "logs"), Slots: *concurrency, Docker: *docker,
				Renovate: *renovate != "",
				ExtraEnv: extra, Log: log,
			}
		case "container":
			if *docker {
				return errors.New("--docker is for the process driver; container jobs never get an engine (IMPL-114)")
			}
			eng, err := container.NewDocker(*engine)
			if err != nil {
				return err
			}
			c := &container.Driver{
				Engine: eng, Image: *image, Command: []string{"oyzu-executor", "--oyzu", "oyzu"}, Server: st.Server,
				Pool: st.Pool, Manager: st.ManagerID, Slots: *concurrency, CPUs: *cpus, MemoryBytes: *memory << 20,
				Network: *network, User: *user, Log: log,
			}
			if err := c.Check(); err != nil {
				return err
			}
			driver = c
		case "kubernetes":
			var api *kubernetes.Client
			if *kubeServer != "" {
				api, err = kubernetes.NewClient(*kubeServer, *kubeCA, *kubeToken, *namespace)
			} else {
				api, err = kubernetes.InCluster(*namespace)
			}
			if err != nil {
				return err
			}
			k := &kubernetes.Driver{
				API: api, Image: *image, Command: []string{"oyzu-executor", "--oyzu", "oyzu"}, Server: st.Server,
				Pool: st.Pool, Manager: st.ManagerID, MaxPods: *concurrency, RuntimeClass: *runtimeClass,
				Docker: *docker, Arch: runtime.GOARCH, Log: log,
			}
			if *cpus > 0 {
				k.CPU = strconv.FormatFloat(*cpus, 'f', -1, 64)
			}
			if *memory > 0 {
				k.Memory = strconv.FormatInt(*memory, 10) + "Mi"
			}
			if *disk > 0 {
				k.Disk = strconv.FormatInt(*disk, 10) + "Gi"
			}
			if *nodeSelector != "" {
				k.NodeSelector = map[string]string{}
				for _, kv := range strings.Split(*nodeSelector, ",") {
					key, value, ok := strings.Cut(kv, "=")
					if !ok || key == "" {
						return fmt.Errorf("--node-selector: %q is not key=value", kv)
					}
					k.NodeSelector[key] = value
				}
			}
			if err := k.Check(); err != nil {
				return err
			}
			driver = k
		default:
			return fmt.Errorf("unknown --driver %q: use process, container or kubernetes", *driverName)
		}
		m, err := manager.Open(manager.Config{
			Client:       runnerclient.New(st.Server, nil),
			Store:        store,
			Driver:       driver,
			DrainTimeout: *drain,
			Log:          log,
		})
		if err != nil {
			return err
		}
		// After the first interrupt, a second one gets the default behaviour
		// and ends the process without waiting for the drain.
		go func() { <-ctx.Done(); stop() }()
		return m.Run(ctx)
	}
	return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

func defaultDir(base func() (string, error), sub string) string {
	dir, err := base()
	if err != nil {
		return filepath.Join(".", "pool-manager", sub)
	}
	return filepath.Join(dir, "oyzu", "pool-manager", sub)
}

func siblingExecutable(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	self, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(self), name)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "pool-manager"
	}
	return h
}
