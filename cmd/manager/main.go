// Command oyzu-pool-manager enrolls this machine as an Oyzu pool manager and runs
// the jobs runs assigns to its pool, each in a fresh container from a pinned
// executor image (the container driver, the default), a fresh pod (the
// kubernetes driver) or a fresh oyzu-executor process (the process driver,
// for trusted code only: the job runs as the manager's own OS user).
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
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oyzuai/fleet/egressgate"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/container"
	"github.com/oyzuai/fleet/manager/kubernetes"
	"github.com/oyzuai/fleet/runnerclient"
	"github.com/oyzuai/fleet/telemetry"
)

const usage = `usage:
  oyzu-pool-manager enroll --server URL --token-file FILE --name NAME [--audience oyzu-runs] [--state-dir DIR]
      Generate this manager's key and enroll it with an enrollment token from
      "runs admin enrollment-token", or move it to a new key with a token from
      "runs admin rekey-token". The token file can be deleted afterwards.
  oyzu-pool-manager run [--state-dir DIR] [--work-dir DIR] [--executor PATH] [--oyzu PATH]
                        [--concurrency 1] [--docker] [--pass-env NAME,...] [--drain-timeout 30m]
                        [--driver container|kubernetes|process] [--image REF] [--engine URL]
                        [--engine-cert-path DIR] [--engine-allow-plaintext]
                        [--cpus N] [--memory-mib N] [--network NAME] [--user 1000:1000]
                        [--egress enforce|report|open]
                        [--namespace NS] [--runtime-class NAME] [--node-selector K=V,...]
                        [--disk-gib N] [--kube-server URL --kube-token-file FILE --kube-ca FILE]
      The default driver is container. The process driver runs jobs as this
      user and is for trusted code only. --executor, --oyzu, --renovate,
      --pass-env, --work-dir and --kind-state-dir are for the process driver,
      --engine, --engine-*, --network and --user for the container driver, --namespace,
      --runtime-class, --node-selector, --disk-gib and --kube-* for the
      kubernetes driver, and --image, --cpus, --memory-mib and --egress for
      container and kubernetes; a flag for another driver is an error.
      --docker is for process and kubernetes.
      --egress controls what jobs can reach. enforce gives each job a network
      with no route out and an egress gateway that allows only the hosts runs
      lists for the job (container) or a NetworkPolicy that leaves the pod only
      the gateway (kubernetes); a pool that enforces and passes its startup
      self-test takes work from untrusted triggers such as pull requests.
      report runs the gateway, logs what enforce would block and allows it.
      open is no control, and the only mode that allows --network NAME. A
      manager enrolled by this version enforces by default; one enrolled
      earlier starts in report mode until it is given --egress enforce.
      Both container and kubernetes require --image NAME@sha256:DIGEST, with
      a 64-character lowercase hex digest; tag-only references are refused.
      Claim and run jobs for the manager's pool until interrupted. The
      container driver runs each job in a fresh container from --image on the
      Docker or Podman engine at --engine (DOCKER_HOST by default), with no
      engine socket and no capabilities. A tcp:// engine on another host needs
      TLS (--engine-cert-path, DOCKER_CERT_PATH and DOCKER_TLS_VERIFY, as for
      the Docker CLI) unless --engine-allow-plaintext is given. The kubernetes driver runs each job
      in a fresh pod from --image in --namespace, through the manager pod's
      service account unless --kube-server is given; --concurrency caps pods. On the
      first interrupt it claims no more and lets running jobs finish for up
      to --drain-timeout; a second interrupt stops at once.
`

var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Printf("oyzu-pool-manager %s\n", version)
		return
	}
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

	// Optional telemetry (OYZU_OTEL_*), off by default. The settings are read
	// and removed from this process's environment, so no executor, build or
	// child inherits them; an executor gets its own through the driver.
	tcfg, terr := telemetry.LoadConfig("oyzu-pool-manager", true)
	if terr != nil {
		log.Warn(terr.Error())
	}
	tele := telemetry.Setup(tcfg, log)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tele.Shutdown(c)
	}()

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
		var err error
		if *stateDir, err = absPath(*stateDir); err != nil {
			return err
		}
		if *tokenFile, err = absPath(*tokenFile); err != nil {
			return err
		}
		if *server == "" || *tokenFile == "" {
			return errors.New("enroll needs --server and --token-file")
		}
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		_, loadErr := manager.Store{Dir: *stateDir}.Load()
		existed := loadErr == nil
		st, err := manager.Enroll(ctx, runnerclient.New(*server, nil), manager.Store{Dir: *stateDir},
			*server, *audience, strings.TrimSpace(string(b)), *name, time.Now())
		if err != nil {
			return err
		}
		if err := recordNewEgress(*stateDir, existed); err != nil {
			return fmt.Errorf("record the egress mode: %w", err)
		}
		log.Info("enrolled", "manager", st.ManagerID, "pool", st.Pool, "name", st.Name, "key", st.Current.ID, "state_dir", *stateDir)
		return nil

	case "run":
		workDir := fs.String("work-dir", defaultDir(os.UserCacheDir, "jobs"), "one directory per job, removed when it ends")
		executor := fs.String("executor", siblingExecutable("oyzu-executor"), "the oyzu-executor executable")
		oyzu := fs.String("oyzu", "oyzu", "the oyzu executable executors use")
		concurrency := fs.Int("concurrency", 1, "jobs run at once")
		docker := fs.Bool("docker", false, "report that jobs may use this host's Docker or BuildKit (oyzu.io/docker); without it, runners get OYZU_NO_DOCKER=1")
		renovate := fs.String("renovate", "", "the Renovate executable; when set, the pool takes renovate jobs (oyzu.io/renovate)")
		kindState := fs.String("kind-state-dir", "", "process driver: where deployment kinds keep state between jobs; <state-dir>/kinds by default")
		passEnv := fs.String("pass-env", "", "comma-separated extra variables executors inherit")
		drain := fs.Duration("drain-timeout", 30*time.Minute, "how long running jobs may finish after an interrupt")
		driverName := fs.String("driver", "container", "how jobs run: container (default), kubernetes, or process (trusted code only: jobs run as the manager's own OS user and can read its key)")
		image := fs.String("image", "", "container and kubernetes drivers: executor image pinned by SHA-256 digest")
		engine := fs.String("engine", os.Getenv("DOCKER_HOST"), "container driver: the engine, unix:///path, npipe:////./pipe/name or tcp://host:port")
		engineCerts := fs.String("engine-cert-path", os.Getenv("DOCKER_CERT_PATH"), "container driver: directory with ca.pem, cert.pem and key.pem for a tcp:// engine over TLS")
		enginePlaintext := fs.Bool("engine-allow-plaintext", false, "container driver: allow a plain-HTTP tcp:// engine on another host (startup tokens cross the network unencrypted)")
		cpus := fs.Float64("cpus", 0, "container and kubernetes drivers: CPUs per job, 0 for no cap")
		memory := fs.Int64("memory-mib", 0, "container and kubernetes drivers: memory per job in MiB, 0 for no cap")
		network := fs.String("network", "", "container driver: the network jobs join, bridge by default; only with --egress open, since otherwise each job gets its own network")
		egress := fs.String("egress", "", "container and kubernetes drivers: enforce, report or open; enforce by default for a manager enrolled by this version, report for an earlier one")
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
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if err := checkDriverFlags(*driverName, set); err != nil {
			return err
		}
		for _, p := range []*string{stateDir, workDir, kindState, kubeToken, kubeCA, engineCerts} {
			abs, err := absPath(*p)
			if err != nil {
				return err
			}
			*p = abs
		}
		for _, c := range []*string{executor, oyzu, renovate} {
			abs, err := absCommand(*c)
			if err != nil {
				return err
			}
			*c = abs
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
				ExtraEnv: extra, Log: log, Telemetry: tcfg,
			}
		case "container":
			if *image == "" {
				return errors.New("the container driver needs --image NAME@sha256:DIGEST; to run jobs on this host as the manager's own user instead, pass --driver process (trusted code only)")
			}
			mode, why, err := resolveEgress(*egress, *stateDir, set["network"])
			if err != nil {
				return err
			}
			if mode != egressOpen {
				if err := checkEngineForEgress(*engine); err != nil {
					return err
				}
			}
			log.Info("egress control", "mode", mode, "why", why)
			eng, err := container.NewDocker(*engine, container.DockerOptions{
				CertPath: *engineCerts, TLSVerify: os.Getenv("DOCKER_TLS_VERIFY") != "", AllowPlaintext: *enginePlaintext,
			})
			if err != nil {
				return err
			}
			c := &container.Driver{
				Engine: eng, Image: *image, Command: []string{"oyzu-executor", "--oyzu", "oyzu"}, Server: st.Server,
				Pool: st.Pool, Manager: st.ManagerID, Slots: *concurrency, CPUs: *cpus, MemoryBytes: *memory << 20,
				Network: *network, User: *user, Egress: container.EgressMode(mode), Log: log,
			}
			if err := c.Check(); err != nil {
				return err
			}
			driver = c
		case "kubernetes":
			if *image == "" {
				return errors.New("the kubernetes driver needs --image NAME@sha256:DIGEST")
			}
			var api *kubernetes.Client
			if *kubeServer != "" {
				api, err = kubernetes.NewClient(*kubeServer, *kubeCA, *kubeToken, *namespace)
			} else {
				api, err = kubernetes.InCluster(*namespace)
			}
			if err != nil {
				return err
			}
			mode, why, err := resolveEgress(*egress, *stateDir, false)
			if err != nil {
				return err
			}
			log.Info("egress control", "mode", mode, "why", why)
			k := &kubernetes.Driver{
				API: api, Image: *image, Command: []string{"oyzu-executor", "--oyzu", "oyzu"}, Server: st.Server,
				Pool: st.Pool, Manager: st.ManagerID, MaxPods: *concurrency, RuntimeClass: *runtimeClass,
				Docker: *docker, Arch: runtime.GOARCH, Egress: kubernetes.EgressMode(mode), Log: log,
			}
			k.NewControl = func(token string) kubernetes.GatewayControl {
				if *kubeServer == "" {
					// In the cluster the manager reaches the gateway's Service directly.
					return egressgate.NewClient("http://"+net.JoinHostPort(k.GatewayName()+"."+api.Namespace+".svc", strconv.Itoa(egressgate.DefaultControlPort)), token)
				}
				base, hc := api.ServiceProxy(k.GatewayName(), "control")
				c := egressgate.NewClient(base, token)
				c.HTTP = hc
				return c
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
