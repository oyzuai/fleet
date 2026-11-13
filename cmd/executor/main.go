// Command oyzu-executor runs one Oyzu job. A pool manager starts it with the
// job's startup token in a file, or in a variable where files are read-only;
// it is not meant to be run by hand.
//
//	oyzu-executor --server URL (--startup-token-file FILE | --startup-token-env NAME) --work-dir DIR [--oyzu PATH] [--renovate PATH]
//	              [--kinds-dir DIR] [--kind-state-dir DIR] [--docker PATH] [--docker-network NAME] [--docker-env A,B]
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/oyzuai/fleet/executor"
	"github.com/oyzuai/fleet/manager/container"
)

// version is set by the release build (-X main.version).
var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var driver executor.ActionDriver
	if endpoint := os.Getenv("FLEET_ACTION_ENGINE"); endpoint != "" {
		os.Unsetenv("FLEET_ACTION_ENGINE")
		engine, err := container.NewDocker(endpoint, container.DockerOptions{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "oyzu-executor:", err)
			os.Exit(1)
		}
		driver = &container.ActionRuntime{Engine: engine}
	}
	if err := executor.CommandWithActionDriver(os.Args[1:], log, driver); err != nil {
		fmt.Fprintln(os.Stderr, "oyzu-executor:", err)
		os.Exit(1)
	}
}
