package telemetry

import "os"

func lookup(k string) (string, bool) { return os.LookupEnv(k) }
