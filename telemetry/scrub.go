package telemetry

// Scrub returns environ without any telemetry variable: the exporter's
// endpoint, a trace parent, or any OTEL_ setting. Build code, kinds, Git and
// Renovate run with an environment that has been through it, so the exporter's
// configuration and any credential an operator put beside it cannot reach them.
func Scrub(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		if !IsTelemetryVar(kv) {
			out = append(out, kv)
		}
	}
	return out
}
