package executor

import (
	"strings"
	"testing"
)

// Invariant (FLEET-AUTH-05): the build never inherits a telemetry setting,
// an exporter credential or the manager's trace parent.
func TestBuildEnvDropsTelemetryAndIDTokenSettings(t *testing.T) {
	in := []string{
		"PATH=/bin", "HOME=/h",
		"OYZU_OTEL_ENABLED=true", "OYZU_OTEL_ENDPOINT=http://collector:4318", "oyzu_otel_traces=full",
		"OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer secret", "OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318",
		"TRACEPARENT=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", "TRACESTATE=a=b",
		EnvIDTokenURL + "=http://x", EnvIDTokenRequestToken + "=t",
	}
	got := strings.Join(buildEnv(in), " ")
	if got != "PATH=/bin HOME=/h" {
		t.Fatalf("build env = %q", got)
	}
}
