# Executor readiness

Typed network readiness is implemented for account-owned Linux container pools
using the Docker Engine API, IPv4, one job network and a pinned executor image.
Measurements are assertions by an enrolled manager, not independent host
attestation. Public protocol fields are defined in the self-contained
[runner contract](https://github.com/oyzuai/oyzu/blob/main/docs/contracts/runner-v1/openapi.yaml).

At startup the manager opens a new boot session. It reports the observed host,
image, runtime configuration, gateway identity and network template. Runs sends
fixed bounded work for that session and boundary. Ordinary slot reports and
heartbeats never renew a measurement. A restart fences the old session; this
slice does not adopt running jobs across sessions.

The manager runs a secret-free control container on the gateway management
bridge before and after a diagnostic container built through the ordinary job
sandbox constructor. The seven checks cover allowed proxy traffic, reachable
HTTP and UDP/TCP DNS controls, explicit proxy denial, blocked direct egress,
DNS confinement, an unreachable gateway control port and resource cleanup.
Actual allocation inspection rejects extra networks, IPv6, host networking,
privilege, extra mounts or a DNS upstream different from the gateway. Docker's
embedded resolver may translate upstream REFUSED to SERVFAIL; a timeout never
counts as that observation, and a direct gateway REFUSED answer is also required.

The server-selected assignment binding accompanies startup. Fleet checks its
current boundary, starts the trusted executor bootstrap without a startup token,
and inspects the allocated image, namespace identity and DNS. It then delivers
the one-use token with a final ready marker. The bootstrap waits up to 30 seconds
for that completed handoff before it can call job/start or obtain job/source
authority. It deletes both handoff files before running the job. Running assignments and their actual image/DNS/network allocation are checked
locally every five seconds, with a five second observation deadline. Known
invalidation delivery is retried while old server authority remains visible. A confirmed failure clears local authority before
result delivery; an old server response cannot restore it. A fresh successful
measurement for the same boundary can sustain a running job. Expiry and a known
boundary change stop local use; teardown has its existing bounded deadline.
Neither local stop nor server revocation retracts credentials already accepted
by an external provider.

Public pool egress mode changes are delivered through readiness work. Fleet
stops claiming while draining the old boundary, then replaces its gateway.
Process and VM execution and unpinned Kubernetes report unsupported. This
implementation does not qualify Kubernetes nodes, Podman, Windows containers,
IPv6, additional network attachments or independent verification. Global pools
retain the existing egress self-test and controls.

Run the real local container proof with:

```sh
oyzu run readiness-container-proof
```

The task builds the executor with the pinned Go toolchain, packages it in a
local digest-pinned image, creates credential-free HTTP/DNS fixtures and removes
its containers and registry on exit. The proof passed on 2026-10-22 with Docker
28.4.0: all seven checks, gateway replacement fencing, replacement measurement,
actual bootstrap handoff, live extra/replacement-network attachment and
stale-restore refusal, clean remeasurement,
and enforcing-to-report mode fencing. Unit checks for manager drivers, runner
client, executor, diagnostics and wire validation passed. This is a component
runtime proof; it does not claim a live App-connected platform build or
Kubernetes qualification.
