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

The [container build sandbox](container-sandbox.md) defines the fixed syscall
and proc/sys controls that support the admitted rootless worker. Its policy
digest and observed engine security configuration are part of runtime identity;
actual startup/running inspection verifies those controls rather than accepting
an image assertion or silently using a different profile.

An inconclusive refresh leaves a previously accepted capability usable only
until its existing server deadline. The manager's scheduling facts follow that
accepted binding, rather than the most recent probe outcome. A confirmed bypass,
changed boundary or expiry removes authority; a successful local probe alone
cannot advertise acceptance before Runs returns its binding.

The manager runs a secret-free control container on the gateway management
bridge before and after a diagnostic container built through the ordinary job
sandbox constructor. The seven checks cover allowed proxy traffic, reachable
HTTP and UDP/TCP DNS controls, explicit proxy denial, blocked direct egress,
DNS confinement, an unreachable gateway control port and resource cleanup.
Actual allocation inspection rejects extra networks, IPv6, host networking,
privilege, extra mounts or a DNS upstream different from the gateway. Docker's
embedded resolver may translate upstream REFUSED to SERVFAIL; a timeout never
counts as that observation, and a direct gateway REFUSED answer is also required.
Job and diagnostic containers disable IPv6, link-local included, through the
`disable_ipv6` sysctls. A kernel booted with `ipv6.disable=1` has no such
sysctls and no IPv6 at all. Fleet asks the engine's own kernel, not the
manager's: it starts one network-less probe container with those sysctls, and
only when the engine refuses because their files are missing does it create
containers without them. Any other probe outcome keeps the sysctls, and a probe
that cannot run fails the container. The readiness boundary records which mode
applies, so a measurement taken in one mode never qualifies the other.

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
its containers and registry on exit. The proof passed on 2026-10-23 with Docker
28.4.0: all seven checks, gateway replacement fencing, replacement measurement,
actual bootstrap handoff, live extra/replacement-network attachment and
stale-restore refusal, clean remeasurement and enforcing-to-report mode fencing.
An intentionally ineffective boundary produced definitive direct TCP and DNS
bypass failures. A missing positive DNS fixture was inconclusive and did not
extend previous evidence. Any direct reply from the off-path DNS fixture proves
a bypass, including an NXDOMAIN reply; a blocked resolver returning NXDOMAIN
alone cannot prove confinement. Unit checks for manager drivers, runner
client, executor, diagnostics and wire validation passed. This is a component
runtime proof; it does not claim a live App-connected platform build or
Kubernetes qualification.

The component task also injects one failed network-cleanup operation around an
actual probe. It requires an inconclusive result with no extension of previous
evidence, then removes the deliberately retained task network. This fault is
injected at the Engine interface; the probe itself still runs in real Docker.

The connected source-checkout work also exposed recursive lazy acquisition when
initializing a partial clone with some Git versions. The explicit `fetch` now
sets `GIT_NO_LAZY_FETCH=1` for that command only; the subsequent checkout can
still retrieve the assigned tree's promised blobs through its normal scoped
source credential. This changes neither the admitted commit nor resource-use
authorization. The actual Git reproduction and focused executor tests cover
this correction; source-provider deployment qualification remains separate.

Masked log spools use the executor's private temporary area. A non-root
container whose checkout is `/work` cannot write its parent `/`; that layout
must still upload diagnostics through the ordinary governed log protocol. The
regression case exercises an unwritable checkout parent and checks delivery.
