# fleet

The Oyzu pool manager and executor.

The [distributed-build completion slice](https://github.com/oyzuai/oyzu/issues/479)
binds admitted native plans to the existing executor. A slice requires the
persisted executable plan, its coupled target group and assigned handoff. The
executor passes those values through bounded stdin to the configured Oyzu worker
before native effects; a preview, missing/oversized plan or non-build slice fails.
Admitted slices fetch the same blobless history as planning, so native version
and dependency preparation retain the admitted source context. Ordinary build
and task jobs keep their existing shallow checkout.
Ordinary non-slice commands retain their existing execution path. Manager
placement and Oyzu's native verification keep their existing owners. The real
platform flow passed shared to API/Web on separate Linux workers to a usable
final bundle, with required reports matching an independent cache-disabled
whole build. The agreed finite functional cases now pass; broader qualification
and maintainer acceptance remain separate.

Ordinary job heartbeats now carry a cancellation request while retaining the
attempt's lease and finish authority. The executor interrupts and waits for its
native process; it acknowledges cancellation only after a normal wait and a
fresh finalized native build record. Missing/stale records and forced stops
remain explicit runner failures. A cancellation that wins the success/finish
race is handled through the same heartbeat and stopped-outcome contract, without
publishing success outputs. The POSIX subprocess regression covers graceful,
missing-record and forced termination. The matching real Linux service/native
proof passed cancellation during shared execution, with interrupted native
evidence, confirmed cleanup and a retained CLI receipt. Cancellation after a
producer contribution commits also passed: the accepted shared record remained
unchanged while API stopped and the bundle never started. Windows graceful
interruption is unqualified.

A slice upload failure now makes one private `retry-handoff` call within the
same live assignment and lease. It transfers the engine's retained immutable
bytes, without another checkout, native preparation or execution attempt. The
successful retry reports the original sealed producer manifest digest; the failed
invocation on disk stays unchanged. Invalid retry records and a second transfer
failure remain failures. Runs independently verifies the contribution before
acceptance. Focused worker tests and the real interrupted-upload proof passed
with Fleet `3559c70`, platform `c45e1872` and public Oyzu `58dc1e71`: three refused
upload requests were followed by one retained transfer retry, the original
producer/attempt remained unchanged, and the independent whole-build outputs
and required reports matched. A separate real missing-upstream refusal retained
accepted producers and never replayed upstream work or started the bundle.
With public collector `26f9b21d`, safe lease replacement also passed: the second
API attempt on another manager restored valid original-producer work, completed
the bundle and matched an independent whole build. Resuming the obsolete executor
was refused without changing accepted records. The separate real PostgreSQL
finish case qualifies late-success token refusal.

Public worker `78ae9292` then passed one coupled job with 29 fresh native actions
and one shared generator; four artifacts and eight native reports matched an
independent whole build. Actual worker/planner configuration mismatch failed
before planned actions and queued no whole-build replay. Missing/invalid required
reports and removed native artifacts each failed through actual worker execution
without an accepted success contribution. Fleet production stayed `3559c70`;
conflicting complete contribution validation also passed on platform `3c75516d`.
Actual native success stayed separate from refused completion: no contribution
was accepted, the attempt failed with `CONTRIBUTION_UNVERIFIED`, dependents never
started and no replacement was queued. The same service subsequently accepted
all four valid contributions with fresh worker result stores, distinct API/Web
managers, CLI exit zero and another independent artifact/report comparison.

`fleet` runs the machines that execute Oyzu builds. It has two programs:

- [`cmd/manager`](cmd/manager/) is the pool manager. It keeps pools of build
  machines available and hands them work.
- [`cmd/executor`](cmd/executor/) is the executor. It runs on a build machine,
  runs the work it is assigned and reports results.

Alongside them:

- [`manager`](manager/) is the claim loop, the manager's identity and key
  rotation, and the `Driver` interface, with the process driver and the
  [`container`](manager/container/), [`kubernetes`](manager/kubernetes/) and
  [`vm`](manager/vm/) drivers. The shipped manager selects `container` (the
  default), `kubernetes` or `process` with `--driver`. The `vm` package (AWS,
  Google Cloud and Azure adapters) is library code: the manager binary does
  not select it, and using it needs integration work.
- [`executor`](executor/) runs one job: startup, checkout, the `oyzu` command,
  heartbeats, Renovate and lock fixes, and the outcome. Deployment kind jobs
  go to [`kindrunner`](kindrunner/), which runs the kind's operation and
  reports its events and result.
- [`kindprotocol`](kindprotocol/) is the deployment kind protocol: its
  documents, their published JSON Schemas, and the checks on them.
- [`runnerclient`](runnerclient/) and [`assertion`](assertion/) are the client
  side of the runs runner protocol: its calls, and the Ed25519 client
  assertions a manager logs in and rotates keys with.

## Executor images

The default manager driver changed from `process` to `container`. A manager
that ran with no `--driver` now needs `--image NAME@sha256:DIGEST` (and a
Docker or Podman engine), or `--driver process` to keep the old behaviour. The
process driver runs repository build code as the manager's own OS user, which
can read the manager's private key in its state directory, so use it for
trusted code only. Flags that belong to one driver (`--oyzu`, `--renovate`,
`--pass-env`, `--work-dir`, `--executor` and `--kind-state-dir` are
process-only; `--engine`, `--network` and `--user` are container-only;
`--egress` belongs to the container and Kubernetes drivers) are
refused when another driver is chosen, instead of being ignored.

The container and Kubernetes manager drivers require `--image` to be pinned
by SHA-256 digest: `NAME@sha256:DIGEST`, where `DIGEST` is exactly 64 lowercase
hex characters. A tag may accompany the digest (`NAME:TAG@sha256:DIGEST`),
but bare names and tag-only references (including version tags) are refused
at startup. This matches kindrunner's digest requirement and keeps executor
images immutable across jobs. Use the digest published by your image registry.

## Running the manager

A remote container engine (`--engine tcp://host:port`) must be reached over
TLS: give `--engine-cert-path` (or `DOCKER_CERT_PATH`, with
`DOCKER_TLS_VERIFY` as for the Docker CLI) a directory holding `ca.pem`,
`cert.pem` and `key.pem`. The engine's certificate is always verified.
Plain HTTP is accepted only for an engine on this machine (`localhost`,
`127.0.0.1`, `::1`); `--engine-allow-plaintext` lifts that for a network you
trust, since every job's startup token crosses it. On Windows the engine
defaults to Docker Desktop's named pipe, `npipe:////./pipe/docker_engine`.

Every call to the engine or cluster has a deadline, executors start off the
claim loop, and teardown is bounded, so a stalled engine cannot keep the
manager from draining or stopping. A container or pod executor that ends
badly has the last 2 KiB of its output, with its startup token and anything
shaped like a bearer token masked, in the reason the job is handed back
with. Kubernetes managers need `get` on `pods/log` for that; without it the
reason carries no output.

The process driver starts each executor in its own process group and
records its PID and process start time in the job directory. A manager
restarted after a crash adopts an executor that is still running: its
directory stays and it holds a slot until it exits. A recorded PID that is
gone or now names another process means the executor is dead and its
directory is removed. Nothing is ever killed by a PID that cannot be
verified. Under systemd, `KillMode=mixed` with `TimeoutStopSec` longer than
`--drain-timeout` lets a stop drain running jobs; the default
`KillMode=control-group` signals executors at once and kills any survivors
with the manager, so nothing is left to adopt.

## Egress control

A build shares its network with whatever it runs, so a proxy inside the job
cannot hold it to anything: the build just opens its own socket. The container
and Kubernetes drivers therefore put an egress gateway outside the job. It
holds each job to the allow list runs sends with the claim (`egress.allow`: an
exact host or `*.suffix`, and a port, where 0 means 443), which always
includes the runs server itself.

`--egress enforce|report|open` chooses how:

- `enforce` (the default for a manager enrolled by this version). Containers:
  each job gets its own network, created `Internal` (no route out) and labelled
  with the pool, manager and job; it is removed and reaped with the job. One
  gateway container per manager, started from the same pinned `--image`
  (`oyzu-executor gateway`), sits on the engine's default network and joins
  each job network. Job containers get `HTTPS_PROXY`, `HTTP_PROXY` and
  `OYZU_EGRESS_GATEWAY` pointing at the gateway's address on their network, and
  their DNS points at it too. Jobs can no longer see one another. Kubernetes:
  the manager applies a gateway Deployment and Service in the jobs namespace, a
  default-deny NetworkPolicy for job pods (selected by their `oyzu.io/job`
  label), and per job a NetworkPolicy, owned by the pod, that allows egress
  only to the gateway's proxy (TCP 3128) and DNS (UDP 53) ports. The pod's IP
  is registered with the gateway once the cluster assigns it, and removed when
  the job ends; pods get the gateway's Service IP as `HTTPS_PROXY` and as their
  only nameserver.
- `report` runs the same gateway and proxy settings but leaves the jobs a
  route out (containers get an ordinary per-job network; Kubernetes gets no
  policy). The gateway logs `Network request to host:port would be blocked
  once egress is enforced` and lets it through. A manager enrolled before
  egress control existed starts in this mode, and records it in
  `<state-dir>/egress`; give it `--egress enforce` when the log is quiet. One
  that was run with `--network` stays `open`.
- `open` is no control: jobs share `--network` (bridge by default). It is the
  only mode that allows `--network NAME`; the container driver refuses the
  combination. The process and VM drivers are always `open`.

The gateway (package [`egressgate`](egressgate/)) answers CONNECT and plain
HTTP for hosts on the job's list and refuses the rest with a 403 that carries
the denial line. It resolves each allowed name itself and dials the address it
checked, so a name cannot change its answer in between. It refuses loopback,
private, link-local, carrier-grade NAT (100.64.0.0/10) and cloud metadata
(169.254.169.254, fd00:ec2::254) addresses unless the allow list names that
exact host (a wildcard never does), and refuses IPv6 unless the IPv6 literal
itself is allowed. Redirects are returned to the client, not followed, so each
hop is checked on its own. A DNS sinkhole on UDP 53 answers every lookup
REFUSED and records it, so a tool that ignores `HTTPS_PROXY` shows up as a
denial instead of a silent failure. The manager registers and unregisters jobs
over a control API on the gateway (a token is required; containers publish it
on the engine host's loopback address only, so an enforcing container manager
needs a local engine, and Kubernetes uses a token Secret and the Service, or
the API server's service proxy for a manager outside the cluster).

Inside the job the runner reads `OYZU_EGRESS_GATEWAY` (or `--egress-gateway`).
When it is set the runner first waits until the gateway has registered the job,
the credential proxy always starts, with or without credential grants, and
chains everything through the gateway instead of dialling out; the gateway's
denials are written to the job log as they happen, in the form

    Blocked network request to registry.npmjs.org:443: not on this job's allow list. A pool admin can allow it with `runs admin pool egress allow <pool> registry.npmjs.org`.

and listed in the job summary beside the destinations the job did contact.

An enforcing pool reports `oyzu.io/egress=enforced`; `report` and `open` pools
report `report` and `open`. It also reports `oyzu.io/untrusted=accepted`, so
runs sends it work from untrusted triggers such as pull requests, only after a
startup self-test passes. The self-test runs a probe job through the same path
as a job and requires that a destination off its list is refused by the
gateway, that a lookup gets no answer and that direct connections to an outside
address (and, on Kubernetes, to the gateway's control port) fail. If it fails,
for example because the cluster's network plugin ignores NetworkPolicy, the pool
reports `egress=open`, takes no untrusted work, logs why and tries again every
minute. Process and VM pools always report `open` and never take it.

The gateway is one more thing that can be down: jobs fail closed while it is.
A container manager restarts a gateway that has died for new jobs; jobs already
running on the old one lose their route out.

### Kubernetes permissions

The manager's Role in the jobs namespace needs, beyond pods and secrets:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "secrets"]   # get on secrets reads the gateway token
    verbs: ["create", "get", "list", "patch", "delete"]
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["create", "get"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["create", "get", "update"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["create", "get", "list", "update", "delete"]
  # only for a manager outside the cluster (--kube-server):
  - apiGroups: [""]
    resources: ["services/proxy"]
    verbs: ["get", "create", "put", "delete"]
```

Those extra rules apply only with `--egress enforce` or `report`. NetworkPolicy
needs a network plugin that enforces it (the self-test checks).

## Building

Build and test with [Oyzu](https://github.com/oyzuai/oyzu): `oyzu build`. The
manager's end-to-end tests run against the real runs service, so they live in
the platform repository and import these packages.

## Releases

Each `v*` tag publishes `oyzu-pool-manager` and `oyzu-executor` for Linux
(amd64 and arm64) from [the release workflow](.github/workflows/release.yml).
Every archive comes with a CycloneDX SBOM, and the release carries
`SHA256SUMS`, its Sigstore signature bundle and SLSA build provenance. The
workflow's header shows how to verify a download.

## License

`fleet` is licensed under the [Functional Source License, Version 1.1, ALv2
Future License](LICENSE.md) (FSL-1.1-ALv2). Each version converts to the Apache
License, Version 2.0 two years after it is made available.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a signed
Contributor License Agreement.

## Job logs

The executor captures build/run stdout and stderr beside the existing 60-line
masked check-summary tail. Build/run commands receive `--json`; a plan command
and its stdout plan record keep their existing invocation and handling. Known
oyzu stderr events become scoped log entries; native output and unknown events
remain text. Plain lines inherit a single running scope, or `oyzu` when output
is ambiguous. Checkout/start/exit entries use `runner`.

The same streaming maskers protect both sinks before bytes reach disk or the
network. Build secrets, source/job/startup credentials, issued ID tokens, the
broker credential and egress values all share the existing mask forms and
six-byte floor. Per-entry `redacted` counts actual substitutions. Build text
still never goes to the executor's own stdout/stderr or administrative slog.

A private directory beside the checkout holds masked NDJSON and, for very large
logs, a bounded disk FIFO. Uploads open every second, 256 KiB or 1,000 entries;
a single JSON-escaped entry may exceed 256 KiB. Text splits at 64 KiB without
tearing UTF-8, invalid bytes become U+FFFD, and line endings remain intact.
The 512 MiB cap keeps approximately half as the live head and half as the most
recent tail. After the head fills, the tail waits until command exit so dropping
the middle cannot invalidate uploaded chunks or cursors. One system entry
counts dropped entries and spooled bytes. Full entry bodies stay on disk
instead of accumulating in memory.

`runnerclient.UploadLogs` posts to `/runner/v1/job/logs` with the job bearer.
The JSON body contains `attempt`, gapless `seq`, `first_sequence`,
`last_sequence`, `entry_count`, `data` (base64 gzip NDJSON) and `hash`
(lowercase SHA-256 of the uncompressed bytes, including newlines). A 409's
`next_seq` rewinds delivery to the retained spool; identical retries are safe.
`FinishLogs` posts to `/runner/v1/job/logs/finish` with `attempt`, `final_seq`,
`total_entries`, and the SHA-256 of all uncompressed chunks concatenated in
order; `incomplete` reports a capture failure. The executor waits at most
30 seconds for logs before reporting the job outcome. Pending uploads then
continue with the same token for up to 15 minutes after job finish; `Run`
waits for delivery to stop before removing the spool. Fast uploads complete
the log handshake before job finish. `Config.LogDrainTimeout` can shorten the
post-finish window and caps the pre-outcome wait too. Transient failures back
off from 100 ms to five seconds; expiration never changes the build's outcome.
Spool/network failures log only administrative metadata.
Spool files close before cleanup, including on Windows.

## Dependency maintenance

The [Dependabot configuration](.github/dependabot.yml) maintains the root Go module and GitHub Actions. Review changes against the supported Go toolchain and the release workflow; contribution and release requirements remain in force.

Routine version checks run on weekdays around 06:30 America/New_York. Minor and patch updates are grouped; major upgrades remain individual proposals. Security updates use a separate group and do not wait for the version-update schedule. Each update block allows three open routine PRs and assigns proposals to `micahlmartin`; GitHub applies a separate limit to security-update PRs. Review, applicable verification and existing merge requirements still apply.

Dependabot alerts and security updates must also be enabled in repository settings; the YAML does not enable those switches. Use the standard GitHub runner for update jobs. The configuration becomes active after it reaches the default branch.
