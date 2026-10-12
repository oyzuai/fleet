# fleet

The Oyzu pool manager and executor.

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
process-only; `--engine`, `--network` and `--user` are container-only) are
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

## Building

See [execution trust and proxies](executor/README.md) for the typed
`execution_config` job field, supported projections, evidence and current limits.

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
