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
  [`vm`](manager/vm/) drivers (AWS, Google Cloud and Azure adapters). Drivers
  are compiled in and chosen by configuration.
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

The container and Kubernetes manager drivers require `--image` to be pinned
by SHA-256 digest: `NAME@sha256:DIGEST`, where `DIGEST` is exactly 64 lowercase
hex characters. A tag may accompany the digest (`NAME:TAG@sha256:DIGEST`),
but bare names and tag-only references (including version tags) are refused
at startup. This matches kindrunner's digest requirement and keeps executor
images immutable across jobs. Use the digest published by your image registry.

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
