# Additional license notices

Fleet's implementation license is in `LICENSE.md`. The following non-module
materials retain their separate licenses. Release archives include these
notices and the corresponding full license texts; the Go module SBOM describes
module dependencies separately.

## Moby container syscall policy

Source: https://github.com/moby/profiles/blob/6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef/seccomp/default.json

License: Apache License, Version 2.0, retained in source at
`manager/container/profiles/LICENSE` and in binary archives at
`third-party/moby-profiles/LICENSE`.

The unmodified input has SHA-256
`6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6`.
Fleet derives its fixed profile in `manager/container/sandbox.go`, adding the
documented rootless namespace setup calls and session-keyring join rule. These
are Fleet's modifications; the upstream snapshot is unchanged. Binary archives
also retain that input as `third-party/moby-profiles/docker-default.json`.

## Public runner readiness schema

The schema under `readiness/schema` comes from the public Oyzu runner-v1
contract, pinned in that directory's source comments. It is Apache-2.0 licensed;
its full license is retained in `readiness/schema/LICENSE` and in binary
archives at `third-party/runner-v1/LICENSE`.

No Wardyn source, assets or dependency is included.
