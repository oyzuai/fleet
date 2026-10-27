# Public executor image

`ghcr.io/oyzuai/oyzu-pool-executor:<version>` is built from
[executor.Containerfile](executor.Containerfile) using the published `docker/image`
plugin, pinned together with `go/app` in `oyzu.lock`. Locked replay does not
require machine preview opt-in in CI. It is linux/amd64 until the public oyzu release provides an arm64 CLI.
Use the digest in the release notes for the manager's `--image`.

The base is Ubuntu 24.04, pinned by OCI index digest: it supplies glibc for the
released CLI plus `/bin/sh` and `/bin/sleep`. Base package notices under
`/usr/share/doc` remain intact. The image runs as uid/gid 1000 with `/work` owned
by that user. `XDG_DATA_HOME=/opt/oyzu/data` is fixed and writable by uid 1000.
The CLI and companion shim live under that data root and are linked from
`/usr/local/bin`. `/etc/oyzu/config.toml` enables published preview plugins;
no plugins or language toolchains are built into the image. No private trust
roots or cache configuration are included.

`tooling/prepare-executor-image.sh` pins oyzu `oyzu/v0.2.3`, its shim and notices
against the release asset API's SHA-256 values (this release does not provide a
separate checksum file). It pins upstream static crun `1.30.1` and its source
archive by SHA-256 and exposes it as `OYZU_CRUN`. It extracts Ubuntu's pinned
`ca-certificates` package into the context to obtain only public Mozilla roots
and their copyright notices. It verifies the fleet release checksums and copies
the already-built executor from its archive. Upstream oyzu notices, fleet license
and third-party notices, crun COPYING/COPYING.libcrun and corresponding source
archive, and ca-certificates copyright notices are retained under
`/usr/share/doc`. Updating a dependency requires updating its checksum and
retaining its notices.

Build from the repository root with a released oyzu and cyclonedx-gomod v1.9.0
on PATH:

```bash
oyzu exec -- bash tooling/release-build.sh 0.1.0 dist/release
bash tooling/prepare-executor-image.sh 0.1.0
oyzu build executor-image
```

The release workflow installs oyzu through its pinned `setup-oyzu` action and
uses only published CLI and plugin releases. It builds the image with oyzu,
signs an ephemeral Ed25519 build witness and publication intent, then uses
`oyzu publish` with its configured keyless Sigstore subject signer. The witness
keys are job-local; consumer trust is the GitHub OIDC subject signature checked
against the release workflow and tag, not a durable witness key. Oyzu publishes
by digest and reads the image and signature back. Docker only moves the version
tag to that verified digest and checks that the alias resolves unchanged.
The first GHCR package must be made public by its owner if organization defaults
create private packages; the workflow token cannot set package visibility.

Verify tarballs with the release notes' `cosign verify-blob`, `sha256sum` and
`gh attestation verify` commands. Verify the image's subject signature with:

```bash
cosign verify --new-bundle-format \
  --certificate-identity 'https://github.com/oyzuai/fleet/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/oyzuai/oyzu-pool-executor@sha256:<release-digest>
```

An isolated build inside the image additionally requires the outer container
runtime to permit crun's user/mount/network namespaces and seccomp setup.
A failed namespace probe is a failed isolation qualification; do not disable
isolation or substitute an unisolated build.
