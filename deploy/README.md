# Public executor image

`ghcr.io/oyzuai/oyzu-pool-executor:<version>` is built from
[executor.Containerfile](executor.Containerfile) using the published `docker/image`
plugin, pinned together with `go/app` in `oyzu.lock`. The Go builder is
`0.1.0-preview.2`, whose captured-plan support handles builds outside the
single-main native host lane. This release has no Darwin arm64 plugin payload.
Locked replay does not require machine preview opt-in in CI. It is linux/amd64
until the public oyzu release provides an arm64 CLI.
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
on PATH. Release archive generation requires a real Git checkout for Go's VCS
stamping. The image-proof helper clones the committed HEAD into a disposable
checkout under `/srv/dev/tmp`; commit changes before running it. This checkout
requirement belongs to release archive generation, not the isolated `fleet`
build or its vet, test and SBOM tooling.

```bash
bash tooling/executor-image-proof.sh
```

The equivalent build sequence is:

```bash
oyzu config set --global plugins.preview true
oyzu install
oyzu build --isolated fleet
oyzu exec -- go version
oyzu exec -- bash tooling/release-build.sh 0.1.0 build/release
bash tooling/prepare-executor-image.sh 0.1.0
oyzu build --isolated executor-image
```

The release workflow installs the pinned CLI, companion shim and notices directly
from the public `oyzuai/oyzu-releases` assets and verifies their SHA-256 values.
It uses fleet's own `oyzu.toml` and `oyzu.lock` for every Go command. The
workflow and image-proof helper enable `plugins.preview` in a job-scoped
HOME/config before acquisition, so the public preview catalog can supply the
locked Go and Docker releases without changing their pins or host configuration.
The single `fleet` target selects the root Go module. Preview.2 plans a captured
build action per main and collects the named `pool-server`, `manager` and
`executor` binaries. Always use `oyzu build --isolated fleet`: the host lane
still refuses multi-main modules. Before any frozen `oyzu exec` commands,
non-frozen `oyzu install` discovers all targets and acquires both locked builder
plugins and the pinned tools. Building only `fleet` does not acquire
`docker/image`, which `exec` also needs. Install can record host-specific
`resolved_environment` entries; the proof script checks that all other lock
fields, including tool recipes and plugin pins, remain unchanged.

Acquiring through install avoids a circular dependency: the executor image
context needs a verified release archive, and archive generation needs `exec`.
After installation, build fleet in isolation, generate the archives outside
`dist`, prepare the real image context, then build the image in isolation.
Acquisition or isolation failures stop the release with oyzu's diagnostic;
there is no host-lane fallback.
It never falls back to another repository's toolset or builds plugins from source.

Release archives, SBOMs and checksums go to `build/release`; `dist` is reserved
for oyzu's build bundle. Keeping the archives outside `dist` lets both the
initial fleet build and the later image build manage a valid bundle there.
The image is built with `oyzu build --isolated executor-image`. As an explicit
image-only stopgap, Docker loads the OCI archive and pushes it using the
version tag as transport. The workflow requires the remote manifest digest to match the digest
oyzu built, then signs that immutable digest keylessly with `cosign sign` and
checks it with `cosign verify` against the release workflow and tag identity.
It does not manufacture build-provenance evidence or configure an ephemeral
key as an accepted provenance authority. Tarball signing and GitHub build
attestations stay in place.

Planned follow-up: switch to `oyzu publish` with keyless intent once oyzu row 23 ships.

The first GHCR package must be made public by its owner if organization defaults
create private packages; the workflow token cannot set package visibility.

Verify tarballs with the release notes' `cosign verify-blob`, `sha256sum` and
`gh attestation verify` commands. Verify the image's subject signature with:

```bash
cosign verify \
  --certificate-identity 'https://github.com/oyzuai/fleet/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/oyzuai/oyzu-pool-executor@sha256:<release-digest>
```

An isolated build inside the image additionally requires the outer container
runtime to permit crun's user/mount/network namespaces and seccomp setup.
A failed namespace probe is a failed isolation qualification; do not disable
isolation or substitute an unisolated build.
