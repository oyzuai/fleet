# Public executor image

`ghcr.io/oyzuai/oyzu-pool-executor:<version>` is built from
[executor-image/Dockerfile](executor-image/Dockerfile) using the published `docker/image`
plugin, pinned together with `go/app` in `oyzu.lock`. The Go builder is
`0.1.0-preview.2`, whose captured-plan support handles builds outside the
single-main native host lane. This release has no Darwin arm64 plugin payload.
Locked replay does not require machine preview opt-in in CI. It is linux/amd64
until the public oyzu release provides an arm64 CLI.
Use the digest in the release notes for the manager's `--image`.

`tools.lockPlatforms` in `oyzu.toml` explicitly preserves tool pin coverage for
`linux/amd64/gnu`, `linux/arm64/gnu`, `darwin/amd64/native`,
`darwin/arm64/native` and `windows/amd64/msvc` when running `oyzu pin`.
This metadata coverage does not extend plugin payload availability or image
support. The lock also records the default Docker quality set: dockerfmt 0.5.4
and Hadolint 2.15.1, including their asset digests and license records.

The base is Docker's official `buildpack-deps:noble-scm`, based on Ubuntu 24.04
and pinned by OCI index digest. It supplies glibc, `/bin/sh`, `/bin/sleep` and
the complete Git package, including its helpers, runtime libraries and HTTPS
transport. Git is required for ordinary remote commit assignments; a source
snapshot alone does not exercise that path. The upstream SCM variant also
includes Mercurial, OpenSSH client, Subversion and procps; its curl base includes
the public CA and download tools. No individual host executable is copied.
Base package notices under `/usr/share/doc` and `/usr/share/common-licenses`
remain intact; the image's `BASE-IMAGE-NOTICES.md` records the upstream sources.
The image runs as uid/gid 1000 with `/work` owned
by that user. `XDG_DATA_HOME=/opt/oyzu/data` is fixed and writable by uid 1000.
The CLI and companion shim live under that data root and are linked from
`/usr/local/bin`. `/etc/oyzu/config.toml` enables published preview plugins;
no plugins or language toolchains are built into the image. No private trust
roots or cache configuration are included.

The `executor-image` target in `build.yaml` declares every download by public
HTTPS URL and SHA-256: oyzu `oyzu/v0.2.5`, its companion shim and notices,
upstream static crun `1.30.1` and its corresponding source archive, and Ubuntu's
`ca-certificates` package. Raw fetches keep their URL filename; the Dockerfile
reads them through `oyzu-fetch-<name>` contexts. Version and digest updates
belong in `build.yaml`. The build runs offline after these inputs are captured.

The Dockerfile, preview configuration and fleet notices are tracked source.
The notices under `executor-image/rootfs/usr/share/doc/oyzu-pool-executor`
retain fleet's license, additional notices, Moby profile and runner schema
licenses. Keep these copies in sync when their originals change. The build
also retains upstream oyzu notices, crun COPYING/COPYING.libcrun and complete
corresponding source, and ca-certificates copyright notices. Only the public
Mozilla roots from that package enter the trust bundle.

The image receives the `fleet` target's named `executor` artifact through
`materialize`, into `rootfs/usr/local/bin`. The Dockerfile renames the versioned
file to `oyzu-executor` without rebuilding it. No prepared context or release
archive supplies that binary. Image `--version` matches the captured artifact;
the separate release archive build injects its requested `main.version`.

Build from the repository root with the released oyzu:

```bash
oyzu config set --global plugins.preview true
oyzu install
oyzu build --isolated fleet executor-image
oyzu exec -- go version
```

The release workflow and image-proof helper use that same single isolated build
for both targets. The root Go module produces named `pool-server`, `manager`
and `executor` binaries; materialization orders the image after its compatible
Go producer. There is no host-lane fallback. Docker image preparation and its
BuildKit worker require a Linux Docker engine, the provisioned digest-pinned
SCM base, and permission to run the isolated workers.

The release workflow downloads the pinned public CLI, companion shim and notices
and verifies their SHA-256 values. It uses fleet's own `oyzu.toml` and `oyzu.lock`
for every Go command. The workflow and helper enable `plugins.preview` in a
job-scoped HOME/config before acquisition. Non-frozen `oyzu install` acquires
both locked plugins and pinned tools before frozen `oyzu exec` needs them.
Install can record host-specific `resolved_environment` entries; the helper
checks that all other lock fields, including recipes and plugin pins, stay
unchanged. It never builds plugins from source.

Run the complete image proof outside the sandbox:

```bash
bash tooling/executor-image-proof.sh
```

The helper clones committed HEAD under `/srv/dev/tmp`; commit changes first.
It checks Git's upload-pack and HTTPS helper plus the CA bundle, then performs
the executor's init/fetch/detached-checkout sequence against a disposable local
repository as uid 1000. That check needs no credentials or external Git server;
it does not claim an external HTTPS handshake was tested.
Release archive generation needs this real Git checkout for Go's VCS stamping.
The isolated `fleet` build and its vet, test and SBOM tooling also support source
snapshots without `.git`. Archive generation additionally requires
cyclonedx-gomod v1.9.0 on PATH (the helper installs it through fleet's Go tools):

```bash
oyzu exec -- bash tooling/release-build.sh 0.1.0 build/release
```

Archives, SBOMs and checksums go to `build/release`; `dist` is reserved for
oyzu's build bundle. The image build is independent of these archives.
As an explicit image-only stopgap, Docker loads the OCI archive and pushes it
using the version tag as transport. The workflow requires the remote manifest
digest to match the digest oyzu built, signs that immutable digest keylessly
with `cosign sign`, then checks it with `cosign verify` against the release
workflow and tag identity. It does not manufacture build-provenance evidence
or configure an ephemeral key as an accepted provenance authority. Tarball
signing and GitHub build attestations stay in place.

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
