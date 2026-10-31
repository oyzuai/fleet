#!/usr/bin/env bash
# Run inside fleet's `oyzu exec -- bash ...`.
set -euo pipefail
version=${1:?usage: release-build.sh VERSION [OUTPUT_DIRECTORY]}
out=${2:-build/release}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
mkdir -p "$out"
out=$(cd "$out" && pwd)
[[ -z $(find "$out" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'Output directory must be empty' >&2; exit 1; }
staging=$(mktemp -d "$out/.staging.XXXXXX")
trap 'rm -rf "$staging"' EXIT
export CGO_ENABLED=0 GOFLAGS='-trimpath -mod=readonly'
for prog in pool-server:oyzu-pool-server manager:oyzu-pool-manager executor:oyzu-executor; do
  dir=${prog%%:*}; name=${prog##*:}
  for arch in amd64 arm64; do
    export GOOS=linux GOARCH=$arch
    stem=${name}_${version}_${GOOS}_${GOARCH}
    mkdir -p "$staging/$stem"
    go build -ldflags "-s -w -X main.version=$version" -o "$staging/$stem/$name" "./cmd/$dir"
    cp LICENSE.md THIRD_PARTY_NOTICES.md "$staging/$stem/"
    mkdir -p "$staging/$stem/third-party/moby-profiles" "$staging/$stem/third-party/runner-v1"
    cp manager/container/profiles/LICENSE manager/container/profiles/docker-default.json "$staging/$stem/third-party/moby-profiles/"
    cp readiness/schema/LICENSE "$staging/$stem/third-party/runner-v1/"
    tar -C "$staging" -czf "$out/$stem.tar.gz" "$stem"
    # Inspect the exact compiled binary, including its embedded module list.
    if command -v cyclonedx-gomod >/dev/null; then
      cyclonedx-gomod bin -json -licenses -version "$version" -output "$out/$stem.cdx.json" "$staging/$stem/$name"
    else
      echo 'cyclonedx-gomod v1.9.0 must be on PATH' >&2; exit 1
    fi
  done
done
(cd "$out" && sha256sum -- *.tar.gz *.cdx.json > SHA256SUMS && sha256sum --check SHA256SUMS)
