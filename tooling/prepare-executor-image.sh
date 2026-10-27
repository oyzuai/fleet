#!/usr/bin/env bash
# Prepare a secret-free Docker context using only verified public release bytes.
set -euo pipefail
version=${1:?usage: prepare-executor-image.sh VERSION [RELEASE_DIRECTORY]}
release=${2:-dist/release}
context=deploy/executor-image
[[ ! -e $context/rootfs && ! -e $context/downloads ]] || { echo "$context already exists; remove the generated context files first" >&2; exit 1; }
mkdir -p "$context/downloads" "$context/rootfs"
fetch() {
  local url=$1 file=$2 checksum=$3
  curl --fail --silent --show-error --location --retry 3 "$url" -o "$context/downloads/$file"
  echo "$checksum  $context/downloads/$file" | sha256sum --check -
}
base=https://github.com/oyzuai/oyzu-releases/releases/download/oyzu/v0.2.3
# SHA-256 values published by GitHub's release asset API (v0.2.3 has no
# separate SHA256SUMS asset). Pin the CLI, companion shim and upstream notices.
fetch "$base/oyzu-linux-x86_64" oyzu 99230d5b6cc452ea3e796e1fa8149abb6e21eb4ee85cc830d08d92e282d427d7
fetch "$base/oyzu-shim-linux-x86_64" oyzu-shim 7d3284db39d96e8b817f8a244b8cd6a9d01c540a4501552c3b9dc4c0618cf653
fetch "$base/oyzu-notices-linux-x86_64.txt" oyzu-notices.txt d3765497ef0c2fa5ff5272d825be7d745501053c181b87f76853dbc147b341cb
fetch https://github.com/containers/crun/releases/download/1.30.1/crun-1.30.1-linux-amd64 crun 86d1e6a0e76945975d3aebfab39cbc6a26eea15f1c3fc66b6776d19e5dc346a0
# Keep upstream's complete corresponding source, including COPYING,
# COPYING.libcrun and dependency/build instructions with the runtime.
fetch https://github.com/containers/crun/releases/download/1.30.1/crun-1.30.1.tar.gz crun-source.tar.gz 99d036d95113552b6df66c7c879432835504bf0e525fc0372745071df129527b
fetch https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.1_all.deb ca-certificates.deb 8a0a754aaafed72cc8efb8c1731808133284a84fbfc76a4fcc73fce9e01b4187
root=$context/rootfs
mkdir -p "$root/opt/oyzu/data/oyzu/bin" "$root/usr/local/bin" "$root/etc/oyzu" "$root/usr/share/doc/oyzu-pool-executor" "$root/usr/share/doc/crun" "$root/etc/ssl/certs"
install -m755 "$context/downloads/oyzu" "$context/downloads/oyzu-shim" "$root/opt/oyzu/data/oyzu/bin/"
install -m755 "$context/downloads/crun" "$root/usr/local/bin/crun"
cp "$context/downloads/oyzu-notices.txt" "$root/usr/share/doc/oyzu-pool-executor/"
cp "$context/downloads/crun-source.tar.gz" "$root/usr/share/doc/crun/"
tar -xOf "$context/downloads/crun-source.tar.gz" crun-1.30.1/COPYING > "$root/usr/share/doc/crun/COPYING"
tar -xOf "$context/downloads/crun-source.tar.gz" crun-1.30.1/COPYING.libcrun > "$root/usr/share/doc/crun/COPYING.libcrun"
# Extract the public trust roots and their copyright notices without installing
# packages or copying host trust (in particular, no private cache CA).
dpkg-deb -x "$context/downloads/ca-certificates.deb" "$context/ca"
cat "$context"/ca/usr/share/ca-certificates/mozilla/*.crt > "$root/etc/ssl/certs/ca-certificates.crt"
cp -R "$context/ca/usr/share/doc/ca-certificates" "$root/usr/share/doc/"
printf '[plugins]\npreview = true\n' > "$root/etc/oyzu/config.toml"
# Verify the release's entire checksum set before taking the existing binary.
(cd "$release" && sha256sum --check SHA256SUMS)
stem=oyzu-executor_${version}_linux_amd64
tar -xzf "$release/$stem.tar.gz" -C "$context" "$stem"
install -m755 "$context/$stem/oyzu-executor" "$root/usr/local/bin/oyzu-executor"
cp -R "$context/$stem/"* "$root/usr/share/doc/oyzu-pool-executor/"
rm "$root/usr/share/doc/oyzu-pool-executor/oyzu-executor"
cp deploy/executor.Containerfile "$context/Dockerfile"
rm -rf "$context/downloads" "$context/ca" "$context/$stem"
