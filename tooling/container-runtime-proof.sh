#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ] || [ -z "${OYZU_CRUN:-}" ] || [ ! -x "$OYZU_CRUN" ]; then
  echo 'container-runtime-proof requires Linux and OYZU_CRUN pointing to the pinned runtime provisioned by normal oyzu install.' >&2
  exit 2
fi
proof_dir="$(mktemp -d)"
registry_name="fleet-runtime-registry-$$"
image_tag=""
cleanup() {
  docker rm --force --volumes "$registry_name" >/dev/null 2>&1 || true
  if [ -n "$image_tag" ]; then docker image rm "$image_tag" >/dev/null 2>&1 || true; fi
  rm -rf "$proof_dir"
}
trap cleanup EXIT
cd "$root"
mkdir -p "$proof_dir/stage/work" "$proof_dir/stage/etc" "$proof_dir/stage/rootfs/"{dev,proc,sys,tmp,run,output}
CGO_ENABLED=0 go build -o "$proof_dir/stage/probe" ./tooling/fixtures/rootless-oci
cp "$proof_dir/stage/probe" "$proof_dir/stage/rootfs/probe"
cp "$OYZU_CRUN" "$proof_dir/stage/crun"
printf 'proof:x:1000:1000:Fleet runtime proof:/work:/probe\n' > "$proof_dir/stage/etc/passwd"
printf 'proof:x:1000:\n' > "$proof_dir/stage/etc/group"
cat > "$proof_dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY --chown=1000:1000 stage/ /
USER 1000:1000
DOCKERFILE
docker run -d --name "$registry_name" -p 127.0.0.1::5000 registry:2 >/dev/null
registry_port="$(docker port "$registry_name" 5000/tcp | head -n1 | sed 's/.*://')"
image_tag="127.0.0.1:$registry_port/rootless-runtime:proof"
docker build --network=none -t "$image_tag" "$proof_dir"
docker push "$image_tag"
image_digest="$(docker image inspect "$image_tag" --format '{{index .RepoDigests 0}}')"
FLEET_RUNTIME_IMAGE="$image_digest" go test ./manager/container -run '^TestDaemonlessOCIWithContainerPolicy$' -count=1 -v
