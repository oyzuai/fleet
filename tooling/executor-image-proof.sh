#!/usr/bin/env bash
# Run on dev01 outside the sandbox. Receipts go to the terminal, never files.
set -euo pipefail
source_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p /srv/dev/worktrees/.rc-proofs
# Keep Go test Unix-socket paths below the kernel path-length limit.
scratch=$(mktemp -d /srv/dev/worktrees/.rc-proofs/f6.XXXXXX)
container_name="fleet-executor-proof-${scratch##*.}"
plugin_store="$scratch/data/oyzu/tools"
loaded_id=
image_snapshot=
image_snapshot_taken=false
run() {
  local label=$1 result
  shift
  printf '\nRUN %s:' "$label"
  printf ' %q' "$@"
  printf '\n'
  if "$@"; then
    printf 'RESULT %s: PASS\n' "$label"
  else
    result=$?
    printf 'RESULT %s: FAIL (exit %s)\n' "$label" "$result" >&2
    return "$result"
  fi
}
cleanup() {
  local result=$? cleanup_result=0 tag prior_id current_id
  trap - EXIT
  set +e
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    run cleanup-container docker rm -f "$container_name" || cleanup_result=1
  fi
  if [[ $image_snapshot_taken == true && -n $loaded_id ]] && docker image inspect "$loaded_id" >/dev/null 2>&1; then
    # Restore any preexisting tag the archive loader replaced; remove only new
    # tags pointing to this proof's image. Never prune a shared Docker daemon.
    while read -r tag current_id; do
      [[ $current_id == "$loaded_id" && $tag != '<none>:<none>' ]] || continue
      prior_id=$(printf '%s\n' "$image_snapshot" | awk -v tag="$tag" '$1 == tag {print $2; exit}')
      if [[ -n $prior_id && $prior_id != "$loaded_id" ]]; then
        run restore-image-tag docker tag "$prior_id" "$tag" || cleanup_result=1
      elif [[ -z $prior_id ]]; then
        run cleanup-image-tag docker image rm --no-prune "$tag" || cleanup_result=1
      fi
    done < <(docker image ls --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}')
    if ! printf '%s\n' "$image_snapshot" | awk -v id="$loaded_id" '$2 == id {found=1} END {exit !found}'; then
      if docker image inspect "$loaded_id" >/dev/null 2>&1; then
        run cleanup-image docker image rm --no-prune "$loaded_id" || cleanup_result=1
      fi
    fi
  fi
  run scratch-disk-used du -sh "$scratch" || cleanup_result=1
  run cleanup-scratch /usr/bin/python3 - "$scratch" <<'PY'
import os, pathlib, shutil, stat, sys
p = pathlib.Path(sys.argv[1]).resolve()
assert p.parent == pathlib.Path('/srv/dev/worktrees/.rc-proofs')
assert p.name.startswith('f6.')
for root, _, _ in os.walk(p):
    os.chmod(root, stat.S_IRWXU)
shutil.rmtree(p)
PY
  [[ $? == 0 ]] || cleanup_result=1
  if [[ $result == 0 && $cleanup_result != 0 ]]; then result=1; fi
  printf 'RESULT overall: exit %s (cleanup exit %s)\n' "$result" "$cleanup_result"
  exit "$result"
}
trap cleanup EXIT
mkdir -p "$scratch"/{fleet,t,bin,home,go-path,go-mod,go-cache}
export TMPDIR="$scratch/t" GOPATH="$scratch/go-path"
export GOMODCACHE="$scratch/go-mod" GOCACHE="$scratch/go-cache"
export GOTOOLCHAIN=local
export PATH="$scratch/bin:$PATH"
run docker-access docker info
run copy-source bash -o pipefail -c '
  tar -C "$1" --exclude=./.git --exclude=./.oyzu --exclude=./build --exclude=./dist \
    --exclude=./deploy/executor-image -cf - . | tar -C "$2" -xf -
' bash "$source_root" "$scratch/fleet"
# The generated context was excluded entirely, including any prior preparation.
mkdir -p "$scratch/fleet/deploy/executor-image"
cd "$scratch/fleet"
base=https://github.com/oyzuai/oyzu-releases/releases/download/oyzu/v0.2.3
run download-oyzu curl -fsSL --retry 3 "$base/oyzu-linux-x86_64" -o "$scratch/bin/oyzu"
run download-shim curl -fsSL --retry 3 "$base/oyzu-shim-linux-x86_64" -o "$scratch/bin/oyzu-shim"
run verify-oyzu sha256sum --check <<CHECKSUMS
99230d5b6cc452ea3e796e1fa8149abb6e21eb4ee85cc830d08d92e282d427d7  $scratch/bin/oyzu
7d3284db39d96e8b817f8a244b8cd6a9d01c540a4501552c3b9dc4c0618cf653  $scratch/bin/oyzu-shim
CHECKSUMS
chmod +x "$scratch/bin/oyzu" "$scratch/bin/oyzu-shim"
# All oyzu commands use one initially empty HOME/store. The explicit empty
# user-config location excludes inherited host user bindings without changing
# machine policy. Do not add development/source bindings or re-pin the lock.
oyzu_env() {
  env HOME="$scratch/home" \
    XDG_CONFIG_HOME="$scratch/home/.config" XDG_DATA_HOME="$scratch/data" \
    XDG_CACHE_HOME="$scratch/cache" OYZU_USER_CONFIG="$scratch/home/.config/oyzu/config.toml" \
    "$scratch/bin/oyzu" "$@"
}
# Non-frozen install can record this host's resolved environments. Preserve
# every other lock field, including exact plugin payloads and tool recipes.
lock_pins() {
  /usr/bin/python3 - <<'PYLOCK'
import hashlib, json, pathlib, tomllib
lock = tomllib.loads(pathlib.Path('oyzu.lock').read_text())
lock.pop('resolved_environment', None)
print(hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
PYLOCK
}
run released-cli oyzu_env --version
pins_before=$(lock_pins)
run preview-opt-in oyzu_env config set --global plugins.preview true
# Acquire all locked plugins before exec. The image context needs release
# archives, so building executor-image cannot bootstrap this environment.
run acquire-plugins oyzu_env install --store "$plugin_store"
test "$(lock_pins)" = "$pins_before"
printf 'RESULT unchanged-tool-and-plugin-pins-after-install: PASS\n'
run fleet-go oyzu_env exec --store "$plugin_store" -- go version
run fleet-build oyzu_env build --isolated --store "$plugin_store" fleet
for binary in pool-server manager executor; do
  artifact=$(jq -er --arg binary "$binary" '[.artifacts[] | select(.target == "fleet" and .name == $binary) | .path] | if length == 1 then .[0] else error("expected one binary per main") end' dist/manifest.json)
  run "binary-$binary" test -x "dist/$artifact"
done
run fleet-vet oyzu_env exec --store "$plugin_store" -- go vet ./cmd/pool-server ./cmd/manager ./cmd/executor
run fleet-tests oyzu_env exec --store "$plugin_store" -- go test ./cmd/pool-server ./cmd/manager ./cmd/executor
run fleet-format oyzu_env exec --store "$plugin_store" -- bash -ec 'test -z "$(gofmt -l cmd/pool-server/main.go cmd/manager/main.go cmd/executor/main.go)"'
run fleet-config oyzu_env config validate
run sbom-helper oyzu_env exec --store "$plugin_store" -- env GOBIN="$scratch/bin" go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
run release-archives oyzu_env exec --store "$plugin_store" -- bash tooling/release-build.sh 0.1.0 build/release
run prepare-context bash tooling/prepare-executor-image.sh 0.1.0
# The image build reuses the acquired store; archives never occupy dist/.
run image-build oyzu_env build --isolated --store "$plugin_store" executor-image
test "$(lock_pins)" = "$pins_before"
printf 'RESULT unchanged-tool-and-plugin-pins-after-build: PASS\n'
archive=$(jq -er '[.artifacts[] | select(.name == "image") | .path] | if length == 1 then .[0] else error("expected one image") end' dist/manifest.json)
digest=$(jq -er '.artifacts[] | select(.name == "image") | .ociDigest' dist/manifest.json)
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]
loaded_id=$(tar -xOf "dist/$archive" "blobs/sha256/${digest#sha256:}" | jq -er '.config.digest')
[[ $loaded_id =~ ^sha256:[0-9a-f]{64}$ ]]
printf 'RESULT image identities: manifest=%s config=%s\n' "$digest" "$loaded_id"
image_snapshot=$(docker image ls --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}')
image_snapshot_taken=true
run image-load docker load --input "dist/$archive"
run image-config docker image inspect "$loaded_id"
run uid-and-versions docker run --rm --name "$container_name" --entrypoint /bin/sh "$loaded_id" -ec '
  test "$(id -u)" = 1000
  printf "RESULT container uid: %s\n" "$(id -u)"
  test -w /work && test -w "$XDG_DATA_HOME"
  printf "RUN oyzu --version (uid 1000)\n"
  oyzu --version
  printf "RESULT oyzu-version: PASS\n"
  printf "RUN oyzu-executor --version (uid 1000)\n"
  oyzu-executor --version
  test "$(oyzu-executor --version)" = "oyzu-executor 0.1.0"
  printf "RESULT executor-version: PASS\n"
  printf "RUN crun --version (uid 1000)\n"
  crun --version
  printf "RESULT crun-version: PASS\n"
'
example=/srv/dev/repos/oyzu/examples/builds/go-app/project
[[ -f $example/go.mod && -f $example/main.go ]]
mkdir "$scratch/go-app"
run copy-go-app cp -a "$example/." "$scratch/go-app/"
# No --privileged, extra capabilities, unconfined policies, Docker socket,
# host toolchain mounts or fallback to an unisolated build.
# Keep stdout/stderr attached: crun diagnostics pass through verbatim.
# On failure, stop without retrying; EXIT still cleans up.
run isolated-go-app docker run --rm --name "$container_name" \
  --mount "type=bind,src=$scratch/go-app,dst=/input,readonly" \
  --entrypoint /bin/sh "$loaded_id" -ec '
    mkdir /work/go-app
    cp -R /input/. /work/go-app/
    cd /work/go-app
    oyzu trust
    oyzu build --isolated
  '
