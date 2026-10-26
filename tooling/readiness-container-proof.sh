#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proof_dir="$(mktemp -d)"
proof_name="fleet-readiness-proof-$$"
registry_name="$proof_name-registry"
canary_name="$proof_name-canary"
cleanup(){
 docker rm --force --volumes "$canary_name" "$registry_name" >/dev/null 2>&1 || true
 if [ -n "${image_tag:-}" ];then docker image rm "$image_tag" >/dev/null 2>&1 || true;fi
 rm -rf "$proof_dir"
}
trap cleanup EXIT
cd "$root"
CGO_ENABLED=0 go build -o "$proof_dir/executor" ./cmd/executor
cat > "$proof_dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY --chmod=0555 executor /executor
USER 1000:1000
DOCKERFILE
docker run -d --name "$registry_name" -p 127.0.0.1::5000 registry:2 >/dev/null
registry_port="$(docker port "$registry_name" 5000/tcp | head -n1 | sed 's/.*://')"
image_tag="127.0.0.1:$registry_port/readiness-executor:proof"
docker build --network=none -t "$image_tag" "$proof_dir"
docker push "$image_tag"
image_digest="$(docker image inspect "$image_tag" --format '{{index .RepoDigests 0}}')"
docker run -d --name "$canary_name" --network bridge "$image_digest" /executor gateway readiness-canary --http :8080 --dns :8053 >/dev/null
canary_ip="$(docker inspect "$canary_name" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
FLEET_READINESS_IMAGE="$image_digest" \
FLEET_READINESS_CANARY_URL="http://$canary_ip:8080" \
FLEET_READINESS_CANARY_DNS="$canary_ip:8053" \
go test ./manager/container -run '^TestReadinessDockerBoundaryAndGatewayReplacement$' -count=1 -v
