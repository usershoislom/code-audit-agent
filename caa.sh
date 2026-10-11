#!/usr/bin/env bash
# code-audit-agent in Docker (Linux / macOS). Same behaviour as caa.ps1.
#   ./caa.sh scan https://github.com/owner/repo
#   ./caa.sh scan ./my-app --trust-target --run-app
#   ./caa.sh rebuild
# Extra languages for the image (Go tools, Node.js): uncomment lines in build.conf.
set -euo pipefail
IMAGE=code-audit-agent
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPORTS="$(pwd)/caa-reports"

# build options: uncommented WITH_*=... lines of build.conf become --build-arg
opts=()
[[ -f "$ROOT/build.conf" ]] && while IFS= read -r line; do
  [[ "$line" =~ ^[[:space:]]*(WITH_[A-Z_]+)=([^[:space:]]+) ]] && opts+=("${BASH_REMATCH[1]}=${BASH_REMATCH[2]}")
done < "$ROOT/build.conf"
want=$(IFS=,; echo "${opts[*]:-default}")
build() {
  echo "[caa] building the Docker image ($want) - the first build takes a few minutes..."
  local args=(build -t "$IMAGE" --build-arg "CAA_BUILD=$want")
  for o in ${opts[@]+"${opts[@]}"}; do args+=(--build-arg "$o"); done
  docker "${args[@]}" "$ROOT"
}

if [[ "${1:-}" == "rebuild" ]]; then build; exit 0; fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  build
else
  have=$(docker image inspect -f '{{index .Config.Labels "caa.build"}}' "$IMAGE")
  [[ "$have" != "$want" ]] && { echo "[caa] build.conf changed ($have -> $want)"; build; }
fi
mkdir -p "$REPORTS"

docker_args=(run --rm -t -v "$REPORTS:/out")
[[ -f "$ROOT/.env" ]] && docker_args+=(--env-file "$ROOT/.env")
[[ "$(uname -s)" == "Linux" ]] && docker_args+=(--add-host host.docker.internal:host-gateway)

caa_args=()
mounted=0
for a in "$@"; do
  if [[ $mounted -eq 0 && ! "$a" =~ ^(https?://|-) && -d "$a" ]]; then
    docker_args+=(-v "$(cd "$a" && pwd):/target:ro")
    caa_args+=(/target)
    mounted=1
  else
    caa_args+=("$a")
  fi
done
for a in "${caa_args[@]}"; do
  [[ "$a" == "--trust-target" ]] && docker_args+=(--security-opt seccomp=unconfined --security-opt apparmor=unconfined)
done
exec docker "${docker_args[@]}" "$IMAGE" "${caa_args[@]}"
