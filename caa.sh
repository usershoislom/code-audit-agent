#!/usr/bin/env bash
# code-audit-agent in Docker (Linux / macOS). Same behaviour as caa.ps1.
#   ./caa.sh scan https://github.com/owner/repo
#   ./caa.sh scan ./my-app --trust-target --run-app
#   ./caa.sh rebuild
set -euo pipefail
IMAGE=code-audit-agent
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPORTS="$(pwd)/caa-reports"

if [[ "${1:-}" == "rebuild" ]]; then exec docker build -t "$IMAGE" "$ROOT"; fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[caa] building the Docker image (first run, takes a few minutes)..."
  docker build -t "$IMAGE" "$ROOT"
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
