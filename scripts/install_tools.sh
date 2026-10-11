#!/usr/bin/env bash
# Install the external analyzers with pinned versions into an isolated prefix.
#
# Why isolated: the scanners have their own Python dependency pins (Semgrep pins opentelemetry,
# for example) that conflict with the applications we analyse and run. Keeping them in a
# separate venv / bin directory means scanning a FastAPI app never breaks the scanner.
#
# Usage:  scripts/install_tools.sh [PREFIX]        (default PREFIX=$HOME/.local/caa-tools)
# Then:   export PATH="$PREFIX/bin:$PATH"
set -euo pipefail

PREFIX="${1:-$HOME/.local/caa-tools}"
BIN="$PREFIX/bin"
mkdir -p "$BIN"

OPENGREP_VERSION="v1.11.5"
OPENGREP_SHA256="b9dd6dede671e1ea2e2628ef4c04ff10afd8de2c4ef50af764b29d5f0980eec3"   # opengrep_manylinux_x86
SEMGREP_VERSION="1.179.0"
BANDIT_VERSION="1.9.4"
GOSEC_VERSION="v2.22.8"
GOVULNCHECK_VERSION="v1.1.4"
OSV_SCANNER_VERSION="v2.2.2"
GITLEAKS_VERSION="v8.28.0"

say() { printf '\n[caa-tools] %s\n' "$*"; }

say "Python analyzers (isolated venv: $PREFIX/venv)"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q "semgrep==$SEMGREP_VERSION" "bandit==$BANDIT_VERSION"
ln -sf "$PREFIX/venv/bin/semgrep" "$BIN/semgrep"
ln -sf "$PREFIX/venv/bin/bandit" "$BIN/bandit"

if [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]]; then
  say "Opengrep $OPENGREP_VERSION (preferred engine: emits data-flow traces in SARIF)"
  tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "https://github.com/opengrep/opengrep/releases/download/$OPENGREP_VERSION/opengrep_manylinux_x86"
  echo "$OPENGREP_SHA256  $tmp" | sha256sum -c - >/dev/null || { echo "opengrep checksum mismatch" >&2; exit 1; }
  install -m 755 "$tmp" "$BIN/opengrep"
  rm -f "$tmp"
else
  say "Opengrep: no pinned binary for $(uname -s)-$(uname -m); Semgrep is used (without data-flow traces)"
fi

if command -v go >/dev/null; then
  say "Go analyzers (gosec, govulncheck, osv-scanner, gitleaks)"
  export GOBIN="$BIN"
  go install "github.com/securego/gosec/v2/cmd/gosec@$GOSEC_VERSION"
  go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
  go install "github.com/google/osv-scanner/v2/cmd/osv-scanner@$OSV_SCANNER_VERSION"
  go install "github.com/zricethezav/gitleaks/v8@$GITLEAKS_VERSION"
else
  say "Go toolchain not found: gosec/govulncheck/osv-scanner/gitleaks skipped (built-in fallbacks are used)"
fi

say "Done. Add to PATH:  export PATH=\"$BIN:\$PATH\""
"$BIN/semgrep" --version >/dev/null && echo "  semgrep ok"
[[ -x "$BIN/opengrep" ]] && "$BIN/opengrep" --version && echo "  opengrep ok" || true
