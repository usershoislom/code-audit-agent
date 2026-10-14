# syntax=docker/dockerfile:1
# code-audit-agent in one image.
#
# Default image (fast to build): Python agent + scanners that cover every supported language
# statically - opengrep rules for Python / JS / TS / Java / Go / HTML, bandit, gitleaks, osv-scanner.
# Optional extras (see build.conf, or pass --build-arg):
#   WITH_GO=1    gosec + govulncheck + Go toolchain (deeper Go checks, run Go apps in the sandbox)
#   WITH_NODE=1  Node.js + npm (run JS/TS apps in the sandbox with --run-app)
#
#   docker build -t code-audit-agent .
#   docker build -t code-audit-agent --build-arg WITH_GO=1 --build-arg WITH_NODE=1 .
#
# Scanners live in their own venv (/opt/caa-tools): their pinned dependencies must not clash with
# the frameworks we install to run scanned applications (FastAPI, Django, ...).

ARG WITH_GO=0
ARG GO_VERSION=1.24

FROM python:3.12-slim-bookworm AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# ---- optional Go tools: only the stage selected by WITH_GO is built (BuildKit skips the other)
FROM golang:${GO_VERSION}-bookworm AS go-1
ENV GOBIN=/out CGO_ENABLED=0
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8 \
 && go install golang.org/x/vuln/cmd/govulncheck@v1.1.4

FROM base AS go-0
RUN mkdir -p /out /usr/local/go

FROM go-${WITH_GO} AS gotools

# ---- final image
FROM base
ARG TARGETARCH
ARG WITH_NODE=0
ARG OPENGREP_VERSION=v1.11.5
ARG GITLEAKS_VERSION=8.28.0
ARG OSV_VERSION=v2.2.2

# Prebuilt, pinned, checksum-verified scanner binaries (no compilation)
RUN set -eu; arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) og=opengrep_manylinux_x86; og_sha=b9dd6dede671e1ea2e2628ef4c04ff10afd8de2c4ef50af764b29d5f0980eec3; \
             gl=x64;   gl_sha=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb; \
             osv_sha=c799274b682e0437c802d4714a136ad09b39c65547c460049ba5358d28afa576 ;; \
      arm64) og=opengrep_manylinux_aarch64; og_sha=d5def7bf466d25e7b57bbcdfd4243c58f297bf3271625f71125d67759dc98742; \
             gl=arm64; gl_sha=eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356; \
             osv_sha=62004a8b3c84d5041e6565113cc98af17da8d5ef9ebd070d355f1522bcd1d383 ;; \
      *) echo "unsupported architecture $arch"; exit 1 ;; \
    esac; \
    gh=https://github.com; cd /tmp; \
    curl -fsSL -o opengrep "$gh/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/$og"; \
    echo "$og_sha  opengrep" | sha256sum -c -; \
    curl -fsSL -o osv-scanner "$gh/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_$arch"; \
    echo "$osv_sha  osv-scanner" | sha256sum -c -; \
    curl -fsSL -o gl.tgz "$gh/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_$gl.tar.gz"; \
    echo "$gl_sha  gl.tgz" | sha256sum -c -; \
    tar -xzf gl.tgz gitleaks; \
    install -m 755 opengrep osv-scanner gitleaks /usr/local/bin/; \
    rm -f opengrep osv-scanner gitleaks gl.tgz

# Optional runtimes for running scanned apps
RUN if [ "$WITH_NODE" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*; \
    fi
COPY --from=gotools /usr/local/go /usr/local/go
COPY --from=gotools /out/ /usr/local/bin/
ENV PATH=/usr/local/go/bin:$PATH

# Python scanners in an isolated venv
RUN python -m venv /opt/caa-tools \
 && /opt/caa-tools/bin/pip install --no-cache-dir bandit==1.9.4 \
 && ln -s /opt/caa-tools/bin/bandit /usr/local/bin/bandit

# The agent (+ Flask/FastAPI/Django so property checks and the app runner can start Python apps)
WORKDIR /opt/caa
COPY pyproject.toml README.md ./
COPY caa ./caa
COPY configs ./configs
COPY scripts ./scripts
COPY eval ./eval
COPY tests ./tests
RUN pip install --no-cache-dir -e '.[stand,dev]'

# Optional headless browser for `caa live` (Playwright + Chromium). Heavy (~400 MB), so off by
# default; enable with WITH_BROWSER=1. Installed into a world-readable path so the non-root user
# can launch it.
ARG WITH_BROWSER=0
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN if [ "$WITH_BROWSER" = "1" ]; then \
      pip install --no-cache-dir playwright==1.56.0 \
      && playwright install --with-deps chromium \
      && chmod -R a+rX /ms-playwright ; \
    fi

RUN useradd -m -u 10001 caa \
 && mkdir -p /out /work \
 && chown caa:caa /out /work \
 && git config --system --add safe.directory '*'

# what this image was built with (the caa.ps1 / caa.sh wrappers rebuild when build.conf changes)
ARG CAA_BUILD=default
LABEL caa.build=$CAA_BUILD

USER caa
ENV CAA_IN_DOCKER=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
VOLUME ["/out"]
ENTRYPOINT ["caa"]
CMD ["--help"]
