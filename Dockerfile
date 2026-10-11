# syntax=docker/dockerfile:1
# code-audit-agent: everything in one image (agent, scanners, Go and Node to run the scanned apps).
#
#   docker build -t code-audit-agent .
#   docker run --rm -v "$PWD/caa-reports:/out" code-audit-agent scan https://github.com/owner/repo
#
# Scanners live in their own venv (/opt/caa-tools): their pinned dependencies must not clash with
# the frameworks we install to run scanned applications (FastAPI, Django, ...).

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS gotools
ENV GOBIN=/out CGO_ENABLED=0
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8 \
 && go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 \
 && go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.2.2 \
 && go install github.com/zricethezav/gitleaks/v8@v8.28.0

FROM python:3.12-slim-bookworm
ARG TARGETARCH
ARG OPENGREP_VERSION=v1.11.5
ARG OPENGREP_SHA256_AMD64=b9dd6dede671e1ea2e2628ef4c04ff10afd8de2c4ef50af764b29d5f0980eec3

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Go toolchain (gosec/govulncheck type-check Go code; the app runner does `go run`)
COPY --from=gotools /usr/local/go /usr/local/go
COPY --from=gotools /out/ /usr/local/bin/
ENV PATH=/usr/local/go/bin:$PATH

# Opengrep: preferred engine (data-flow traces in SARIF). Pinned + checksum-verified on amd64;
# on other architectures the agent falls back to Semgrep CE (no traces).
RUN if [ "$TARGETARCH" = "amd64" ] || [ -z "$TARGETARCH" ]; then \
      curl -fsSL -o /usr/local/bin/opengrep \
        "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
      && echo "${OPENGREP_SHA256_AMD64}  /usr/local/bin/opengrep" | sha256sum -c - \
      && chmod 755 /usr/local/bin/opengrep; \
    fi

# Python scanners in an isolated venv
RUN python -m venv /opt/caa-tools \
 && /opt/caa-tools/bin/pip install --no-cache-dir semgrep==1.179.0 bandit==1.9.4 \
 && ln -s /opt/caa-tools/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/caa-tools/bin/bandit /usr/local/bin/bandit

# The agent (+ stand frameworks so property checks / the app runner can import Flask, FastAPI, Django)
WORKDIR /opt/caa
COPY pyproject.toml README.md ./
COPY caa ./caa
COPY configs ./configs
COPY scripts ./scripts
COPY eval ./eval
COPY tests ./tests
RUN pip install --no-cache-dir -e '.[stand,dev]'

RUN useradd -m -u 10001 caa \
 && mkdir -p /out /work \
 && chown caa:caa /out /work \
 && git config --system --add safe.directory '*'

USER caa
ENV CAA_IN_DOCKER=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
VOLUME ["/out"]
ENTRYPOINT ["caa"]
CMD ["--help"]
