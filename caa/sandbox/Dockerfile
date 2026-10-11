# Image for L4 property checks: only what the harness and the seeded stand need.
# Build: docker build -t caa-sandbox:latest -f caa/sandbox/Dockerfile .
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.1.3 requests==2.32.3 markupsafe==3.0.2 \
 && useradd -u 65534 -o -M -s /usr/sbin/nologin sandbox || true
USER 65534:65534
WORKDIR /src
