# kscan scanner image: kscan + semgrep, gitleaks, trivy, osv-scanner, bandit.
#
# Every tool version and checksum is pinned here (Go tools) or in
# docker/requirements.txt (Python tools, hash-locked). To update a tool,
# change its ARGs below, then `make image image-test` and tag a new release.
#
# gosec and govulncheck are not included: both need the full Go toolchain at
# scan time, which would add ~250 MB. Semgrep's p/golang rules plus trivy and
# osv-scanner still cover Go code and dependencies inside the image.

ARG GO_IMAGE=golang:1.25.14-trixie
ARG PYTHON_IMAGE=python:3.12.16-slim-trixie

# --- 1. kscan itself -------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY rules ./rules
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kscan ./cmd/kscan

# --- 2. Go-based scanners, downloaded and checksum-verified ----------------
FROM --platform=$BUILDPLATFORM debian:trixie-slim AS tools
ARG TARGETARCH

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080

ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256_AMD64=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ARG TRIVY_SHA256_ARM64=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f

ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256_AMD64=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG OSV_SCANNER_SHA256_ARM64=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN case "$TARGETARCH" in \
      amd64) gl_arch=x64;   tv_arch=64bit; gl_sum=$GITLEAKS_SHA256_AMD64; tv_sum=$TRIVY_SHA256_AMD64; osv_sum=$OSV_SCANNER_SHA256_AMD64 ;; \
      arm64) gl_arch=arm64; tv_arch=ARM64; gl_sum=$GITLEAKS_SHA256_ARM64; tv_sum=$TRIVY_SHA256_ARM64; osv_sum=$OSV_SCANNER_SHA256_ARM64 ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz"; \
    curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz"; \
    curl -fsSLo osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}"; \
    printf '%s  gitleaks.tgz\n%s  trivy.tgz\n%s  osv-scanner\n' "$gl_sum" "$tv_sum" "$osv_sum" | sha256sum -c -; \
    mkdir -p /out; \
    tar -xzf gitleaks.tgz -C /out gitleaks; \
    tar -xzf trivy.tgz -C /out trivy; \
    install -m 0755 osv-scanner /out/osv-scanner

# --- 3. Runtime: Python for semgrep + bandit -------------------------------
FROM ${PYTHON_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="kscan" \
      org.opencontainers.image.description="Security scan orchestrator: semgrep, gitleaks, trivy, osv-scanner, bandit" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # Mounted repos are owned by another uid; let git (gitleaks, --changed-since) read them.
    && git config --system --add safe.directory '*'

COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && find /usr/local/lib/python3.12 -name '__pycache__' -prune -exec rm -rf {} +

COPY --from=tools /out/ /usr/local/bin/
COPY --from=build /out/kscan /usr/local/bin/kscan

# CI usually runs the container as the runner's uid (docker run --user), which
# has no passwd entry; give every uid a writable HOME and cache dir.
RUN useradd --uid 10001 --create-home --home-dir /home/scanner scanner \
    && mkdir -p /cache/trivy \
    && chmod 1777 /home/scanner /cache /cache/trivy
ENV HOME=/home/scanner \
    TRIVY_CACHE_DIR=/cache/trivy \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    PYTHONDONTWRITEBYTECODE=1
USER scanner
WORKDIR /src
ENTRYPOINT ["kscan"]
CMD ["scan", "."]
