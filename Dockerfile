# Stage 0: native security TCB
FROM rust:1.82-bookworm AS rust-tcb-builder

WORKDIR /build
COPY rust/khaos-core/ rust/khaos-core/
RUN cargo build --release --no-default-features \
    --manifest-path rust/khaos-core/Cargo.toml \
    --bin khaos-sandbox-launcher \
    --bin khaos-browser-kernel-helper

# Stage 1: Python agent
FROM python:3.11-slim AS python-agent

WORKDIR /app

# System dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    bubblewrap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies and source package.
COPY pyproject.toml ./
COPY python/ python/
RUN pip install --no-cache-dir -e .

# Runtime project files.
COPY prompts/ prompts/
COPY AGENTS.md KHAOS.md config.yaml ./
COPY --from=rust-tcb-builder /build/rust/khaos-core/target/release/khaos-sandbox-launcher /usr/local/bin/khaos-sandbox-launcher

# Data directories.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin khaos \
    && chown root:root /usr/local/bin/khaos-sandbox-launcher \
    && chmod 0755 /usr/local/bin/khaos-sandbox-launcher \
    && setcap cap_sys_admin=ep /usr/local/bin/khaos-sandbox-launcher \
    && mkdir -p /app/data /app/skills /run/khaos /run/khaos-helper \
    && chown -R khaos:khaos /app/data /app/skills /run/khaos \
    && chown root:root /run/khaos-helper \
    && chmod 0700 /run/khaos \
    && chmod 0755 /run/khaos-helper

ENV KHAOS_SANDBOX_LAUNCHER=/usr/local/bin/khaos-sandbox-launcher

USER 10001:10001

CMD ["python", "-m", "khaos.cli", "start", "--socket", "/run/khaos/agent.sock", "--db", "/app/data/khaos.db"]

# Stage 1b: root-only browser kernel helper sidecar. It owns all netns, veth,
# nftables and browser cgroup operations; the Python image contains no ip/nft.
FROM debian:bookworm-slim AS kernel-helper

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust-tcb-builder /build/rust/khaos-core/target/release/khaos-browser-kernel-helper /usr/local/sbin/khaos-browser-kernel-helper
COPY packaging/docker/kernel-helper-entrypoint.sh /usr/local/sbin/kernel-helper-entrypoint
RUN chown root:root /usr/local/sbin/khaos-browser-kernel-helper /usr/local/sbin/kernel-helper-entrypoint \
    && chmod 0755 /usr/local/sbin/khaos-browser-kernel-helper /usr/local/sbin/kernel-helper-entrypoint

ENTRYPOINT ["/usr/local/sbin/kernel-helper-entrypoint"]

# Stage 2: Go gateway
FROM golang:1.22-alpine AS go-builder

WORKDIR /build
COPY go/ go/
RUN cd go && CGO_ENABLED=0 go build -o /gateway ./cmd/gateway/

FROM alpine:3.19 AS gateway

RUN apk add --no-cache ca-certificates
COPY --from=go-builder /gateway /usr/local/bin/khaos-gateway

EXPOSE 8080

CMD ["khaos-gateway", "--addr", "0.0.0.0:8080"]
