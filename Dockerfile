# Stage 0: native security TCB
FROM rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS rust-tcb-builder

WORKDIR /build
COPY rust/khaos-core/ rust/khaos-core/
RUN cargo build --locked --release --no-default-features \
    --manifest-path rust/khaos-core/Cargo.toml \
    --bin khaos-sandbox-launcher \
    --bin khaos-exec-launcher \
    --bin khaos-browser-kernel-helper

# Stage 1: Python agent
FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS python-agent

WORKDIR /app

# System dependencies.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
    gcc \
    bubblewrap \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies come only from the repository's frozen resolution.  The
# bootstrap wheel is hash-locked, and ``uv sync --frozen`` refuses to resolve
# anything that is not already present in uv.lock.  The source tree is kept on
# PYTHONPATH so this image does not perform a second, floating build-isolation
# install of the project itself.
COPY pyproject.toml uv.lock ./
COPY python/bootstrap-requirements.txt /tmp/khaos-bootstrap-requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes \
    -r /tmp/khaos-bootstrap-requirements.txt \
    && UV_PROJECT_ENVIRONMENT=/usr/local uv sync --frozen --no-dev --no-install-project \
    && python -m pip uninstall -y uv
COPY python/ python/

# Runtime project files.
COPY prompts/ prompts/
COPY AGENTS.md KHAOS.md config.yaml ./
COPY --from=rust-tcb-builder /build/rust/khaos-core/target/release/khaos-sandbox-launcher /usr/local/bin/khaos-sandbox-launcher
COPY --from=rust-tcb-builder /build/rust/khaos-core/target/release/khaos-exec-launcher /usr/local/bin/khaos-exec-launcher
COPY packaging/docker/agent-secret-init.py /usr/local/sbin/khaos-agent-secret-init.py
COPY packaging/docker/authorityd-key-init.py /usr/local/sbin/khaos-authorityd-key-init.py

# Data directories.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin khaos \
    && useradd --system --uid 10003 --home-dir /nonexistent --shell /usr/sbin/nologin khaos-authority \
    && useradd --system --uid 10004 --home-dir /nonexistent --shell /usr/sbin/nologin khaos-job \
    && chown root:root /usr/local/bin/khaos-sandbox-launcher \
    && chmod 0755 /usr/local/bin/khaos-sandbox-launcher \
    && setcap cap_sys_admin=ep /usr/local/bin/khaos-sandbox-launcher \
    && chown root:root /usr/local/bin/khaos-exec-launcher \
    && chmod 0755 /usr/local/bin/khaos-exec-launcher \
    && chown root:root /usr/local/sbin/khaos-agent-secret-init.py \
    && chmod 0755 /usr/local/sbin/khaos-agent-secret-init.py \
    && chown root:root /usr/local/sbin/khaos-authorityd-key-init.py \
    && chmod 0755 /usr/local/sbin/khaos-authorityd-key-init.py \
    && mkdir -p /app/data /app/skills /run/khaos /run/khaos-helper /var/lib/khaos \
        /run/khaos-authorityd /var/lib/khaos-authorityd \
    && chown -R khaos:khaos /app/data /app/skills /var/lib/khaos \
    && chown -R khaos-authority:khaos-authority /run/khaos-authorityd /var/lib/khaos-authorityd \
    && chown khaos:root /run/khaos \
    && chmod 02750 /run/khaos \
    && chown root:root /run/khaos-helper \
    && chmod 0755 /run/khaos-helper

ENV KHAOS_DEV_MODE=0 \
    KHAOS_EXEC_LAUNCHER=/usr/local/bin/khaos-exec-launcher \
    KHAOS_SANDBOX_LAUNCHER=/usr/local/bin/khaos-sandbox-launcher \
    HOME=/var/lib/khaos \
    PYTHONPATH=/app/python

USER 10001:10001

CMD ["python", "-m", "khaos.cli", "start", "--socket", "/run/khaos/agent.sock", "--gateway-uid", "10002", "--gateway-gid", "0"]

# Stage 1b: root-only browser kernel helper sidecar. It owns all netns, veth,
# nftables and browser cgroup operations; the Python image contains no ip/nft.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS kernel-helper

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust-tcb-builder /build/rust/khaos-core/target/release/khaos-browser-kernel-helper /usr/local/sbin/khaos-browser-kernel-helper
COPY packaging/docker/kernel-helper-entrypoint.sh /usr/local/sbin/kernel-helper-entrypoint
RUN chown root:root /usr/local/sbin/khaos-browser-kernel-helper /usr/local/sbin/kernel-helper-entrypoint \
    && chmod 0755 /usr/local/sbin/khaos-browser-kernel-helper /usr/local/sbin/kernel-helper-entrypoint \
    && sha256sum /usr/local/sbin/khaos-browser-kernel-helper \
        > /usr/local/sbin/khaos-browser-kernel-helper.sha256 \
    && chown root:root /usr/local/sbin/khaos-browser-kernel-helper.sha256 \
    && chmod 0444 /usr/local/sbin/khaos-browser-kernel-helper.sha256

ENTRYPOINT ["/usr/local/sbin/kernel-helper-entrypoint"]

# Stage 2: Go gateway
FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS go-builder

WORKDIR /build
COPY go/ go/
RUN cd go && go mod verify \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -o /gateway ./cmd/gateway/

FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1 AS gateway

RUN apk add --no-cache ca-certificates
RUN addgroup -S -g 10002 khaos-gateway \
    && adduser -S -D -u 10002 -G khaos-gateway khaos-gateway
COPY --from=go-builder /gateway /usr/local/bin/khaos-gateway

USER 10002:10002

EXPOSE 8080

CMD ["khaos-gateway", "--addr", "0.0.0.0:8080"]
