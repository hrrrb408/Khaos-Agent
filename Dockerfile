# Stage 1: Python agent
FROM python:3.11-slim AS python-agent

WORKDIR /app

# System dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies and source package.
COPY pyproject.toml ./
COPY python/ python/
RUN pip install --no-cache-dir -e .

# Runtime project files.
COPY prompts/ prompts/
COPY AGENTS.md KHAOS.md config.yaml ./

# Data directories.
RUN mkdir -p /app/data /app/skills /run/khaos

CMD ["python", "-m", "khaos.cli", "start", "--socket", "/run/khaos/agent.sock", "--db", "/app/data/khaos.db"]

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
