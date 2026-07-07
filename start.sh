#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
GO_BIN="${GO:-go}"
NPM_BIN="${NPM:-npm}"

cd "$ROOT"

PYTHONPATH=python "$PYTHON_BIN" -m khaos.grpc_server --host 127.0.0.1 --port 50051 --db khaos.db --config config.yaml &
PY_PID=$!

sleep 1

mkdir -p "$ROOT/.cache/go-build"
cd "$ROOT/go"
GOCACHE="$ROOT/.cache/go-build" "$GO_BIN" run ./cmd/gateway --addr 127.0.0.1:8080 --python-agent 127.0.0.1:50051 &
GO_PID=$!

cd "$ROOT/web"
"$NPM_BIN" run dev &
WEB_PID=$!

trap 'kill "$PY_PID" "$GO_PID" "$WEB_PID" 2>/dev/null || true' EXIT
wait
