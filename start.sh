#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default to python3.11 to match the Makefile/test toolchain. Override with
# PYTHON=/path/to/python if you need a different interpreter.
PYTHON_BIN="${PYTHON:-python3.11}"
GO_BIN="${GO:-go}"
NPM_BIN="${NPM:-npm}"

cd "$ROOT"
mkdir -p "$ROOT/.cache"

# start.sh does not clear or sandbox the environment. Variables exported in the
# launching shell (for example NVIDIA_API_KEY) are inherited by both the Python
# AgentService and the Go gateway processes below.

PY_PID=""
GO_PID=""
WEB_PID=""

cleanup() {
    # Kill the whole process group of each child (`kill -- -PGID`). With job
    # control enabled below, every backgrounded child becomes the leader of its
    # own process group, so this also reaps grandchildren that a bare
    # `kill $PID` would orphan — the `go run` compiled binary and the Next.js
    # dev server would otherwise keep holding ports 8080/3000 after exit.
    for pid in "$PY_PID" "$GO_PID" "$WEB_PID"; do
        if [ -n "$pid" ]; then
            kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT INT TERM

# Job control makes each backgrounded job its own process group leader, so the
# group's PGID equals the child PID and `kill -- -$PID` reaches the whole tree.
set -m

PYTHONPATH=python "$PYTHON_BIN" -m khaos.grpc_server \
    --host 127.0.0.1 --port 50051 --db khaos.db --config config.yaml \
    > "$ROOT/.cache/python.log" 2>&1 &
PY_PID=$!

sleep 1

mkdir -p "$ROOT/.cache/go-build"
cd "$ROOT/go"
GOCACHE="$ROOT/.cache/go-build" "$GO_BIN" run ./cmd/gateway \
    --addr 127.0.0.1:8080 --python-agent 127.0.0.1:50051 \
    > "$ROOT/.cache/go.log" 2>&1 &
GO_PID=$!

cd "$ROOT/web"
"$NPM_BIN" run dev > "$ROOT/.cache/web.log" 2>&1 &
WEB_PID=$!

wait
