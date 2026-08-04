.PHONY: dev build test test-python test-go test-rust lint migrate clean

PYTHON ?= python3.11

dev:
	./start.sh

build: build-rust
	@echo "build complete"

build-rust:
	@if [ -d rust/khaos-core ] && command -v cargo >/dev/null 2>&1; then \
	  cd rust/khaos-core && PYO3_PYTHON=$$(command -v python3.11 || command -v python3) cargo build --locked --release --bin khaos-exec-launcher; \
	else echo "rust: toolchain or crate not present, skipping"; fi

test: test-python test-go test-rust

test-python:
	@if command -v cargo >/dev/null 2>&1 && [ -d rust/khaos-core ]; then \
	  cargo build --locked --release --no-default-features --bin khaos-exec-launcher --manifest-path rust/khaos-core/Cargo.toml; \
	else echo "rust: native execution launcher unavailable; Python tests may fail closed"; fi
	PYTHONPATH=python $(PYTHON) -m pytest python/tests

test-go:
	@if ! command -v go >/dev/null 2>&1; then echo "go: toolchain not installed, skipping"; elif [ -d go ] && find go -name '*.go' | grep -q .; then mkdir -p .cache/go-build && cd go && GOCACHE=$(CURDIR)/.cache/go-build go test ./...; else echo "go: no tests"; fi

test-rust:
	@if ! command -v cargo >/dev/null 2>&1; then echo "rust: toolchain not installed, skipping"; \
	elif [ -d rust/khaos-core ]; then cd rust/khaos-core && cargo test --no-default-features; \
	else echo "rust: no crate"; fi

lint:
	# P2-6: Pyright type check (security-critical modules are strict; see
	# docs/type-check-rollout.md).  Requires the `lsp` extra (pyright).
	PYTHONPATH=python uv run pyright || echo "(pyright not installed; run: uv sync --extra lsp)"

migrate:
	PYTHONPATH=python $(PYTHON) -m khaos.db.migrate --db khaos.db

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
