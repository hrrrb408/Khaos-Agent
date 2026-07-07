.PHONY: dev build test test-python test-go test-rust lint migrate clean

PYTHON ?= python3.11

dev:
	./start.sh

build:
	@echo "P0-A has no compiled artifacts yet"

test: test-python test-go test-rust

test-python:
	PYTHONPATH=python $(PYTHON) -m pytest python/tests

test-go:
	@if ! command -v go >/dev/null 2>&1; then echo "go: toolchain not installed, skipping"; elif [ -d go ] && find go -name '*.go' | grep -q .; then mkdir -p .cache/go-build && cd go && GOCACHE=$(CURDIR)/.cache/go-build go test ./...; else echo "go: no tests"; fi

test-rust:
	@if [ -d rust ] && find rust -name 'Cargo.toml' | grep -q .; then cd rust/khaos-core && cargo test; else echo "rust: no P0-A tests"; fi

lint:
	@echo "P0-A lint tooling not configured yet"

migrate:
	PYTHONPATH=python $(PYTHON) -m khaos.db.migrate --db khaos.db

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
