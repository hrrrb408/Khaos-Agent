"""Python-side integration tests for the Rust parallel executor."""

from __future__ import annotations

import json
import time

import pytest

from khaos.rust_bridge import RustToolExecutor, execute_parallel, rust_available

pytestmark = pytest.mark.skipif(not rust_available(), reason="Rust extension not built")


def test_echo_returns_payload():
    executor = RustToolExecutor()
    results = executor.run_parallel([{"id": "1", "kind": "echo", "payload": "hi"}], 500)

    assert len(results) == 1
    assert results[0]["call_id"] == "1"
    assert results[0]["success"] is True
    assert results[0]["output"] == "hi"


def test_sum_aggregates_numbers():
    executor = RustToolExecutor()
    results = executor.run_parallel(
        [{"id": "1", "kind": "sum", "payload": "[1.5, 2.5, 3.0]"}], 500
    )

    assert results[0]["success"] is True
    assert results[0]["output"] == "7"


def test_failure_does_not_abort_siblings():
    executor = RustToolExecutor()
    results = executor.run_parallel(
        [
            {"id": "1", "kind": "fail", "payload": "boom"},
            {"id": "2", "kind": "echo", "payload": "ok"},
        ],
        500,
    )

    assert len(results) == 2
    assert results[0]["success"] is False
    assert "boom" in results[0]["error"]
    assert results[1]["success"] is True


def test_timeout_produces_error():
    executor = RustToolExecutor()
    results = executor.run_parallel([{"id": "1", "kind": "sleep", "payload": "800"}], 100)

    assert results[0]["success"] is False
    assert "timeout" in results[0]["error"]


def test_results_preserve_input_order():
    executor = RustToolExecutor()
    calls = [
        {"id": "third", "kind": "echo", "payload": "c"},
        {"id": "first", "kind": "echo", "payload": "a"},
        {"id": "second", "kind": "echo", "payload": "b"},
    ]
    results = executor.run_parallel(calls, 500)

    assert [r["call_id"] for r in results] == ["third", "first", "second"]


def test_empty_input_returns_empty():
    executor = RustToolExecutor()
    assert executor.run_parallel([], 500) == []


def test_execute_parallel_helper_returns_results():
    results = execute_parallel([{"id": "1", "kind": "echo", "payload": "x"}], 500)

    assert results is not None
    assert results[0]["success"] is True


def test_parallel_runs_concurrently():
    """Two sleeps must finish faster sequentially than concurrently."""
    executor = RustToolExecutor()
    start = time.monotonic()
    executor.run_parallel(
        [
            {"id": "1", "kind": "sleep", "payload": "200"},
            {"id": "2", "kind": "sleep", "payload": "200"},
        ],
        1000,
    )
    elapsed = time.monotonic() - start
    # Concurrent: under 350ms; sequential would be >= 400ms.
    assert elapsed < 0.35, f"took {elapsed:.3f}s"
