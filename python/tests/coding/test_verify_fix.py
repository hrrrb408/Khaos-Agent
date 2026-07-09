"""Tests for the verify-fix loop strategy layer."""

from __future__ import annotations

import json

from khaos.coding.verify_fix import DEFAULT_MAX_FIX_ATTEMPTS, VerifyFixLoop


def _failed_test_result(
    failed: int = 1,
    errors: int = 0,
    passed: int = 0,
    failed_cases: list[dict] | None = None,
) -> dict:
    """Build a ToolResult-shaped dict mimicking a failing test_run."""
    if failed_cases is None and (failed or errors):
        failed_cases = [
            {
                "name": "test_add_file",
                "file": "tests/test_file_tools.py",
                "line": 45,
                "error": "AssertionError: expected 1, got 0",
            }
        ]
    output = json.dumps(
        {
            "success": False,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "exit_code": 1,
            "failed_cases": failed_cases or [],
            "summary": f"{failed} failed",
        },
        ensure_ascii=False,
    )
    return {"name": "test_run", "success": False, "output": output, "error": ""}


def _passed_test_result() -> dict:
    """Build a ToolResult-shaped dict for a passing test_run."""
    output = json.dumps(
        {
            "success": True,
            "passed": 10,
            "failed": 0,
            "errors": 0,
            "exit_code": 0,
            "failed_cases": [],
            "summary": "10 passed",
        },
        ensure_ascii=False,
    )
    return {"name": "test_run", "success": True, "output": output, "error": ""}


def test_should_enter_loop_on_test_failure() -> None:
    loop = VerifyFixLoop()
    assert loop.should_enter_loop(_failed_test_result()) is True


def test_should_not_enter_on_success() -> None:
    loop = VerifyFixLoop()
    assert loop.should_enter_loop(_passed_test_result()) is False


def test_should_not_enter_on_non_test_tool() -> None:
    loop = VerifyFixLoop()
    result = {"name": "read_file", "success": True, "output": "...", "error": ""}
    assert loop.should_enter_loop(result) is False


def test_should_not_enter_on_errors_only_when_failed_zero() -> None:
    # errors > 0 still counts as a failure worth fixing.
    loop = VerifyFixLoop()
    result = _failed_test_result(failed=0, errors=2)
    assert loop.should_enter_loop(result) is True


def test_loop_exhausted_after_max_attempts() -> None:
    loop = VerifyFixLoop(max_fix_attempts=2)
    failed = _failed_test_result()
    # First attempt.
    assert loop.should_enter_loop(failed) is True
    loop.build_failure_context(failed)
    assert loop.is_loop_exhausted() is False
    # Second attempt.
    assert loop.should_enter_loop(failed) is True
    loop.build_failure_context(failed)
    assert loop.is_loop_exhausted() is True
    # Budget exhausted: no further entry.
    assert loop.should_enter_loop(failed) is False


def test_build_failure_context_format() -> None:
    loop = VerifyFixLoop()
    ctx = loop.build_failure_context(_failed_test_result())
    # Header shows the attempt index.
    assert "第 1/3 次修复尝试" in ctx
    # Failed case details are present.
    assert "test_add_file" in ctx
    assert "tests/test_file_tools.py" in ctx
    assert "45" in ctx
    assert "AssertionError" in ctx
    # Guidance steps are present.
    assert "读取失败文件" in ctx
    assert "重新运行测试" in ctx


def test_final_report_content() -> None:
    loop = VerifyFixLoop(max_fix_attempts=2)
    failed = _failed_test_result()
    loop.build_failure_context(failed)
    loop.build_failure_context(failed)
    report = loop.get_final_report()
    assert "共 2 次尝试" in report
    assert "仍然失败" in report
    assert "test_add_file" in report
    assert "请由用户决策" in report


def test_final_report_when_all_pass() -> None:
    loop = VerifyFixLoop(max_fix_attempts=3)
    loop.build_failure_context(_failed_test_result())
    # Second attempt passes.
    loop.build_failure_context(_failed_test_result(failed=0, passed=10, failed_cases=[]))
    report = loop.get_final_report()
    # The last attempt had no failures, so the report declares success.
    assert "所有测试" in report or "通过" in report


def test_max_fix_attempts_default() -> None:
    loop = VerifyFixLoop()
    assert loop.max_fix_attempts == DEFAULT_MAX_FIX_ATTEMPTS == 3


def test_with_zero_max_attempts() -> None:
    loop = VerifyFixLoop(max_fix_attempts=0)
    assert loop.should_enter_loop(_failed_test_result()) is False
    assert loop.is_loop_exhausted() is True
    assert "no attempts" in loop.get_final_report()


def test_should_not_enter_on_unparseable_output() -> None:
    loop = VerifyFixLoop()
    # output is not JSON and has no test shape.
    result = {"name": "test_run", "success": False, "output": "not json", "error": ""}
    assert loop.should_enter_loop(result) is False


def test_should_not_enter_when_output_is_none() -> None:
    loop = VerifyFixLoop()
    result = {"name": "test_run", "success": False, "output": None, "error": ""}
    assert loop.should_enter_loop(result) is False


def test_build_failure_context_increments_attempt_count() -> None:
    loop = VerifyFixLoop(max_fix_attempts=3)
    assert loop.attempt_count == 0
    loop.build_failure_context(_failed_test_result())
    assert loop.attempt_count == 1
    loop.build_failure_context(_failed_test_result())
    assert loop.attempt_count == 2


def test_negative_max_attempts_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        VerifyFixLoop(max_fix_attempts=-1)
