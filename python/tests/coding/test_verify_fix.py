"""Tests for the verify-fix loop strategy layer."""

from __future__ import annotations

import json

import pytest
from khaos.coding.verify_fix import (
    DEFAULT_MAX_FIX_ATTEMPTS,
    VerificationState,
    VerifyFixLoop,
)


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
    # The predicate is side-effect free; observation is explicit.
    assert loop.verification_history == ()
    assert loop.attempt_count == 0


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
    # The first failure authorizes repair #1.
    first = loop.observe_test_result(failed)
    assert first is not None
    assert first.state is VerificationState.FAILING
    assert loop.should_enter_loop(failed, observation=first) is True
    loop.build_failure_context(failed, observation=first)
    assert loop.is_loop_exhausted() is False
    # The second failure authorizes repair #2. Merely reaching the repair
    # count does not make the latest failure terminal.
    second = loop.observe_test_result(failed)
    assert second is not None
    assert second.state is VerificationState.FAILING
    assert loop.should_enter_loop(failed, observation=second) is True
    loop.build_failure_context(failed, observation=second)
    assert loop.attempt_count == 2
    assert loop.is_loop_exhausted() is False
    # The next failure is the first observation with no repair remaining.
    terminal = loop.observe_test_result(failed)
    assert terminal is not None
    assert terminal.state is VerificationState.EXHAUSTED_FAILURE
    assert loop.is_loop_exhausted() is True
    assert loop.should_enter_loop(failed, observation=terminal) is False


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
    for _ in range(2):
        observation = loop.observe_test_result(failed)
        assert observation is not None
        loop.build_failure_context(failed, observation=observation)
    loop.observe_test_result(failed)
    report = loop.get_final_report()
    assert "共 2 次修复尝试" in report
    assert "exhausted_failure" in report
    assert "仍然失败" in report
    assert "test_add_file" in report
    assert "请由用户决策" in report


def test_final_report_when_all_pass() -> None:
    loop = VerifyFixLoop(max_fix_attempts=3)
    failed = _failed_test_result()
    first = loop.observe_test_result(failed)
    assert first is not None
    loop.build_failure_context(failed, observation=first)
    # The second observation passes; it is authoritative even if historical
    # repair accounting is later exhausted.
    passed = loop.observe_test_result(_passed_test_result())
    assert passed is not None
    assert passed.state is VerificationState.PASSED
    report = loop.get_final_report()
    assert "最新验证观察已通过" in report
    assert "最新验证仍然失败" not in report


def test_max_fix_attempts_default() -> None:
    loop = VerifyFixLoop()
    assert loop.max_fix_attempts == DEFAULT_MAX_FIX_ATTEMPTS == 3


def test_with_zero_max_attempts() -> None:
    loop = VerifyFixLoop(max_fix_attempts=0)
    failed = _failed_test_result()
    observation = loop.observe_test_result(failed)
    assert observation is not None
    assert observation.state is VerificationState.EXHAUSTED_FAILURE
    assert loop.should_enter_loop(failed, observation=observation) is False
    assert loop.is_loop_exhausted() is True
    assert "达到最大自动修复次数" in loop.get_final_report()

    passing_loop = VerifyFixLoop(max_fix_attempts=0)
    passing = passing_loop.observe_test_result(_passed_test_result())
    assert passing is not None
    assert passing.state is VerificationState.PASSED
    assert passing_loop.is_loop_exhausted() is False


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
    first = loop.observe_test_result(_failed_test_result())
    assert first is not None
    loop.build_failure_context(_failed_test_result(), observation=first)
    assert loop.attempt_count == 1
    second = loop.observe_test_result(_failed_test_result())
    assert second is not None
    loop.build_failure_context(_failed_test_result(), observation=second)
    assert loop.attempt_count == 2
    assert len(loop.verification_history) == 2
    assert len(loop.repair_history) == 2


def test_negative_max_attempts_raises() -> None:
    with pytest.raises(ValueError):
        VerifyFixLoop(max_fix_attempts=-1)


def test_no_progress_signal_after_repeated_failures() -> None:
    loop = VerifyFixLoop(max_fix_attempts=3)
    failed = _failed_test_result()
    loop.observe_test_result(failed)
    loop.observe_test_result(failed)
    signal = loop.no_progress_signal()
    assert signal.detected is True
    assert signal.observation_indices == (1, 2)
    assert signal.reason == "identical_failure_signature"
    assert loop.should_stop_no_progress() is True


@pytest.mark.parametrize(
    ("max_attempts", "sequence", "expected_states", "expected_repairs"),
    [
        (
            3,
            ("fail", "pass"),
            (VerificationState.FAILING, VerificationState.PASSED),
            1,
        ),
        (
            3,
            ("fail", "fail", "pass"),
            (
                VerificationState.FAILING,
                VerificationState.FAILING,
                VerificationState.PASSED,
            ),
            2,
        ),
        (
            3,
            ("fail", "fail", "fail", "pass"),
            (
                VerificationState.FAILING,
                VerificationState.FAILING,
                VerificationState.FAILING,
                VerificationState.PASSED,
            ),
            3,
        ),
        (
            3,
            ("fail", "fail", "fail", "fail"),
            (
                VerificationState.FAILING,
                VerificationState.FAILING,
                VerificationState.FAILING,
                VerificationState.EXHAUSTED_FAILURE,
            ),
            3,
        ),
        (0, ("fail",), (VerificationState.EXHAUSTED_FAILURE,), 0),
        (0, ("pass",), (VerificationState.PASSED,), 0),
    ],
)
def test_observation_and_repair_state_matrix(
    max_attempts: int,
    sequence: tuple[str, ...],
    expected_states: tuple[VerificationState, ...],
    expected_repairs: int,
) -> None:
    """Verification observations and repair issuance have separate counts."""
    loop = VerifyFixLoop(max_fix_attempts=max_attempts)
    states: list[VerificationState] = []
    failed = _failed_test_result()
    for result_kind in sequence:
        result = failed if result_kind == "fail" else _passed_test_result()
        observation = loop.observe_test_result(result)
        assert observation is not None
        states.append(observation.state)
        if result_kind == "fail" and loop.should_enter_loop(
            result, observation=observation
        ):
            assert loop.build_failure_context(result, observation=observation)

    assert tuple(states) == expected_states
    assert loop.attempt_count == expected_repairs
    assert len(loop.verification_history) == len(sequence)
    assert len(loop.repair_history) == expected_repairs
