"""Tests for the test_run feedback-loop tool and its output parsers."""

import json
import subprocess

import pytest

from khaos.tools import test_tools
from khaos.tools.test_tools import (
    _detect_framework,
    _format_summary,
    _parse_generic,
    _parse_go,
    _parse_jest,
    _parse_pytest,
)


async def _workspace_execution(tmp_path):
    """Set up a git repo + workspace + ExecutionService for workspace-write tests."""
    from khaos.coding.execution import ExecutionService, HostExecutionBackend
    from khaos.coding.workspace.manager import WorkspaceManager

    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t.com"],
        ["git", "config", "user.name", "T"],
    ):
        subprocess.run(cmd, cwd=repo, check=True)
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repo, "task")
    execution = ExecutionService(HostExecutionBackend(), manager)
    return execution, workspace


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------


def test_detect_framework_matches_common_runners():
    assert _detect_framework("pytest tests/ -q") == "pytest"
    assert _detect_framework("jest") == "jest"
    assert _detect_framework("vitest run") == "jest"
    assert _detect_framework("go test ./...") == "go"
    assert _detect_framework("npm test") == "generic"


# ---------------------------------------------------------------------------
# pytest parsing
# ---------------------------------------------------------------------------


PYTEST_FAIL_OUTPUT = """\
tests/test_core.py F.                                                      [100%]

================================== FAILURES ==================================
_________________________________ test_bar ___________________________________

    def test_bar():
>       assert 1 == 2
E       AssertionError

tests/test_core.py:12: AssertionError
========================= short test summary info ==========================
FAILED tests/test_core.py::test_bar - assert 1 == 2
=================== 1 failed, 1 passed in 1.23s =============================
"""


def test_parse_pytest_counts_and_failed_cases():
    result = _parse_pytest(PYTEST_FAIL_OUTPUT)

    assert result["passed"] == 1
    assert result["failed"] == 1
    assert len(result["failed_cases"]) == 1
    case = result["failed_cases"][0]
    assert case["name"] == "test_bar"
    assert case["file"] == "tests/test_core.py"
    assert case["error"] == "assert 1 == 2"
    # Line number resolved from the traceback header.
    assert case["line"] == 12


def test_parse_pytest_clean_run_has_no_failed_cases():
    result = _parse_pytest("===== 3 passed in 0.5s =====")

    assert result == {
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "failed_cases": [],
    }


def test_parse_pytest_errors_only():
    result = _parse_pytest("===== 2 errors in 0.4s =====")

    assert result["passed"] == 0
    assert result["failed"] == 0
    assert result["errors"] == 2


# ---------------------------------------------------------------------------
# jest / vitest parsing
# ---------------------------------------------------------------------------


JEST_FAIL_OUTPUT = """\
FAIL  src/calc.test.js
  ● add() › adds two numbers

    expect(received).toBe(expected)

      4 |   expect(add(1, 2)).toBe(4);
        |                     ^
      at Object.<anonymous> (src/calc.test.js:4:23)

Tests: 1 failed, 3 passed, 4 total
"""


def test_parse_jest_counts_and_failed_cases():
    result = _parse_jest(JEST_FAIL_OUTPUT)

    assert result["passed"] == 3
    assert result["failed"] == 1
    assert result["failed_cases"]
    case = result["failed_cases"][0]
    assert "add()" in case["name"]
    assert "src/calc.test.js" in case["file"]
    assert case["line"] == 4


VITEST_OUTPUT = """\
FAIL  src/calc.test.ts > add() [ add() ]

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

Error: expected 3 to be 4
 ❯ src/calc.test.ts:4:23

 Test Files  1 failed (1)
      Tests  1 failed (1)
"""


def test_parse_vitest_counts():
    result = _parse_jest(VITEST_OUTPUT)

    assert result["failed"] == 1


# ---------------------------------------------------------------------------
# go test parsing
# ---------------------------------------------------------------------------


GO_FAIL_OUTPUT = """\
=== RUN   TestAdd
=== RUN   TestAdd/positive
    calc_test.go:12: expected 3, got 4
--- FAIL: TestAdd/positive (0.00s)
--- PASS: TestAdd/negative (0.00s)
PASS
ok  \texample.com/pkg  0.5s
"""


def test_parse_go_counts_and_failed_case():
    result = _parse_go(GO_FAIL_OUTPUT)

    assert result["passed"] == 1
    assert result["failed"] == 1
    case = result["failed_cases"][0]
    assert case["name"] == "TestAdd/positive"
    assert case["file"] == "calc_test.go"
    assert case["line"] == 12
    assert "expected 3, got 4" in case["error"]


def test_parse_go_non_verbose_fail_marker():
    result = _parse_go("FAIL\texample.com/pkg\t0.5s\n")

    assert result["failed"] >= 1


# ---------------------------------------------------------------------------
# generic fallback parsing
# ---------------------------------------------------------------------------


def test_parse_generic_keyword_fallback():
    text = """
Some custom runner output
FAILED scenario_one
FAILED scenario_two at path/to/feature:42
2 failing
"""
    result = _parse_generic(text)

    assert result["failed"] == 2
    assert len(result["failed_cases"]) >= 2


def test_parse_generic_mocha_style():
    text = "  3 passing\n  1 failing\n"

    result = _parse_generic(text)

    assert result["passed"] == 3
    assert result["failed"] == 1


# ---------------------------------------------------------------------------
# summary formatting
# ---------------------------------------------------------------------------


def test_format_summary_parts():
    assert _format_summary(2, 0, 0, 0) == "2 passed"
    assert _format_summary(2, 1, 0, 1) == "2 passed, 1 failed"
    assert _format_summary(0, 0, 0, 0) == "passed"
    assert "no results" in _format_summary(0, 0, 0, 1)


# ---------------------------------------------------------------------------
# integration: ExecutionService-backed execution via a known command
# ---------------------------------------------------------------------------


async def test_test_run_empty_command_returns_error(tmp_path):
    result = json.loads(await test_tools.test_run("", cwd=str(tmp_path)))

    assert result["success"] is False
    assert "empty" in result["error"]


async def test_test_run_without_execution_service_fails_closed(tmp_path):
    """Coding Agent reachable test_run() must fail closed without ExecutionService."""
    result = json.loads(await test_tools.test_run("echo hello", cwd=str(tmp_path)))

    assert result["success"] is False
    assert "ExecutionService unavailable" in result["error"]


async def test_test_run_executes_real_command(tmp_path):
    # ``python3 -c`` doubles as a deterministic "test" that exits 0 with known
    # stdout so we exercise the full ExecutionService path without a real runner.
    execution, workspace = await _workspace_execution(tmp_path)
    result = json.loads(
        await test_tools.test_run(
            "python3 -c \"print('3 passed in 0.1s')\"",
            cwd=str(workspace.worktree_path),
            execution_service=execution,
            task_id="task",
            workspace_id=workspace.id,
        )
    )

    assert result["success"] is True
    assert result["exit_code"] == 0
    assert result["passed"] == 3


async def test_test_run_unknown_command_reports_failure(tmp_path):
    execution, workspace = await _workspace_execution(tmp_path)
    result = json.loads(
        await test_tools.test_run(
            "definitely-not-a-real-binary-xyz",
            cwd=str(workspace.worktree_path),
            execution_service=execution,
            task_id="task",
            workspace_id=workspace.id,
        )
    )

    assert result["success"] is False
    assert "not found" in result["summary"].lower()


async def test_test_run_timeout(monkeypatch, tmp_path):
    # Force a tiny timeout so the hung process branch is exercised.
    monkeypatch.setattr(test_tools, "TEST_RUN_TIMEOUT", 0)
    execution, workspace = await _workspace_execution(tmp_path)
    result = json.loads(
        await test_tools.test_run(
            "python3 -c \"import time; time.sleep(5)\"",
            cwd=str(workspace.worktree_path),
            execution_service=execution,
            task_id="task",
            workspace_id=workspace.id,
        )
    )

    assert result["success"] is False
    assert "timed out" in result["summary"]
