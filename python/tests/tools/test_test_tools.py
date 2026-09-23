"""Tests for the test_run feedback-loop tool and its output parsers."""

import asyncio
import json
import subprocess
import sys

import pytest
from khaos.coding.execution.environment import (
    split_command_environment,
    validate_command_environment,
)
from khaos.tools import test_tools
from khaos.tools.test_tools import (
    _detect_framework,
    _format_summary,
    _parse_generic,
    _parse_go,
    _parse_jest,
    _parse_pytest,
    _parse_tap,
    _parse_unittest,
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
        await asyncio.to_thread(subprocess.run, cmd, cwd=repo, check=True)
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    await asyncio.to_thread(
        subprocess.run, ["git", "add", "."], cwd=repo, check=True
    )
    await asyncio.to_thread(
        subprocess.run,
        ["git", "commit", "-qm", "base"],
        cwd=repo,
        check=True,
    )
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
    assert _detect_framework("node --experimental-strip-types --test src/config.test.ts") == "tap"
    assert _detect_framework("python -m unittest discover -s tests -v") == "unittest"
    assert _detect_framework("npm test") == "generic"


def test_command_environment_prefix_is_no_shell_and_bounded():
    assignments, argv = split_command_environment(
        ("GO111MODULE=off", "go", "test", "-v", ".")
    )

    assert assignments == {"GO111MODULE": "off"}
    assert argv == ("go", "test", "-v", ".")
    validate_command_environment(assignments, allowed_keys={"GO111MODULE"})

    with pytest.raises(PermissionError):
        validate_command_environment(assignments, allowed_keys={"PATH"})


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
# unittest parsing
# ---------------------------------------------------------------------------


UNITTEST_FAIL_OUTPUT = """\\
test_falsey (tests.test_cache.CacheTests) ... ok
test_missing (tests.test_cache.CacheTests) ... FAIL
test_import (tests.test_cache.CacheTests) ... ERROR

======================================================================
FAIL: test_missing (tests.test_cache.CacheTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File \"tests/test_cache.py\", line 18, in test_missing
    self.assertEqual(value, 0)
AssertionError: None != 0

======================================================================
ERROR: test_import (tests.test_cache.CacheTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File \"tests/test_cache.py\", line 4, in test_import
    import missing_module
ModuleNotFoundError: No module named 'missing_module'

----------------------------------------------------------------------
Ran 3 tests in 0.002s

FAILED (failures=1, errors=1)
"""


def test_parse_unittest_counts_and_failure_cases():
    result = _parse_unittest(UNITTEST_FAIL_OUTPUT)

    assert result["passed"] == 1
    assert result["failed"] == 1
    assert result["errors"] == 1
    assert {case["name"] for case in result["failed_cases"]} == {
        "test_missing (tests.test_cache.CacheTests)",
        "test_import (tests.test_cache.CacheTests)",
    }


def test_parse_unittest_clean_run_uses_ran_summary():
    result = _parse_unittest("Ran 3 tests in 0.001s\n\nOK\n")

    assert result == {
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "failed_cases": [],
    }


def test_parse_tap_counts_node_test_failures():
    result = _parse_tap(
        """TAP version 13
not ok 1 - explicit false is preserved
1..1
# tests 1
# pass 0
# fail 1
# cancelled 0
"""
    )

    assert result == {
        "passed": 0,
        "failed": 1,
        "errors": 0,
        "failed_cases": [
            {
                "name": "explicit false is preserved",
                "file": "",
                "error": "",
                "line": None,
            }
        ],
    }


def test_parse_tap_counts_node_test_success():
    result = _parse_tap(
        """TAP version 13
ok 1 - explicit false is preserved
ok 2 - missing value defaults
1..2
# tests 2
# pass 2
# fail 0
# cancelled 0
"""
    )

    assert result == {
        "passed": 2,
        "failed": 0,
        "errors": 0,
        "failed_cases": [],
    }


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


@pytest.mark.posix_host
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


@pytest.mark.posix_host
async def test_test_run_pytest_does_not_create_workspace_cache(tmp_path):
    """Pytest verification must not turn runner cache into workspace drift."""
    execution, workspace = await _workspace_execution(tmp_path)
    (workspace.worktree_path / "test_cache_hygiene.py").write_text(
        "def test_cache_hygiene():\n    assert True\n",
        encoding="utf-8",
    )

    result = json.loads(
        await test_tools.test_run(
            f"{sys.executable} -m pytest -q",
            cwd=str(workspace.worktree_path),
            execution_service=execution,
            task_id="task",
            workspace_id=workspace.id,
        )
    )

    assert result["success"] is True
    assert not (workspace.worktree_path / ".pytest_cache").exists()


async def test_test_run_uses_approved_spawn_plan_environment(tmp_path):
    from types import SimpleNamespace

    class _CaptureExecution:
        request = None

        async def execute(self, request):
            self.request = request
            return SimpleNamespace(
                return_code=0,
                stdout="1 passed in 0.1s\n",
                stderr="",
                status="completed",
            )

    execution = _CaptureExecution()
    spawn_plan = SimpleNamespace(
        environment=(("LANG", "C.UTF-8"), ("PATH", "/trusted/bin")),
    )

    result = json.loads(
        await test_tools.test_run(
            "pytest -q",
            cwd=str(tmp_path),
            execution_service=execution,
            task_id="task",
            workspace_id="workspace",
            spawn_plan=spawn_plan,
        )
    )

    assert result["success"] is True
    assert execution.request.environment == {
        "LANG": "C.UTF-8",
        "PATH": "/trusted/bin",
    }


async def test_test_run_binds_environment_prefix_to_approved_spawn_plan(tmp_path):
    from types import SimpleNamespace

    class _CaptureExecution:
        request = None

        async def execute(self, request):
            self.request = request
            return SimpleNamespace(
                return_code=0,
                stdout="1 passed in 0.1s\n",
                stderr="",
                status="completed",
            )

    execution = _CaptureExecution()
    spawn_plan = SimpleNamespace(
        environment=(
            ("GO111MODULE", "off"),
            ("PATH", "/trusted/bin"),
        ),
    )

    result = json.loads(
        await test_tools.test_run(
            "GO111MODULE=off go test -v .",
            cwd=str(tmp_path),
            execution_service=execution,
            task_id="task",
            workspace_id="workspace",
            spawn_plan=spawn_plan,
        )
    )

    assert result["success"] is True
    assert execution.request.argv == ("go", "test", "-v", ".")
    assert execution.request.environment == {
        "GO111MODULE": "off",
        "PATH": "/trusted/bin",
    }


async def test_test_run_projects_spawn_environment_into_permission_profile(tmp_path):
    from types import SimpleNamespace

    class _CaptureExecution:
        request = None

        async def execute(self, request):
            self.request = request
            return SimpleNamespace(
                return_code=0,
                stdout="1 passed in 0.1s\n",
                stderr="",
                status="completed",
            )

    execution = _CaptureExecution()
    spawn_plan = SimpleNamespace(
        environment=(
            ("PATH", "/trusted/bin"),
            ("PYTEST_ADDOPTS", "-p no:cacheprovider"),
        ),
    )

    result = json.loads(
        await test_tools.test_run(
            "pytest -q",
            cwd=str(tmp_path),
            execution_service=execution,
            task_id="task",
            workspace_id="workspace",
            spawn_plan=spawn_plan,
        )
    )

    assert result["success"] is True
    assert execution.request.permission_profile.environment_keys == frozenset(
        {"PATH", "PYTEST_ADDOPTS"}
    )


@pytest.mark.posix_host
async def test_test_run_accepts_registry_workspace_manager_injection(tmp_path):
    """The broker's complete process injection contract reaches test_run."""
    execution, workspace = await _workspace_execution(tmp_path)
    from khaos.tools.registry import ToolInvocationBroker, create_runtime_registry

    broker = ToolInvocationBroker(create_runtime_registry())
    result = json.loads(
        await broker.invoke(
            "test_run",
            mode="coding",
            context={
                "execution_service": execution,
                "workspace_manager": execution.workspace_manager,
                "process_authority": object(),
                "principal_id": "principal",
                "project_id": "project",
                "runtime_id": "runtime",
                "task_id": "task",
                "workspace_id": workspace.id,
            },
            command="python3 -c \"print('1 passed in 0.1s')\"",
            cwd=str(workspace.worktree_path),
        )
    )

    assert result["success"] is True
    assert result["passed"] == 1


@pytest.mark.posix_host
async def test_test_run_resolves_relative_cwd_inside_workspace(tmp_path):
    """Relative process cwd values must bind to the active worktree."""
    execution, workspace = await _workspace_execution(tmp_path)
    from khaos.tools.registry import ToolInvocationBroker, create_runtime_registry

    broker = ToolInvocationBroker(create_runtime_registry())
    result = json.loads(
        await broker.invoke(
            "test_run",
            mode="coding",
            context={
                "execution_service": execution,
                "workspace_manager": execution.workspace_manager,
                "process_authority": object(),
                "principal_id": "principal",
                "project_id": "project",
                "runtime_id": "runtime",
                "task_id": "task",
                "workspace_id": workspace.id,
            },
            command="python3 -c \"print('1 passed in 0.1s')\"",
            cwd=".",
        )
    )

    assert result["success"] is True
    assert result["passed"] == 1


@pytest.mark.posix_host
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
    # Batch 15.7: deterministic timeout-classification test.
    #
    # Previously this set ``TEST_RUN_TIMEOUT=0`` (converted to 1ms by
    # ``max(float(TEST_RUN_TIMEOUT), 0.001)``) and spawned a real
    # ``python3 -c "time.sleep(5)"`` subprocess.  The 1ms deadline races
    # with OS scheduling — sometimes the timeout fired before
    # ``create_subprocess_exec`` even returned, sometimes after the child
    # was alive but before it reached ``time.sleep``.  That made the test
    # flaky on CI runners under load.
    #
    # The timeout *classification* (``result.status == "timed-out"`` →
    # summary) is pure Python and does not need a real process.  We still
    # set ``TEST_RUN_TIMEOUT=0`` to exercise the 0 → 0.001s ResourceBudget
    # conversion (so validation does not reject the request), but the
    # ExecutionService is mocked to return a ``timed-out`` result directly,
    # eliminating the subprocess race.
    from unittest.mock import AsyncMock

    from khaos.coding.execution.models import ExecutionResult

    monkeypatch.setattr(test_tools, "TEST_RUN_TIMEOUT", 0)

    mock_execution = AsyncMock()
    mock_execution.execute = AsyncMock(
        return_value=ExecutionResult(
            execution_id="test-timeout",
            status="timed-out",
            return_code=None,
            stdout="",
            stderr="",
            duration_ms=1,
        )
    )

    result = json.loads(
        await test_tools.test_run(
            "python3 -c \"import time; time.sleep(5)\"",
            cwd=str(tmp_path),
            execution_service=mock_execution,
            task_id="task",
            workspace_id="ws",
        )
    )

    assert result["success"] is False
    assert "timed out" in result["summary"]
