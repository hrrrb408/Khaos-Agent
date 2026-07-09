"""Verify-fix loop strategy layer for coding mode.

When the agent runs ``test_run`` and the parsed result contains failing tests,
this module formats the failure into a guidance message that is injected back
into the conversation so the model diagnoses, fixes, and re-runs the tests —
without any user intervention.

It is a *strategy layer* that cooperates with :class:`AgentLoop.run`, not a
separate agent. The loop keeps two pieces of state:

* ``_attempt_count`` — how many fix attempts have been issued so far.
* ``_history`` — the outcome of every attempt (passed/failed test counts).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Default cap on automatic fix attempts before handing back to the user.
DEFAULT_MAX_FIX_ATTEMPTS: int = 3


@dataclass
class FixAttempt:
    """Record of one verify-fix attempt."""

    attempt: int
    passed: int
    failed: int
    errors: int
    failed_cases: list[dict] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True when the attempt had no failures and no errors."""
        return self.failed == 0 and self.errors == 0


class VerifyFixLoop:
    """Automatic verify-fix loop strategy layer.

    In coding mode, when ``AgentLoop``'s tool scheduling returns a ``test_run``
    result whose parsed output contains failures, this module injects the
    failure context back into the message list so the model repairs the failure
    and re-runs the tests.

    A ``ToolResult`` arriving from the scheduler is represented as a plain dict
    with the keys ``name``, ``success``, ``output``, and ``error``. The actual
    pass/fail counts live inside ``output`` (a JSON string produced by
    ``test_run``), because ``test_run`` never raises — it always returns a
    structured JSON result. The loop therefore parses ``output`` rather than
    trusting ``ToolResult.success``.
    """

    def __init__(
        self,
        max_fix_attempts: int = DEFAULT_MAX_FIX_ATTEMPTS,
        test_command: str = "pytest",
        test_cwd: str = ".",
    ) -> None:
        if max_fix_attempts < 0:
            raise ValueError("max_fix_attempts must be non-negative")
        self.max_fix_attempts = max_fix_attempts
        self.test_command = test_command
        self.test_cwd = test_cwd
        self._attempt_count = 0
        self._history: list[FixAttempt] = []

    def should_enter_loop(self, tool_result: dict) -> bool:
        """Decide whether to enter the verify-fix loop for this result.

        Conditions: ``name == "test_run"``, the parsed output reports a failure
        (``failed > 0`` or ``errors > 0``), and the attempt budget is not yet
        exhausted. Returns ``False`` for any other tool, a passing test, or
        when ``max_fix_attempts == 0``.
        """
        if self.max_fix_attempts == 0:
            return False
        if not isinstance(tool_result, dict):
            return False
        if tool_result.get("name") != "test_run":
            return False
        if self._attempt_count >= self.max_fix_attempts:
            return False
        parsed = _parse_test_output(tool_result)
        if parsed is None:
            return False
        # Record the attempt regardless of the decision so the final report is
        # complete even when the budget runs out on this very call.
        return bool(parsed["failed"] or parsed["errors"])

    def build_failure_context(self, tool_result: dict) -> str:
        """Format test-failure details into a guidance message for the model.

        Increments the attempt counter and records the attempt. The message
        includes the failing test names, files, line numbers, and the error
        snippets, followed by an explicit ``read → fix → re-run`` instruction.
        """
        parsed = _parse_test_output(tool_result)
        if parsed is None:
            logger.warning("build_failure_context called without parseable test output")
            return ""

        self._attempt_count += 1
        attempt = FixAttempt(
            attempt=self._attempt_count,
            passed=parsed["passed"],
            failed=parsed["failed"],
            errors=parsed["errors"],
            failed_cases=parsed["failed_cases"],
        )
        self._history.append(attempt)

        lines: list[str] = [
            f"## 测试失败（第 {self._attempt_count}/{self.max_fix_attempts} 次修复尝试）",
            "",
            "以下测试失败：",
        ]
        cases = parsed["failed_cases"]
        if cases:
            for case in cases:
                lines.append(_format_failed_case(case))
        else:
            lines.append(
                f"- {parsed['failed']} failed, {parsed['errors']} errors"
                "（未能解析具体用例）"
            )

        lines.extend(
            [
                "",
                "请：",
                "1. 读取失败文件的相关代码",
                "2. 修复导致失败的问题",
                "3. 重新运行测试",
            ]
        )
        message = "\n".join(lines)
        logger.info(
            "verify-fix attempt %d/%d: %d failed, %d errors",
            self._attempt_count,
            self.max_fix_attempts,
            parsed["failed"],
            parsed["errors"],
        )
        return message

    def is_loop_exhausted(self) -> bool:
        """True when the fix budget has been spent."""
        return self._attempt_count >= self.max_fix_attempts

    def get_final_report(self) -> str:
        """Summarise the loop: attempts made and which tests finally passed."""
        if not self._history:
            return "verify-fix loop: no attempts were made."
        lines: list[str] = [
            f"## Verify-Fix 最终报告（共 {self._attempt_count} 次尝试）",
            "",
        ]
        for attempt in self._history:
            status = "通过" if attempt.success else "失败"
            lines.append(
                f"- 第 {attempt.attempt} 次：{attempt.passed} passed, "
                f"{attempt.failed} failed, {attempt.errors} errors — {status}"
            )

        last = self._history[-1]
        if last.success:
            lines.append("")
            lines.append(
                f"所有测试在第 {self._attempt_count} 次尝试后通过。"
            )
        else:
            remaining = [c.get("name", "<unknown>") for c in last.failed_cases]
            lines.append("")
            lines.append(
                f"达到最大修复次数（{self.max_fix_attempts}），以下测试仍然失败："
            )
            for name in remaining:
                lines.append(f"  - {name}")
            lines.append("请由用户决策后续操作。")
        return "\n".join(lines)

    @property
    def attempt_count(self) -> int:
        """Number of fix attempts issued so far."""
        return self._attempt_count


def _parse_test_output(tool_result: dict) -> dict | None:
    """Extract pass/fail counts from a ``test_run`` ToolResult dict.

    The ``output`` field is the JSON string produced by ``test_run``. When it
    can't be parsed (or isn't a test result at all), return ``None``.
    """
    output = tool_result.get("output")
    if output is None:
        return None
    if isinstance(output, (dict,)):
        data = output
    elif isinstance(output, str):
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return None
    else:
        return None
    if not isinstance(data, dict):
        return None
    # Only treat it as a test result if it has the test_run shape.
    if not any(key in data for key in ("passed", "failed", "errors")):
        return None
    return {
        "passed": int(data.get("passed", 0)),
        "failed": int(data.get("failed", 0)),
        "errors": int(data.get("errors", 0)),
        "failed_cases": list(data.get("failed_cases", [])),
    }


def _format_failed_case(case: dict) -> str:
    """Render one failed test case into a bullet line."""
    name = case.get("name") or "<unknown test>"
    file_ref = case.get("file") or ""
    line = case.get("line")
    error = case.get("error") or ""

    location = file_ref
    if line:
        location = f"{file_ref}:{line}" if file_ref else f"line {line}"
    suffix = f" — {error}" if error else ""
    if location:
        return f"- {name}: {location}{suffix}"
    return f"- {name}{suffix}"
