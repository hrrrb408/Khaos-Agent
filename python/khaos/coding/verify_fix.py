"""Verify-fix loop strategy layer for coding mode.

The loop deliberately separates two timelines:

* verification observations contain every parseable ``test_run`` result;
* repair attempts contain only repair guidance that was actually issued.

This distinction is important at the repair budget boundary. A failing test
result can still authorize the final repair attempt, and a later passing
result must supersede historical failure/exhaustion state.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

#: Default cap on automatic fix attempts before handing back to the user.
DEFAULT_MAX_FIX_ATTEMPTS: int = 3


class VerificationState(str, Enum):
    """Terminal interpretation of the latest parseable verification result."""

    UNKNOWN = "unknown"
    FAILING = "failing"
    PASSED = "passed"
    EXHAUSTED_FAILURE = "exhausted_failure"


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    """One parseable test observation, independent of repair issuance."""

    observation: int
    passed: int
    failed: int
    errors: int
    failed_cases: tuple[dict[str, Any], ...] = ()
    state: VerificationState = VerificationState.UNKNOWN

    @property
    def success(self) -> bool:
        """True when this verification observation had no failures/errors."""
        return self.failed == 0 and self.errors == 0

    @property
    def failure_signature(self) -> tuple[Any, ...]:
        """Return a bounded, deterministic signature for no-progress checks."""
        cases = tuple(
            (
                str(case.get("name") or ""),
                str(case.get("file") or ""),
                case.get("line"),
                str(case.get("error") or ""),
            )
            for case in self.failed_cases
        )
        return self.failed, self.errors, cases


@dataclass(frozen=True, slots=True)
class RepairAttempt:
    """Record of one repair guidance issuance.

    The linked observation identifies the failure that triggered this repair;
    test counts themselves remain exclusively on ``VerificationObservation``.
    """

    attempt: int
    observation: int
    failure_signature: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class NoProgressSignal:
    """Typed observable signal for repeated identical verification failures."""

    detected: bool
    observation_indices: tuple[int, ...] = ()
    failure_signature: tuple[Any, ...] = ()
    reason: str = ""


class VerifyFixLoop:
    """Automatic verify-fix loop strategy layer.

    In coding mode, when ``AgentLoop``'s tool scheduling returns a ``test_run``
    result whose parsed output contains failures, this module injects the
    failure context back into the message list so the model repairs the failure
    and re-runs the tests.

    A ``ToolResult`` arriving from the scheduler is represented as a mapping
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
        self._verification_history: list[VerificationObservation] = []
        self._repair_history: list[RepairAttempt] = []
        self._report_emitted = False

    def observe_test_result(
        self, tool_result: Mapping[str, Any]
    ) -> VerificationObservation | None:
        """Record one parseable ``test_run`` result.

        Observation is intentionally independent from the repair budget. Every
        parseable result is recorded, including results received after the
        budget is exhausted. ``PASSED`` is always the latest authoritative
        state when the current observation is green; a failure becomes
        ``EXHAUSTED_FAILURE`` only when no repair remains *at the time the
        failure is observed*.
        """
        if not isinstance(tool_result, Mapping):
            return None
        if tool_result.get("name") != "test_run":
            return None
        parsed = _parse_test_output(tool_result)
        if parsed is None:
            return None

        return self._record_observation(
            passed=parsed["passed"],
            failed=parsed["failed"],
            errors=parsed["errors"],
            failed_cases=tuple(parsed["failed_cases"]),
        )

    def observe_autonomous_run(self, run: Any) -> VerificationObservation | None:
        """Record an M8.3 run in this same repair strategy layer.

        The autonomous planner has richer typed statuses than the legacy
        ``test_run`` tool.  This adapter reduces them to the existing bounded
        observation shape so repair budgets, no-progress detection, and
        recovery remain owned by one loop rather than creating a second
        controller in ``AgentLoop``.
        """
        status = getattr(getattr(run, "status", None), "value", getattr(run, "status", None))
        if not isinstance(status, str) or status not in {
            "passed",
            "failed",
            "timed_out",
            "cancelled",
            "stale",
            "infrastructure_error",
            "unknown",
        }:
            return None
        required = getattr(run, "required_count", 0)
        passed = getattr(run, "passed_count", 0)
        if type(required) is not int or required < 0:
            required = 0
        if type(passed) is not int or passed < 0:
            passed = 0
        passed = min(passed, required)
        failed = 0 if status == "passed" else max(1, required - passed)
        errors = 0 if status in {"passed", "failed"} else 1
        failed_cases: list[dict[str, Any]] = []
        for diagnostic in tuple(getattr(run, "diagnostics", ()) or ())[:64]:
            category = getattr(getattr(diagnostic, "category", None), "value", "verification")
            path = getattr(diagnostic, "path", None)
            line = getattr(diagnostic, "line", None)
            message = getattr(diagnostic, "message", "")
            name = f"{category}:{path or 'verification'}"
            failed_cases.append(
                {
                    "name": str(name)[:512],
                    "file": path if isinstance(path, str) else None,
                    "line": line if type(line) is int and line > 0 else None,
                    "error": str(message)[:1024],
                }
            )
        for evidence in tuple(getattr(run, "evidence", ()) or ())[:64]:
            evidence_status = getattr(
                getattr(evidence, "status", None), "value", getattr(evidence, "status", None)
            )
            if evidence_status == "passed":
                continue
            check_id = getattr(evidence, "check_id", "verification-check")
            failed_cases.append(
                {
                    "name": str(check_id)[:512],
                    "file": None,
                    "line": None,
                    "error": str(evidence_status or status)[:1024],
                }
            )
        if status != "passed" and not failed_cases:
            failed_cases.append(
                {
                    "name": "autonomous-verification",
                    "file": None,
                    "line": None,
                    "error": status,
                }
            )
        return self._record_observation(
            passed=passed,
            failed=failed,
            errors=errors,
            failed_cases=tuple(failed_cases[:64]),
        )

    def _record_observation(
        self,
        *,
        passed: int,
        failed: int,
        errors: int,
        failed_cases: tuple[dict[str, Any], ...],
    ) -> VerificationObservation:
        observation_number = len(self._verification_history) + 1
        if not failed and not errors:
            state = VerificationState.PASSED
        elif self._attempt_count >= self.max_fix_attempts:
            state = VerificationState.EXHAUSTED_FAILURE
        else:
            state = VerificationState.FAILING
        observation = VerificationObservation(
            observation=observation_number,
            passed=passed,
            failed=failed,
            errors=errors,
            failed_cases=failed_cases,
            state=state,
        )
        self._verification_history.append(observation)
        logger.info(
            "verification observation %d: state=%s passed=%d failed=%d errors=%d",
            observation.observation,
            observation.state.value,
            observation.passed,
            observation.failed,
            observation.errors,
        )
        return observation

    def should_enter_loop(
        self,
        tool_result: Mapping[str, Any],
        *,
        observation: VerificationObservation | None = None,
    ) -> bool:
        """Decide whether to enter the verify-fix loop for this result.

        This is a pure predicate: it never records an observation or mutates
        repair state. Callers must invoke :meth:`observe_test_result` first.
        Conditions are ``name == "test_run"``, a parseable failing result, and
        at least one automatic repair still available.
        """
        if not isinstance(tool_result, Mapping):
            return False
        if tool_result.get("name") != "test_run":
            return False
        if self._attempt_count >= self.max_fix_attempts:
            return False
        parsed = (
            {
                "failed": observation.failed,
                "errors": observation.errors,
            }
            if observation is not None
            else _parse_test_output(tool_result)
        )
        if parsed is None:
            return False
        return bool(parsed["failed"] or parsed["errors"])

    def build_failure_context(
        self,
        tool_result: Mapping[str, Any],
        *,
        observation: VerificationObservation | None = None,
    ) -> str:
        """Format test-failure details into a guidance message for the model.

        This method is the repair-issuance boundary. It increments
        ``attempt_count`` only when a repair is actually admitted. For
        backwards-compatible direct callers, a missing observation is recorded
        here; AgentLoop passes the observation explicitly after observing it.
        """
        if observation is None:
            observation = self.observe_test_result(tool_result)
        if observation is None or (
            not observation.failed and not observation.errors
        ):
            return ""
        # A failure observed after the budget is spent cannot issue another
        # automatic repair. In particular, the third failure does not reach
        # this branch until repair #3 has already been admitted.
        if self._attempt_count >= self.max_fix_attempts:
            return ""

        attempt = self.admit_repair(observation)
        if attempt is None:
            return ""

        lines: list[str] = [
            f"## 测试失败（第 {attempt}/{self.max_fix_attempts} 次修复尝试）",
            "",
            "以下测试失败：",
        ]
        cases = observation.failed_cases
        if cases:
            for case in cases:
                lines.append(_format_failed_case(case))
        else:
            lines.append(
                f"- {observation.failed} failed, {observation.errors} errors"
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
            "verify-fix repair attempt %d/%d issued for observation %d",
            self._attempt_count,
            self.max_fix_attempts,
            observation.observation,
        )
        return message

    def admit_repair(self, observation: VerificationObservation) -> int | None:
        """Consume one repair attempt for any verification observation.

        M8.3 uses this exact budget boundary while supplying its own typed,
        bounded diagnostic context.  Returning ``None`` means the failure is
        observed but no further automatic mutation may be requested.
        """
        if not isinstance(observation, VerificationObservation):
            return None
        if not observation.failed and not observation.errors:
            return None
        if self._attempt_count >= self.max_fix_attempts:
            return None
        self._attempt_count += 1
        self._repair_history.append(
            RepairAttempt(
                attempt=self._attempt_count,
                observation=observation.observation,
                failure_signature=observation.failure_signature,
            )
        )
        logger.info(
            "verify-fix repair attempt %d/%d issued for observation %d",
            self._attempt_count,
            self.max_fix_attempts,
            observation.observation,
        )
        return self._attempt_count

    @property
    def verification_state(self) -> VerificationState:
        """Return the latest parseable verification state."""
        if not self._verification_history:
            return VerificationState.UNKNOWN
        return self._verification_history[-1].state

    @property
    def latest_verification(self) -> VerificationObservation | None:
        """Return the latest parseable observation, if any."""
        return self._verification_history[-1] if self._verification_history else None

    @property
    def verification_history(self) -> tuple[VerificationObservation, ...]:
        """Return all parseable verification observations in order."""
        return tuple(self._verification_history)

    @property
    def repair_history(self) -> tuple[RepairAttempt, ...]:
        """Return all automatic repairs issued in order."""
        return tuple(self._repair_history)

    def is_loop_exhausted(self) -> bool:
        """Return whether the latest failure is terminally exhausted."""
        return self.verification_state is VerificationState.EXHAUSTED_FAILURE

    def no_progress_signal(self) -> NoProgressSignal:
        """Return a typed signal for two identical latest failures.

        M7.1.1 exposes the signal only. Recovery/Replan state transitions are
        deliberately owned by the later Recovery Engine batch.
        """
        if len(self._verification_history) < 2:
            return NoProgressSignal(False)
        previous, current = self._verification_history[-2:]
        if (
            (not previous.failed and not previous.errors)
            or (not current.failed and not current.errors)
        ):
            return NoProgressSignal(False)
        if previous.failure_signature != current.failure_signature:
            return NoProgressSignal(False)
        return NoProgressSignal(
            detected=True,
            observation_indices=(previous.observation, current.observation),
            failure_signature=current.failure_signature,
            reason="identical_failure_signature",
        )

    def should_stop_no_progress(self) -> bool:
        """Compatibility predicate backed by the typed no-progress signal."""
        return self.no_progress_signal().detected

    @property
    def report_emitted(self) -> bool:
        """Return whether the exhaustion report has already been emitted."""
        return self._report_emitted

    def mark_report_emitted(self) -> None:
        """Mark the one-shot exhaustion report as emitted by AgentLoop."""
        self._report_emitted = True

    def get_final_report(self) -> str:
        """Summarise repairs using the latest verification observation."""
        latest = self.latest_verification
        if latest is None:
            return "verify-fix loop: no verification observations were recorded."

        lines: list[str] = [
            (
                f"## Verify-Fix 最终报告（共 {self._attempt_count} 次修复尝试，"
                f"{len(self._verification_history)} 次验证观察）"
            ),
            "",
        ]
        for observation in self._verification_history:
            lines.append(
                f"- 验证观察 {observation.observation}："
                f"{observation.passed} passed, {observation.failed} failed, "
                f"{observation.errors} errors — {observation.state.value}"
            )

        if latest.state is VerificationState.PASSED:
            lines.extend(
                [
                    "",
                    "最新验证观察已通过；历史失败或修复次数上限不覆盖 PASSED。",
                ]
            )
        elif latest.state is VerificationState.EXHAUSTED_FAILURE:
            remaining = [case.get("name", "<unknown>") for case in latest.failed_cases]
            lines.extend(
                [
                    "",
                    f"达到最大自动修复次数（{self.max_fix_attempts}），最新验证仍然失败：",
                ]
            )
            for name in remaining:
                lines.append(f"  - {name}")
            lines.append("请由用户决策后续操作。")
        elif latest.state is VerificationState.FAILING:
            lines.extend(
                [
                    "",
                    "最新验证仍然失败；任务不能因普通 END_TURN 判定为完成。",
                    f"已发出 {self._attempt_count}/{self.max_fix_attempts} 次自动修复。",
                ]
            )
        else:
            lines.extend(["", "最新验证状态未知。"])
        return "\n".join(lines)

    @property
    def attempt_count(self) -> int:
        """Number of fix attempts issued so far."""
        return self._attempt_count


def _parse_test_output(tool_result: Mapping[str, Any]) -> dict[str, Any] | None:
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
    try:
        passed = int(data.get("passed", 0))
        failed = int(data.get("failed", 0))
        errors = int(data.get("errors", 0))
    except (TypeError, ValueError):
        return None
    if min(passed, failed, errors) < 0:
        return None
    raw_failed_cases = data.get("failed_cases", [])
    if raw_failed_cases is None:
        raw_failed_cases = []
    if not isinstance(raw_failed_cases, (list, tuple)):
        return None
    failed_cases = [
        case for case in raw_failed_cases if isinstance(case, dict)
    ]
    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "failed_cases": failed_cases,
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
