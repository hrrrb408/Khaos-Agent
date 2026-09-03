"""M8.3 executor adapter over the existing ``ExecutionService``."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionResult,
    NetworkPolicy,
    ResourceBudget,
)
from khaos.coding.verification.contracts import (
    DiagnosticCategory,
    DiagnosticSeverity,
    VerificationCheck,
    VerificationCheckStatus,
    VerificationDiagnostic,
    VerificationPlan,
    VerificationRunStatus,
)
from khaos.coding.verification.diagnostics import DiagnosticParser
from khaos.coding.verification.evidence import VerificationEvidence, VerificationRun

RepositoryGenerationReader = Callable[[], int | Awaitable[int]]


class VerificationExecutor:
    """Run planner-selected argv through one already-composed execution owner."""

    def __init__(
        self,
        execution_service: Any,
        *,
        diagnostic_parser: DiagnosticParser | None = None,
    ) -> None:
        if execution_service is None or not callable(getattr(execution_service, "execute", None)):
            raise ValueError("VerificationExecutor requires the composed ExecutionService")
        self.execution_service = execution_service
        self.diagnostic_parser = diagnostic_parser or DiagnosticParser()

    async def execute(
        self,
        plan: VerificationPlan,
        *,
        workspace_root: Path,
        task_id: str,
        workspace: Any | None = None,
        repository_generation_reader: RepositoryGenerationReader | None = None,
        principal_id: str = "",
        project_id: str = "",
        run_id: str | None = None,
        event_sink: Any | None = None,
    ) -> VerificationRun:
        """Execute a plan with read-only, network-denied requests.

        The executor never invokes ``subprocess`` itself and never falls back
        to a host backend.  A composed ``ExecutionService`` decides whether a
        restricted backend is available; unavailable infrastructure is
        represented as a distinct negative result.
        """
        if type(plan) is not VerificationPlan or not plan.is_valid():
            raise ValueError("verification plan is invalid")
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be non-empty")
        root = Path(workspace_root).expanduser().resolve(strict=True)
        _validate_workspace_binding(root, plan, workspace)
        effective_run_id = run_id or f"m83-run-{hashlib.sha256(f'{plan.plan_id}:{time.time_ns()}'.encode()).hexdigest()[:24]}"
        started_at = time.time()
        monotonic_started = time.monotonic()
        evidence: list[VerificationEvidence] = []
        run_diagnostics: list[VerificationDiagnostic] = []
        initial_workspace_generation = _workspace_generation(workspace, plan.workspace_generation)
        initial_repository_generation = await _read_generation(repository_generation_reader, plan.repository_generation)
        stale_reason = _stale_reason(
            plan,
            workspace_generation=initial_workspace_generation,
            repository_generation=initial_repository_generation,
        )
        if stale_reason is not None:
            run_diagnostics.append(_run_diagnostic(DiagnosticCategory.INFRASTRUCTURE, stale_reason))
            return VerificationRun(
                run_id=effective_run_id,
                plan=plan,
                status=VerificationRunStatus.STALE,
                evidence=(),
                started_at=started_at,
                finished_at=time.time(),
                diagnostics=tuple(run_diagnostics),
            )

        aggregate_status = VerificationRunStatus.RUNNING
        for check in plan.checks:
            current_workspace_generation = _workspace_generation(workspace, plan.workspace_generation)
            current_repository_generation = await _read_generation(repository_generation_reader, plan.repository_generation)
            stale_reason = _stale_reason(
                plan,
                workspace_generation=current_workspace_generation,
                repository_generation=current_repository_generation,
            )
            if stale_reason is not None:
                run_diagnostics.append(_run_diagnostic(DiagnosticCategory.INFRASTRUCTURE, stale_reason))
                aggregate_status = VerificationRunStatus.STALE
                break
            remaining = plan.max_total_seconds - (time.monotonic() - monotonic_started)
            if remaining <= 0:
                aggregate_status = VerificationRunStatus.TIMED_OUT
                run_diagnostics.append(_run_diagnostic(DiagnosticCategory.TIMEOUT, "verification run exceeded its total time budget"))
                break
            check_started_at = time.time()
            await _emit(
                event_sink,
                "verification.check_started",
                {
                    "task_id": task_id,
                    "plan_id": plan.plan_id,
                    "check_id": check.check_id,
                    "stage": int(check.stage),
                    "kind": check.kind.value,
                    "command_digest": check.command_digest,
                },
            )
            try:
                result = await self._execute_check(
                    check,
                    root=root,
                    task_id=task_id,
                    workspace_id=plan.workspace_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    timeout_seconds=min(check.timeout_seconds, remaining),
                    output_limit_bytes=min(
                        check.output_limit_bytes,
                        plan.max_output_bytes,
                        65_536,
                    ),
                    run_id=effective_run_id,
                )
            except asyncio.CancelledError:
                await self._terminate(f"m83-{effective_run_id}-{check.check_id}")
                evidence.append(
                    _synthetic_evidence(
                        run_id=effective_run_id,
                        plan=plan,
                        check=check,
                        status=VerificationCheckStatus.CANCELLED,
                        category=DiagnosticCategory.INFRASTRUCTURE,
                        started_at=check_started_at,
                        finished_at=time.time(),
                    )
                )
                await _emit_evidence_events(
                    event_sink,
                    task_id=task_id,
                    plan=plan,
                    evidence=evidence[-1],
                )
                aggregate_status = VerificationRunStatus.CANCELLED
                break
            except TimeoutError:
                await self._terminate(f"m83-{effective_run_id}-{check.check_id}")
                evidence.append(
                    _synthetic_evidence(
                        run_id=effective_run_id,
                        plan=plan,
                        check=check,
                        status=VerificationCheckStatus.TIMED_OUT,
                        category=DiagnosticCategory.TIMEOUT,
                        started_at=check_started_at,
                        finished_at=time.time(),
                    )
                )
                await _emit_evidence_events(
                    event_sink,
                    task_id=task_id,
                    plan=plan,
                    evidence=evidence[-1],
                )
                run_diagnostics.append(
                    _run_diagnostic(
                        DiagnosticCategory.TIMEOUT,
                        f"verification check exceeded its timeout: {check.check_id}",
                    )
                )
                aggregate_status = VerificationRunStatus.TIMED_OUT
                break
            except Exception as exc:  # noqa: BLE001 - execution owner failures are negative evidence
                evidence.append(
                    _synthetic_evidence(
                        run_id=effective_run_id,
                        plan=plan,
                        check=check,
                        status=VerificationCheckStatus.INFRASTRUCTURE_ERROR,
                        category=DiagnosticCategory.INFRASTRUCTURE,
                        started_at=check_started_at,
                        finished_at=time.time(),
                    )
                )
                await _emit_evidence_events(
                    event_sink,
                    task_id=task_id,
                    plan=plan,
                    evidence=evidence[-1],
                )
                run_diagnostics.append(
                    _run_diagnostic(
                        DiagnosticCategory.INFRASTRUCTURE,
                        f"verification execution owner unavailable: {type(exc).__name__}",
                    )
                )
                aggregate_status = VerificationRunStatus.INFRASTRUCTURE_ERROR
                break
            evidence_item = self._evidence_from_result(
                run_id=effective_run_id,
                plan=plan,
                check=check,
                result=result,
                workspace_root=root,
                    output_limit_bytes=min(
                        check.output_limit_bytes,
                        plan.max_output_bytes,
                        65_536,
                    ),
                    started_at=check_started_at,
                    finished_at=time.time(),
                )
            evidence.append(evidence_item)
            await _emit_evidence_events(
                event_sink,
                task_id=task_id,
                plan=plan,
                evidence=evidence_item,
            )
            if evidence_item.status is not VerificationCheckStatus.PASSED:
                if evidence_item.diagnostics:
                    run_diagnostics.extend(evidence_item.diagnostics)
                if check.required:
                    aggregate_status = _run_status_for_check(evidence_item.status)
                    break
                # Optional checks improve confidence but do not turn a
                # complete required set into a completion-critical failure.
                # Keep their negative observation in the run diagnostics.

            after_workspace_generation = _workspace_generation(workspace, plan.workspace_generation)
            after_repository_generation = await _read_generation(repository_generation_reader, plan.repository_generation)
            stale_reason = _stale_reason(
                plan,
                workspace_generation=after_workspace_generation,
                repository_generation=after_repository_generation,
            )
            if stale_reason is not None:
                run_diagnostics.append(_run_diagnostic(DiagnosticCategory.INFRASTRUCTURE, stale_reason))
                aggregate_status = VerificationRunStatus.STALE
                break

        if aggregate_status is VerificationRunStatus.RUNNING:
            aggregate_status = (
                VerificationRunStatus.PASSED
                if _required_evidence_passed(plan, evidence)
                else VerificationRunStatus.UNKNOWN
            )
        return VerificationRun(
            run_id=effective_run_id,
            plan=plan,
            status=aggregate_status,
            evidence=tuple(evidence),
            started_at=started_at,
            finished_at=time.time(),
            diagnostics=tuple(_unique_diagnostics(run_diagnostics)),
        )

    async def run(self, plan: VerificationPlan, **kwargs: Any) -> VerificationRun:
        """Compatibility alias for callers that use the ``run`` vocabulary."""
        return await self.execute(plan, **kwargs)

    async def _execute_check(
        self,
        check: VerificationCheck,
        *,
        root: Path,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        timeout_seconds: float,
        output_limit_bytes: int,
        run_id: str,
    ) -> ExecutionResult:
        del principal_id, project_id
        cwd = _safe_cwd(root, check.cwd)
        request = ExecutionRequest(
            argv=check.argv,
            cwd=cwd,
            writable_roots=(),
            environment={},
            allowed_environment_keys=frozenset({"PATH", "LANG", "LC_ALL", "TMPDIR"}),
            network_policy=NetworkPolicy.NONE,
            budget=ResourceBudget(
                timeout_seconds=max(0.1, timeout_seconds),
                output_bytes=output_limit_bytes,
                cpu_time_seconds=max(0.1, timeout_seconds),
            ),
            task_id=task_id,
            workspace_id=workspace_id,
            access_mode="read-only",
            correlation_id=f"m83-{run_id}-{check.check_id}",
        )
        return await asyncio.wait_for(
            self.execution_service.execute(request),
            timeout=max(0.1, timeout_seconds) + 1.0,
        )

    async def _terminate(self, execution_id: str) -> None:
        terminate = getattr(self.execution_service, "terminate", None)
        if not callable(terminate):
            return
        try:
            outcome = terminate(execution_id)
            if inspect.isawaitable(outcome):
                await outcome
        except Exception:  # noqa: BLE001 - cancellation cleanup must not mask cancellation
            # Cancellation remains a negative observation even if the
            # execution owner cannot prove a matching process identity.
            return

    def _evidence_from_result(
        self,
        *,
        run_id: str,
        plan: VerificationPlan,
        check: VerificationCheck,
        result: ExecutionResult,
        workspace_root: Path,
        output_limit_bytes: int,
        started_at: float,
        finished_at: float,
    ) -> VerificationEvidence:
        stdout, stdout_truncated = _bounded_output(result.stdout, output_limit_bytes)
        stderr, stderr_truncated = _bounded_output(result.stderr, output_limit_bytes)
        status = _status_from_execution(result, check)
        diagnostics: tuple[VerificationDiagnostic, ...] = ()
        if status is not VerificationCheckStatus.PASSED:
            diagnostics = self.diagnostic_parser.parse(
                check,
                stdout=stdout,
                stderr=stderr,
                workspace_root=workspace_root,
                related_paths=check.target_paths,
            )
        result_diagnostics = getattr(result, "diagnostics", {})
        if not isinstance(result_diagnostics, Mapping):
            result_diagnostics = {}
        output_truncated = stdout_truncated or stderr_truncated or any(
            type(result_diagnostics.get(name)) is bool
            and result_diagnostics.get(name) is True
            for name in ("output_truncated", "stdout_truncated", "stderr_truncated")
        )
        return VerificationEvidence(
            run_id=run_id,
            plan_id=plan.plan_id,
            check_id=check.check_id,
            workspace_id=plan.workspace_id,
            workspace_generation=plan.workspace_generation,
            repository_generation=plan.repository_generation,
            command_digest=check.command_digest,
            status=status,
            exit_code=result.return_code,
            duration_ms=max(0, int(result.duration_ms)),
            stdout_digest=_sha256(stdout),
            stderr_digest=_sha256(stderr),
            output_truncated=output_truncated,
            diagnostics=diagnostics,
            started_at=started_at,
            finished_at=finished_at,
        )


def _safe_cwd(root: Path, relative: str) -> Path:
    candidate = root if relative == "." else root / PurePosixPath(relative)
    resolved = candidate.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise PermissionError("verification cwd escapes the workspace")
    if not resolved.is_dir():
        raise PermissionError("verification cwd is not a directory")
    return resolved


def _validate_workspace_binding(
    root: Path,
    plan: VerificationPlan,
    workspace: Any | None,
) -> None:
    """Require an injected active workspace to match the immutable plan."""
    if workspace is None:
        return
    active_workspace_id = getattr(workspace, "id", None)
    if (
        active_workspace_id not in (None, "")
        and active_workspace_id != plan.workspace_id
    ):
        raise PermissionError("verification workspace identity does not match the plan")
    active_root = getattr(workspace, "worktree_path", None)
    if active_root is None:
        return
    try:
        resolved_active_root = Path(active_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PermissionError("active verification workspace path is unavailable") from exc
    if resolved_active_root != root:
        raise PermissionError("verification workspace path does not match the active workspace")


def _workspace_generation(workspace: Any | None, fallback: int) -> int:
    value = getattr(workspace, "generation", fallback) if workspace is not None else fallback
    if type(value) is not int or value < 0:
        raise ValueError("workspace generation is invalid")
    return value


async def _read_generation(reader: RepositoryGenerationReader | None, fallback: int) -> int:
    if reader is None:
        return fallback
    value = reader()
    if inspect.isawaitable(value):
        value = await value
    generation = getattr(value, "generation", None)
    if generation is not None:
        value = generation
    if type(value) is not int or value < 0:
        raise ValueError("repository generation reader returned an invalid value")
    return value


def _stale_reason(
    plan: VerificationPlan,
    *,
    workspace_generation: int,
    repository_generation: int,
) -> str | None:
    if workspace_generation != plan.workspace_generation:
        return "workspace generation changed after plan creation"
    if repository_generation != plan.repository_generation:
        return "repository intelligence generation changed after plan creation"
    return None


def _status_from_execution(result: ExecutionResult, check: VerificationCheck) -> VerificationCheckStatus:
    status = str(result.status or "").casefold().replace("-", "_")
    if status in {"timed_out", "timeout", "timedout"}:
        return VerificationCheckStatus.TIMED_OUT
    if status in {"cancelled", "canceled", "aborted"}:
        return VerificationCheckStatus.CANCELLED
    if status in {"stale"}:
        return VerificationCheckStatus.STALE
    if status in {
        "unsupported",
        "unavailable",
        "infrastructure_error",
        "infra_error",
        "resource_exhausted",
    }:
        return VerificationCheckStatus.INFRASTRUCTURE_ERROR
    if status in {"passed", "success", "completed"}:
        if result.return_code in check.expected_exit_codes:
            return VerificationCheckStatus.PASSED
        if result.return_code is None:
            return VerificationCheckStatus.UNKNOWN
        return VerificationCheckStatus.FAILED
    if status in {"failed", "error", "nonzero", "exit_nonzero"}:
        return VerificationCheckStatus.FAILED
    return VerificationCheckStatus.UNKNOWN


def _run_status_for_check(status: VerificationCheckStatus) -> VerificationRunStatus:
    return {
        VerificationCheckStatus.FAILED: VerificationRunStatus.FAILED,
        VerificationCheckStatus.TIMED_OUT: VerificationRunStatus.TIMED_OUT,
        VerificationCheckStatus.CANCELLED: VerificationRunStatus.CANCELLED,
        VerificationCheckStatus.STALE: VerificationRunStatus.STALE,
        VerificationCheckStatus.INFRASTRUCTURE_ERROR: VerificationRunStatus.INFRASTRUCTURE_ERROR,
        VerificationCheckStatus.UNKNOWN: VerificationRunStatus.UNKNOWN,
        VerificationCheckStatus.PASSED: VerificationRunStatus.PASSED,
    }[status]


def _required_evidence_passed(plan: VerificationPlan, evidence: list[VerificationEvidence]) -> bool:
    if not plan.required_checks:
        return False
    by_id = {item.check_id: item for item in evidence}
    return all(
        by_id.get(check.check_id) is not None
        and by_id[check.check_id].status is VerificationCheckStatus.PASSED
        and not by_id[check.check_id].output_truncated
        for check in plan.required_checks
    )


def _synthetic_evidence(
    *,
    run_id: str,
    plan: VerificationPlan,
    check: VerificationCheck,
    status: VerificationCheckStatus,
    category: DiagnosticCategory,
    started_at: float = 0.0,
    finished_at: float = 0.0,
) -> VerificationEvidence:
    return VerificationEvidence(
        run_id=run_id,
        plan_id=plan.plan_id,
        check_id=check.check_id,
        workspace_id=plan.workspace_id,
        workspace_generation=plan.workspace_generation,
        repository_generation=plan.repository_generation,
        command_digest=check.command_digest,
        status=status,
        exit_code=None,
        duration_ms=0,
        stdout_digest=_sha256(""),
        stderr_digest=_sha256(""),
        output_truncated=False,
        diagnostics=(_run_diagnostic(category, status.value),),
        started_at=started_at,
        finished_at=finished_at,
    )


def _run_diagnostic(category: DiagnosticCategory, message: str) -> VerificationDiagnostic:
    severity = DiagnosticSeverity.ERROR
    if category is DiagnosticCategory.UNSTRUCTURED:
        severity = DiagnosticSeverity.INFO
    return VerificationDiagnostic(category, severity, message, source="executor")


def _bounded_output(value: object, limit: int) -> tuple[str, bool]:
    if not isinstance(value, str):
        return "", bool(value)
    encoded = value.encode("utf-8", errors="replace")
    return encoded[:limit].decode("utf-8", errors="replace"), len(encoded) > limit


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


async def _emit(sink: Any | None, event: str, payload: dict[str, object]) -> None:
    """Emit bounded observation metadata without affecting execution."""
    if sink is None:
        return
    emitter = getattr(sink, "emit", None)
    if not callable(emitter):
        return
    try:
        result = emitter(event, payload)
        if inspect.isawaitable(result):
            await result
    except Exception:  # noqa: BLE001 - observability cannot affect execution
        return


async def _emit_evidence_events(
    sink: Any | None,
    *,
    task_id: str,
    plan: VerificationPlan,
    evidence: VerificationEvidence,
) -> None:
    """Emit one check outcome and digest-only diagnostics."""
    status_event = {
        "passed": "verification.check_passed",
        "failed": "verification.check_failed",
        "timed_out": "verification.check_timeout",
        "cancelled": "verification.check_failed",
        "stale": "verification.check_failed",
        "infrastructure_error": "verification.check_failed",
        "unknown": "verification.check_failed",
    }.get(evidence.status.value, "verification.check_failed")
    await _emit(
        sink,
        status_event,
        {
            "task_id": task_id,
            "plan_id": plan.plan_id,
            "check_id": evidence.check_id,
            "status": evidence.status.value,
            "command_digest": evidence.command_digest,
            "output_truncated": evidence.output_truncated,
        },
    )
    for diagnostic in evidence.diagnostics:
        await _emit(
            sink,
            "verification.diagnostic_parsed",
            {
                "task_id": task_id,
                "plan_id": plan.plan_id,
                "check_id": evidence.check_id,
                "category": diagnostic.category.value,
                "severity": diagnostic.severity.value,
                "path": diagnostic.path,
                "line": diagnostic.line,
                "column": diagnostic.column,
                "message_digest": _sha256(diagnostic.message),
            },
        )


def _unique_diagnostics(values: list[VerificationDiagnostic]) -> tuple[VerificationDiagnostic, ...]:
    unique: dict[tuple[object, ...], VerificationDiagnostic] = {}
    for value in values:
        unique.setdefault((value.category.value, value.path, value.line, value.column, value.message), value)
    return tuple(unique.values())[:64]


__all__ = ["RepositoryGenerationReader", "VerificationExecutor"]
