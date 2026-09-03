"""Adapter that runs a real Khaos AgentLoop for M8.0 scenarios."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from khaos.agent import AgentConfig
from khaos.coding.execution import BackendSelector, ExecutionService, ProcessSupervisor
from khaos.coding.intelligence.query_service import ContextIntelligenceService
from khaos.coding.workspace import WorkspaceManager
from khaos.evaluation.coding.contracts import CodingScenario
from khaos.evaluation.coding.fixtures import MaterializedFixture
from khaos.evaluation.coding.metrics import CodingTraceCollector
from khaos.evaluation.coding.oracle import OracleError, ReviewFinding
from khaos.evaluation.coding.results import AgentExecution
from khaos.modes import ModeManager
from khaos.runtime import (
    RuntimeConfig,
    RuntimeProfile,
    build_runtime,
    close_runtime_or_register,
)

_REVIEW_TOOL_ALLOWLIST = (
    "read_file",
    "search_files",
    "list_directory",
    "file_info",
    "tree_view",
    "file_search_content",
    "code_search",
    "code_symbols",
    "git_diff",
    "git_log",
    "git_status",
    "git_pr_body",
)


class RuntimeCodingAgentInvoker:
    """Use the production AgentLoop composition with an explicit test/dev profile.

    The model router is supplied by the caller.  This class has no fake agent
    implementation and does not mutate the fixture outside normal Khaos tools.
    """

    def __init__(
        self,
        database: Any,
        router: Any,
        *,
        principal_id: str = "evaluation",
        project_id: str = "coding-evaluation",
        model: str = "unknown",
        provider: str = "unknown",
        confirm_callback: Any = None,
        agent_config: AgentConfig | None = None,
    ) -> None:
        self.database = database
        self.router = router
        self.principal_id = principal_id
        self.project_id = project_id
        self.model = model
        self.provider = provider
        self.confirm_callback = confirm_callback or (lambda _request: {"approved": True})
        self.agent_config = agent_config

    async def run(
        self,
        scenario: CodingScenario,
        fixture: MaterializedFixture,
        trace: CodingTraceCollector,
    ) -> AgentExecution:
        runtime_id = f"m8-runtime-{uuid.uuid4().hex}"
        session_id = f"m8-session-{uuid.uuid4().hex}"
        await self.database.create_session(
            session_id,
            "coding",
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        mode_manager = ModeManager(
            self.database,
            project_root=fixture.agent_root,
            principal_id=self.principal_id,
            session_id=session_id,
            project_id=self.project_id,
        )
        await mode_manager.load()
        # The fixture is the model-controlled project root; the immutable
        # Khaos coding prompt remains an application-owned input and is not
        # copied into or sourced from the evaluated repository.
        prompt_root = Path(__file__).resolve().parents[4]
        mode_manager.project_root = prompt_root
        workspace_manager = WorkspaceManager(
            root=fixture._private_root / "worktrees",
            runtime_profile=RuntimeProfile.TESTING,
            principal_id=self.principal_id,
            principal_kind="human",
            parent_principal_id=f"human:{self.principal_id}",
            delegation_digest="a" * 64,
            project_id=self.project_id,
            runtime_id=runtime_id,
            session_id=session_id,
            source_transport="test",
        )
        backend_selector = BackendSelector(
            runtime_profile=RuntimeProfile.TESTING,
        )
        execution_service = ExecutionService(
            process_supervisor=ProcessSupervisor(runtime_profile=RuntimeProfile.TESTING),
            backend_selector=backend_selector,
            workspace_manager=workspace_manager,
            principal_id=self.principal_id,
            project_id=self.project_id,
            runtime_id=runtime_id,
            runtime_profile=RuntimeProfile.TESTING,
        )
        # M8.0 must exercise the production-shaped repository-intelligence
        # facade, including its generation-bound index and metrics.  This is
        # an explicit testing composition seam; production composition is
        # still owned by build_runtime and cannot receive this injection.
        context_intelligence = ContextIntelligenceService(
            workspace_manager,
            index_database=fixture._private_root / "repo-intelligence.db",
        )
        runtime = await build_runtime(
            RuntimeConfig(
                project_root=fixture.agent_root,
                profile=RuntimeProfile.TESTING,
                mode_override="coding",
                confirm_callback=self.confirm_callback,
                db=self.database,
                router=self.router,
                mode_manager=mode_manager,
                workspace_manager=workspace_manager,
                execution_service=execution_service,
                context_intelligence=context_intelligence,
                principal_id=self.principal_id,
                principal_kind="human",
                parent_principal_id=f"human:{self.principal_id}",
                delegation_digest="a" * 64,
                source_transport="test",
                foreground_session=True,
                session_id=session_id,
                runtime_id=runtime_id,
                project_id=self.project_id,
                agent_config=replace(
                    self.agent_config or AgentConfig(),
                    max_turns=min(
                        (self.agent_config or AgentConfig()).max_turns,
                        scenario.limits.max_model_turns,
                    ),
                    stream_timeout=min(
                        (self.agent_config or AgentConfig()).stream_timeout,
                        max(1, int(scenario.limits.timeout_seconds)),
                    ),
                ),
                tool_allowlist=(
                    list(_REVIEW_TOOL_ALLOWLIST)
                    if scenario.kind.value == "CODE_REVIEW"
                    else None
                ),
            )
        )
        status = "ERROR"
        completion_status: str | None = None
        error: str | None = None
        assistant_outputs: list[str] = []
        assistant_output_bytes = 0
        try:
            async for message in runtime.loop.run(scenario.user_prompt, session_id):
                trace.record_message(message)
                if getattr(message, "role", "") == "assistant":
                    content = getattr(message, "content", "")
                    if isinstance(content, str) and content:
                        remaining = max(0, scenario.limits.max_output_bytes - assistant_output_bytes)
                        if remaining:
                            bounded = content[:remaining]
                            assistant_outputs.append(bounded)
                            assistant_output_bytes += len(bounded.encode("utf-8"))
                if message.event == "error":
                    status = "ERROR"
                    error = str(message.metadata.get("message") or "agent loop error")[:1024]
                elif message.event == "done":
                    completion_status = str(message.metadata.get("terminal_status") or "completed")
                    status = "COMPLETED"
            if status != "COMPLETED" and error is None:
                error = "agent loop ended without a done event"
        except asyncio.CancelledError:
            active_workspace = runtime.loop.active_workspace
            if active_workspace is not None:
                await workspace_manager.cleanup(active_workspace.id, force=True)
            try:
                await workspace_manager.close()
            finally:
                await close_runtime_or_register(runtime)
            raise
        except Exception as exc:  # noqa: BLE001 - adapter boundary converts runtime failures to evidence
            status = "ERROR"
            error = _safe_error(exc)
        repository_metrics = getattr(runtime.loop, "repo_intelligence", None)
        snapshot = getattr(repository_metrics, "metrics_snapshot", None)
        if callable(snapshot):
            trace.record_repository_metrics(snapshot())
        context_engine = getattr(runtime.loop, "context_engine", None)
        context_snapshot = getattr(context_engine, "metrics_snapshot", None)
        if callable(context_snapshot):
            trace.record_context_metrics(context_snapshot())
        active_workspace = runtime.loop.active_workspace
        final_root = (
            active_workspace.worktree_path
            if active_workspace is not None
            else fixture.agent_root
        )
        task_id = getattr(runtime.loop, "_active_task_id", None)
        workspace_id = getattr(active_workspace, "id", None)
        review_findings = (
            _extract_review_findings(assistant_outputs)
            if scenario.kind.value == "CODE_REVIEW"
            else ()
        )

        async def cleanup() -> None:
            if active_workspace is not None:
                await workspace_manager.cleanup(active_workspace.id, force=True)
            try:
                await workspace_manager.close()
            finally:
                await close_runtime_or_register(runtime)

        return AgentExecution(
            status=status,
            completion_status=completion_status,
            final_root=Path(final_root),
            runtime_id=runtime_id,
            model=self.model,
            provider=self.provider,
            review_findings=review_findings,
            error=error,
            task_id=task_id,
            workspace_id=workspace_id,
            cleanup=cleanup,
        )


def _safe_error(exc: BaseException) -> str:
    message = str(exc).strip().replace("\n", " ")
    return (message or type(exc).__name__)[:1024]


def _extract_review_findings(outputs: list[str]) -> tuple[ReviewFinding, ...]:
    """Parse bounded JSON review output without retaining natural-language text."""

    for raw in reversed(outputs):
        candidates = [raw.strip()]
        fenced = re.search(r"```(?:json)?\s*(.*?)```", raw, flags=re.DOTALL | re.IGNORECASE)
        if fenced is not None:
            candidates.insert(0, fenced.group(1).strip())
        for candidate in candidates:
            if len(candidate.encode("utf-8")) > 64 * 1024:
                continue
            try:
                value = json.loads(candidate)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            raw_findings = value.get("findings") if isinstance(value, dict) else value
            if not isinstance(raw_findings, list) or len(raw_findings) > 128:
                continue
            findings: list[ReviewFinding] = []
            for item in raw_findings:
                if not isinstance(item, dict):
                    continue
                try:
                    findings.append(ReviewFinding.from_mapping(item))
                except OracleError:
                    continue
            return tuple(findings)
    return ()


__all__ = ["RuntimeCodingAgentInvoker"]
