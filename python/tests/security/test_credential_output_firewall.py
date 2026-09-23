"""Synthetic canary coverage for credential output boundaries."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import khaos.audit.logger as audit_module
import pytest
from khaos.agent.core import AgentLoop, Message
from khaos.audit import AuditLogger
from khaos.db import Database
from khaos.evaluation.coding import (
    BenchmarkRunConfig,
    CodingBenchmarkJsonlWriter,
    CodingBenchmarkResultV1,
    CodingResultState,
    load_builtin_manifest,
)
from khaos.memory.audit import DurableMemoryAuditSink
from khaos.memory.core.contracts import RuntimeMemoryContext
from khaos.memory.events import MemoryEventBridge
from khaos.security.credentials import SecretValue
from khaos.security.middleware import SecurityMiddleware
from khaos.security.secret_redaction import SecretRedactor
from khaos.supervision.contracts import SupervisionEventType
from khaos.supervision.service import TaskSupervisionService
from khaos.tools.result_finalizer import ToolResultFinalizer
from khaos.tools.scheduler_models import ToolResult


class _MemoryEventSink:
    def __init__(self, redactor: SecretRedactor) -> None:
        self.secret_redactor = redactor
        self.events = []

    async def record_event(self, event):
        self.events.append(event)
        return event.event_id


class _OperationStore:
    def __init__(self) -> None:
        self.finished = None
        self.stored = None

    async def finish(self, claim, result, *, terminal_status):
        del claim, terminal_status
        self.finished = result
        return result

    async def put_result(self, call, *, session_id, tool_context, result):
        del call, session_id, tool_context
        self.stored = result


class _UntrustedObject:
    def __str__(self) -> str:
        return "untrusted-object-should-not-be-stringified"


async def _database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "khaos.db")
    await database.connect()
    await database.run_migrations()
    return database


def _assert_secretless(values: list[object], canary: str) -> None:
    serialized = "\n".join(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        for value in values
    )
    assert canary not in serialized


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_synthetic_canary_crosses_all_runtime_output_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = f"synthetic-output-{secrets.token_urlsafe(18)}"
    redactor = SecretRedactor()
    redactor.register(SecretValue(canary))
    cyclic: list[object] = []
    cyclic.append(cyclic)
    assert redactor.redact({"unknown": _UntrustedObject()})[
        "unknown"
    ] == "[REDACTED_UNSUPPORTED_OUTPUT]"
    assert redactor.redact(cyclic) == [["[REDACTED_UNSUPPORTED_OUTPUT]"]]

    stdout = redactor.redact_text(f"stdout: {canary}")
    stderr = redactor.redact_text(f"stderr: {canary}")
    provider_error = redactor.safe_error(RuntimeError(f"provider: {canary}"))
    assert canary not in stdout
    assert canary not in stderr
    assert canary not in provider_error

    middleware = SecurityMiddleware(secret_redactor=redactor)
    _scan, browser_diagnostic = await middleware.post_check(
        "browser_observe",
        {"stdout": stdout, "stderr": stderr, "app_diagnostic": canary},
    )
    assert canary not in json.dumps(browser_diagnostic, default=str)

    operation_store = _OperationStore()
    finalizer = ToolResultFinalizer(
        audit_writer=None,
        operation_store=operation_store,
        secret_redactor=redactor,
    )
    result = await finalizer.finish_and_store(
        None,
        ToolResult(
            tool_call_id="synthetic-call",
            name="synthetic-tool",
            success=False,
            output={"stdout": canary},
            error=f"tool error: {canary}",
            warning=f"warning: {canary}",
            reconciliation_hint=f"hint: {canary}",
            arguments={"authorization": canary},
        ),
        terminal_status="failed",
        call={},
        session_id="synthetic-session",
        tool_context={},
    )
    _assert_secretless([result.__dict__, operation_store.finished.__dict__], canary)
    _assert_secretless([operation_store.stored.__dict__], canary)

    trusted_audit_dir = tmp_path / ".khaos" / "audit"
    monkeypatch.setattr(audit_module, "AUDIT_LOG_TRUSTED_DIR", trusted_audit_dir)
    database = await _database(tmp_path)
    audit = AuditLogger(
        database,
        log_path="synthetic-events.jsonl",
        secret_redactor=redactor,
    )
    try:
        await audit.log(
            f"tool-{canary}",
            f"target-{canary}",
            "error",
            {"detail": canary, canary: canary},
            session_id=None,
            source_transport=f"Bearer {canary}",
        )
        async with database.read_connection() as connection:
            audit_rows = await (
                await connection.execute(
                    "SELECT action, target, result, detail FROM audit_log"
                )
            ).fetchall()
        audit_file = (trusted_audit_dir / "synthetic-events.jsonl").read_text(
            encoding="utf-8"
        )
        _assert_secretless(
            [tuple(row) for row in audit_rows] + [audit_file], canary
        )

        memory_sink = DurableMemoryAuditSink(
            database, secret_redactor=redactor
        )
        runtime = RuntimeMemoryContext(
            principal_id="synthetic-principal",
            project_id="synthetic-project",
            session_id="synthetic-session",
            task_id="synthetic-task",
            workspace_id="synthetic-workspace",
            mode="coding",
        )
        await memory_sink.log_decision(
            "MEMORY_FAILED",
            runtime,
            detail={"failure": canary},
        )

        memory_broker = _MemoryEventSink(redactor)
        bridge = MemoryEventBridge(memory_broker)
        memory_event = await bridge.tool_result(
            runtime,
            output=canary,
            error=f"failure-memory: {canary}",
        )
        assert canary not in json.dumps(memory_event.payload, default=str)

        supervision = TaskSupervisionService(
            database,
            secret_redactor=redactor,
        )
        for event_type, payload in (
            (SupervisionEventType.TASK_STARTED, {"goal": canary}),
            (SupervisionEventType.CHECKPOINT_CREATED, {"checkpoint": canary}),
            (SupervisionEventType.SUBAGENT_PROGRESS, {"diagnostic": canary}),
        ):
            await supervision.emit(
                task_id="synthetic-task",
                workspace_id="synthetic-workspace",
                principal_id="synthetic-principal",
                project_id="synthetic-project",
                event_type=event_type,
                payload=payload,
            )
        for event_type in (
            SupervisionEventType.MCP_CONNECTED,
            SupervisionEventType.HOOK_COMPLETED,
        ):
            await supervision.emit_extension_event(
                task_id="synthetic-task",
                workspace_id="synthetic-workspace",
                principal_id="synthetic-principal",
                project_id="synthetic-project",
                event_type=event_type,
                extension_id="synthetic-extension",
                payload={"extension_diagnostic": canary},
            )

        loop = object.__new__(AgentLoop)
        loop.db = database
        loop.principal_id = "synthetic-principal"
        loop.project_id = "synthetic-project"
        loop.secret_redactor = redactor
        loop.memory_manager = None
        await database.create_session(
            "synthetic-session",
            "coding",
            principal_id="synthetic-principal",
            project_id="synthetic-project",
        )
        await loop._persist_message(
            "synthetic-session",
            Message(
                role="tool",
                content=canary,
                tool_calls=[{"diagnostic": canary}],
                metadata={"provider_error": canary},
            ),
        )

        async with database.read_connection() as connection:
            persisted_rows = await (
                await connection.execute(
                    "SELECT content, tool_calls FROM messages"
                )
            ).fetchall()
            memory_rows = await (
                await connection.execute(
                    "SELECT detail_json FROM memory_audit"
                )
            ).fetchall()
            supervision_rows = await (
                await connection.execute(
                    "SELECT payload_json, '' FROM task_supervision_events "
                    "UNION ALL SELECT '', state_json FROM task_supervision_states"
                )
            ).fetchall()
        _assert_secretless(
            [tuple(row) for row in persisted_rows]
            + [tuple(row) for row in memory_rows]
            + [tuple(row) for row in supervision_rows],
            canary,
        )

        manifest = load_builtin_manifest()
        scenario = manifest.get("bugfix-python-cache")
        config = BenchmarkRunConfig(
            provider="synthetic-provider",
            model="synthetic-model",
            khaos_sha="a" * 64,
            scenario_manifest_digest=manifest.digest,
            config_digest="b" * 64,
        )
        benchmark_result = CodingBenchmarkResultV1(
            run_id="synthetic-firewall-run",
            result_state=CodingResultState.FAILURE,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            scenario_digest=scenario.digest,
            scenario_kind=scenario.kind,
            difficulty=scenario.difficulty,
            languages=scenario.languages,
            repository_base_revision="synthetic-base",
            config=config,
            started_at="2026-09-12T00:00:00+00:00",
            finished_at="2026-09-12T00:00:01+00:00",
            metrics={"provider_error": canary, "nested": {"stderr": canary}},
        )
        result_path = tmp_path / "synthetic-results.jsonl"
        await CodingBenchmarkJsonlWriter(
            result_path,
            secret_redactor=redactor,
        ).append(benchmark_result)
        jsonl = result_path.read_text(encoding="utf-8")
        _assert_secretless([jsonl], canary)
        persisted_payload = json.loads(jsonl)
        assert persisted_payload["result_digest"] != benchmark_result.result_digest
        assert persisted_payload["metrics"]["provider_error"] != canary
    finally:
        audit.close()
        await database.close()
