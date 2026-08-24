"""Trust-Kernel audit adapter for Memory V2.

Memory providers may emit their own telemetry, but Broker decisions must be
written by the injected Khaos ``AuditLogger``/``BoundAuditLogger``.  This
adapter deliberately exposes only the small port needed by the Broker.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from khaos.memory.core.contracts import RuntimeMemoryContext


class TrustKernelMemoryAuditSink:
    """Write memory decisions through the existing Khaos audit authority."""

    def __init__(self, audit_logger: Any, *, required: bool = True) -> None:
        self._audit_logger = audit_logger
        self._required = required

    async def log_decision(
        self,
        action: str,
        runtime: RuntimeMemoryContext,
        *,
        memory_id: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Persist one Broker decision with runtime attribution."""

        if self._audit_logger is None:
            if self._required:
                raise RuntimeError("Memory V2 requires the Khaos audit logger")
            return
        result = "error" if "FAILED" in action or "REJECTED" in action else "success"
        payload = dict(detail or {})
        if memory_id:
            payload.setdefault("memory_id", memory_id)
        logger = self._bound_logger(runtime)
        await logger.log(
            action,
            memory_id or "memory",
            result,
            payload,
            runtime.session_id,
            task_id=runtime.task_id,
            source_transport=runtime.environment.get("source_transport")
            if isinstance(runtime.environment, Mapping)
            else None,
        )

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Expose the standard audit port for direct integration tests."""

        del target
        if self._audit_logger is None:
            if self._required:
                raise RuntimeError("Memory V2 requires the Khaos audit logger")
            return 0
        return await self._audit_logger.log(
            action,
            "memory",
            result,
            detail,
            session_id,
            task_id=task_id,
            source_transport=source_transport,
        )

    def _bound_logger(self, runtime: RuntimeMemoryContext) -> Any:
        """Bind a root Trust-Kernel logger to the current runtime identity."""

        bind = getattr(self._audit_logger, "bind", None)
        if not callable(bind):
            return self._audit_logger
        environment = runtime.environment
        return bind(
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            policy_digest=getattr(self._audit_logger, "policy_digest", None),
            runtime_id=(
                str(environment.get("runtime_id"))
                if isinstance(environment, Mapping) and environment.get("runtime_id")
                else None
            ),
            source_transport=(
                str(environment.get("source_transport"))
                if isinstance(environment, Mapping) and environment.get("source_transport")
                else None
            ),
        )


class DurableMemoryAuditSink:
    """Minimal local sink for explicitly unbound test/maintenance brokers.

    Production composition injects :class:`TrustKernelMemoryAuditSink`.  This
    fallback only keeps direct SQLite provider tests observable; it is not an
    authority and is never selected when the production audit requirement is
    enabled.
    """

    def __init__(self, database: Any) -> None:
        self._database = database

    async def log_decision(
        self,
        action: str,
        runtime: RuntimeMemoryContext,
        *,
        memory_id: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        payload = dict(detail or {})
        if memory_id:
            payload.setdefault("memory_id", memory_id)
        async with self._database.transaction() as conn:
            await conn.execute(
                "INSERT INTO memory_audit (action, memory_id, provider_id, "
                "principal_id, project_id, session_id, detail_json, created_at) "
                "VALUES (?, ?, '', ?, ?, ?, ?, datetime('now'))",
                (
                    action,
                    memory_id,
                    runtime.principal_id,
                    runtime.project_id,
                    runtime.session_id or "",
                    _json(payload),
                ),
            )

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        source_transport: str | None = None,
    ) -> int:
        del target, result, task_id, source_transport
        runtime = RuntimeMemoryContext(
            principal_id="unbound",
            project_id="unbound",
            session_id=session_id,
            task_id=None,
            workspace_id=None,
            mode="maintenance",
        )
        await self.log_decision(action, runtime, detail=detail)
        return 0


def _json(value: Mapping[str, Any]) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


MemoryAuditSinkAdapter = TrustKernelMemoryAuditSink

__all__ = [
    "DurableMemoryAuditSink",
    "MemoryAuditSinkAdapter",
    "TrustKernelMemoryAuditSink",
]
