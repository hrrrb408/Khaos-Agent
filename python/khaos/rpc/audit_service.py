"""Audit-log RPC application service."""

from __future__ import annotations

from khaos.audit import AuditLogger
from khaos.runtime import RequestContext


class AuditService:
    """Query audit records within the authenticated principal's scope."""

    def __init__(self, logger: AuditLogger) -> None:
        self.logger = logger

    async def query(
        self,
        ctx: RequestContext,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        """Return newest audit entries visible to ``ctx.principal_id``."""
        entries = await self.logger.query(
            action=action,
            result=result,
            since=since,
            until=until,
            limit=limit,
            principal_id=ctx.principal_id,
        )
        return [entry.to_dict() for entry in entries]


__all__ = ["AuditService"]
