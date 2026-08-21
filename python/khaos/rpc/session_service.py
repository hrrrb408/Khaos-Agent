"""Session RPC application service.

The JSON-line transport owns authentication and framing.  This service owns
only the durable session read model and always applies the caller's
``RequestContext`` when querying it.
"""

from __future__ import annotations

from khaos.db import Database
from khaos.runtime import RequestContext


class SessionService:
    """Read the durable sessions visible to one authenticated principal."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def list(
        self,
        ctx: RequestContext,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """List the caller's sessions newest-first.

        An empty principal is deliberately passed as ``""`` rather than
        ``None``.  ``None`` is the database API's explicit administrator
        opt-in and must never be reachable from an unauthenticated RPC.
        """
        principal_id = ctx.principal_id or ""
        rows = await self.db.list_sessions(
            limit,
            offset,
            principal_id=principal_id,
            project_id=ctx.project_id,
        )
        return [dict(row) for row in rows]

    async def get(
        self,
        ctx: RequestContext,
        session_id: str,
        message_limit: int = 50,
    ) -> dict[str, object]:
        """Return one session and its messages within the caller's scope.

        Cross-principal access has the same response shape as a missing
        session so callers cannot enumerate another principal's identifiers.
        """
        principal_id = ctx.principal_id or ""
        session = await self.db.get_session(
            session_id,
            principal_id=principal_id,
            project_id=ctx.project_id,
        )
        if session is None:
            return {
                "ok": False,
                "error": "session not found",
                "session_id": session_id,
            }
        messages = await self.db.get_session_messages(
            session_id,
            limit=message_limit,
            offset=0,
            principal_id=principal_id,
            project_id=ctx.project_id,
        )
        return {
            "ok": True,
            "session": session,
            "messages": [dict(message) for message in messages],
        }


__all__ = ["SessionService"]
