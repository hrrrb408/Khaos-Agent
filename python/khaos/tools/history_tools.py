"""Tools for session history search.

M4 batch 3.1.16A-4-4-2: the module-global ``_session_search`` holder
and the ``set_session_search`` setter have been removed.

Background — why the holder was problematic:

  ``set_session_search`` was *never* called from production code —
  ``grpc_server.py`` / ``runtime/factory.py`` / ``cli/main.py`` all
  omitted the call, so every handler returned
  ``{"status": "unavailable", ...}`` in production.  The handlers were
  effectively dead code.  Worse, even if someone had wired it up, the
  holder would have shared one ``SessionSearch`` instance across all
  principals — and since ``SessionSearch`` is now principal-scoped
  (A-4-3), that single instance could only ever serve one principal.
  Any second principal would either see the first principal's history
  (if the instance was non-scoped) or get empty results (if it was
  scoped to the other principal).

Closure — per-call construction (mirrors the cron_tools /
orchestrator_tools / permission_tools pattern):

  Every handler now receives ``principal_id`` and ``db`` as keyword
  arguments injected by :class:`ToolInvocationBroker` via the new
  ``history.read`` capability declared in ``registry.py``.  Each call
  constructs a fresh ``SessionSearch(db, principal_id=principal_id)``
  instance — ``SessionSearch.__init__`` is just two attribute stores,
  so this is cheaper than maintaining a holder.  No module-global
  state, no cross-principal leak, no "unavailable" dead code.

Fail-closed semantics:

  Empty ``principal_id`` is rejected by ``_require_principal``.  A
  missing ``db`` returns ``{"status": "unavailable", ...}`` (mirrors
  the original "not configured" behavior) so a misconfigured tool
  context fails gracefully rather than crashing.
"""

from __future__ import annotations

import logging
from typing import Any

from khaos.session import SessionSearch

logger = logging.getLogger(__name__)


def _require_principal(principal_id: str) -> dict[str, Any] | None:
    """Return an ``ok=false`` error dict if ``principal_id`` is empty,
    else ``None``.

    M4 batch 3.1.16A-4-4-2: history tools must not fall open to an
    unscoped query when the caller's principal is missing — that would
    let a misconfigured tool context return every principal's session
    history.  Empty principal is rejected (mirrors
    ``cron_tools._require_principal`` / ``permission_tools._require_principal``).
    """
    if not principal_id:
        return {"status": "unavailable", "error": "principal_id is required", "results": []}
    return None


def _build_search(principal_id: str, db: Any) -> SessionSearch | None:
    """Construct a principal-scoped ``SessionSearch`` for this call.

    Returns ``None`` when ``db`` is missing — callers translate this
    into the "not configured" unavailable response so a misconfigured
    tool context fails gracefully instead of crashing.
    """
    if db is None:
        return None
    return SessionSearch(db, principal_id=principal_id)


async def history_search(
    query: str,
    limit: int = 10,
    *,
    principal_id: str = "",
    db: Any = None,
    **kwargs: Any,
) -> dict:
    """Search past session history using full-text search.

    Args:
        query: FTS5 query (supports AND/OR/NOT, quoted phrases, prefix
            wildcards).
        limit: Maximum results to return (default 10).
        principal_id: Caller's principal ID (injected by broker via the
            ``history.read`` capability).  Required — the search is
            scoped to this principal's owned sessions/messages.
        db: Database instance (injected by broker from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    search = _build_search(principal_id, db)
    if search is None:
        return {"status": "unavailable", "error": "session search not configured", "results": []}
    results = await search.search(query, limit=limit)
    return {
        "query": query,
        "results": [
            {
                "session_id": r.session_id,
                "snippet": r.snippet,
                "role": r.role,
                "created_at": r.created_at,
            }
            for r in results
        ],
    }


async def history_browse(
    limit: int = 20,
    *,
    principal_id: str = "",
    db: Any = None,
    **kwargs: Any,
) -> dict:
    """Browse recent sessions by date (scoped to the caller's principal).

    Args:
        limit: Maximum sessions to return (default 20).
        principal_id: Caller's principal ID (injected by broker).
        db: Database instance (injected by broker from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    search = _build_search(principal_id, db)
    if search is None:
        return {"status": "unavailable", "error": "session search not configured", "sessions": []}
    summaries = await search.browse(limit=limit)
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "title": s.title,
                "message_count": s.message_count,
                "created_at": s.created_at,
            }
            for s in summaries
        ]
    }


async def history_read(
    session_id: str,
    *,
    principal_id: str = "",
    db: Any = None,
    **kwargs: Any,
) -> dict:
    """Read messages from a specific session (scoped to the caller's
    principal).

    The caller's principal must own the session — a foreign principal's
    ``session_id`` returns an empty message list (the underlying
    ``get_session_messages`` filters by ``principal_id``).

    Args:
        session_id: Session ID to read.
        principal_id: Caller's principal ID (injected by broker).
        db: Database instance (injected by broker from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    search = _build_search(principal_id, db)
    if search is None:
        return {"status": "unavailable", "error": "session search not configured"}
    messages = await search.read_session(session_id)
    return {
        "session_id": session_id,
        "messages": [
            {"role": m.get("role"), "content": m.get("content"), "created_at": m.get("created_at")}
            for m in messages
        ],
    }


HISTORY_TOOLS = [
    {
        "name": "history_search",
        "description": "Search past session history. Supports AND/OR/NOT operators and quoted phrases.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "description": "Max results (default 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "history_browse",
        "description": "Browse recent sessions by date.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max sessions (default 20)"},
            },
        },
    },
    {
        "name": "history_read",
        "description": "Read messages from a specific past session.",
        "parameters": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session ID to read"},
            },
            "required": ["session_id"],
        },
    },
]
