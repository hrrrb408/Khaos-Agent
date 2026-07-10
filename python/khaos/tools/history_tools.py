"""Tools for session history search.

Handlers delegate to a :class:`SessionSearch` instance injected via
:func:`set_session_search` at startup. Without an injected instance the
handlers report "not available" instead of returning empty results that look
like successful (but data-free) searches.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Module-level holder for the live SessionSearch instance.
_session_search: Any = None


def set_session_search(search: Any) -> None:
    """Inject the process-wide SessionSearch instance (called at startup)."""
    global _session_search
    _session_search = search
    logger.info("session search injected into history_tools")


async def history_search(query: str, limit: int = 10, **kwargs: Any) -> dict:
    """Search past session history using full-text search."""
    if _session_search is None:
        return {"status": "unavailable", "error": "session search not configured", "results": []}
    results = await _session_search.search(query, limit=limit)
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


async def history_browse(limit: int = 20, **kwargs: Any) -> dict:
    """Browse recent sessions by date."""
    if _session_search is None:
        return {"status": "unavailable", "error": "session search not configured", "sessions": []}
    summaries = await _session_search.browse(limit=limit)
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


async def history_read(session_id: str, **kwargs: Any) -> dict:
    """Read messages from a specific session."""
    if _session_search is None:
        return {"status": "unavailable", "error": "session search not configured"}
    messages = await _session_search.read_session(session_id)
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
