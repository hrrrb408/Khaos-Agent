"""Session history search with FTS5 and context windowing."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """一个搜索结果。"""

    session_id: str
    snippet: str          # FTS5 snippet（高亮匹配片段）
    rank: float           # BM25 排名
    message_id: int
    created_at: str
    role: str


@dataclass
class SessionSummary:
    """会话摘要（用于浏览模式）。"""

    session_id: str
    title: str            # 首条用户消息（作为标题）
    preview: str         # 最后一条消息摘要
    created_at: str
    message_count: int


@dataclass
class MessageWindow:
    """围绕锚点消息的上下文窗口。"""

    messages: list[dict] = field(default_factory=list)
    anchor_id: int = 0
    has_before: bool = False      # 前面还有更多消息
    has_after: bool = False       # 后面还有更多消息


class SessionSearch:
    """跨会话历史搜索。

    M4 batch 3.1.16A-4-3: ``principal_id`` scopes every underlying DB
    call.  ``None`` means admin opt-in (no scoping, legacy behavior) so
    existing callers/tests keep working; a non-None value restricts
    search/browse/scroll/read to that principal's owned rows.

    H-02 (round-4 review): ``project_id`` is an independent owner
    dimension.  When provided, every underlying DB call is further
    scoped to that project — closing cross-project reads on shared DBs.
    """

    def __init__(self, db, *, principal_id: str | None = None, project_id: str | None = None):
        self.db = db
        self.principal_id = principal_id
        self.project_id = project_id

    async def search(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
    ) -> list[SearchResult]:
        """FTS5 搜索。支持 AND/OR/NOT/引号短语/前缀通配。"""
        rows = await self.db.search_sessions(
            query, limit, offset,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        return [
            SearchResult(
                session_id=str(row["session_id"]),
                snippet=str(row.get("snippet", "")),
                rank=float(row.get("rank", 0)),
                message_id=int(row.get("id", 0)),
                created_at=str(row.get("created_at", "")),
                role=str(row.get("role", "")),
            )
            for row in rows
        ]

    async def browse(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> list[SessionSummary]:
        """按时间倒序浏览最近的会话。"""
        sessions = await self.db.list_sessions(
            limit, offset,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        summaries: list[SessionSummary] = []
        for session in sessions:
            sid = str(session["id"])
            # Title = first user message of the session.
            title = ""
            try:
                first = await self.db.get_session_messages(
                    sid, 1, 0,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                )
                if first:
                    title = str(first[0].get("content", ""))[:100]
            except Exception:  # noqa: BLE001
                title = ""
            summaries.append(
                SessionSummary(
                    session_id=sid,
                    title=title,
                    preview=str(session.get("preview", ""))[:120],
                    created_at=str(session.get("created_at", "")),
                    message_count=int(session.get("message_count", 0)),
                )
            )
        return summaries

    async def scroll(
        self,
        session_id: str,
        around_message_id: int,
        window: int = 5,
    ) -> MessageWindow:
        """获取围绕锚点消息的上下文窗口。"""
        messages = await self.db.get_message_window(
            session_id,
            around_message_id,
            window,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        # Efficient before/after counts relative to the window's edges.
        if messages:
            before, after = await self.db.count_messages_before_after(
                session_id,
                around_message_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
            has_before = before > 0
            has_after = after > 0
        else:
            has_before = has_after = False
        return MessageWindow(
            messages=messages,
            anchor_id=around_message_id,
            has_before=has_before,
            has_after=has_after,
        )

    async def read_session(self, session_id: str) -> list[dict]:
        """读取完整会话（分页加载）。"""
        return await self.db.get_session_messages(
            session_id, 50, 0,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )

    async def _count_session_messages(self, session_id: str) -> int:
        count = await self.db.count_session_messages(
            session_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        return int(count) if count else 0
