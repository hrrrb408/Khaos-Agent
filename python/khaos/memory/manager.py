"""Memory injection and cross-mode transfer."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from khaos.agent.core import SimpleTokenEngine
from khaos.memory.store import Memory, MemoryScope, MemoryStore, extract_memories_from_messages
from khaos.modes import Mode

logger = logging.getLogger(__name__)


@dataclass
class MemoryBudget:
    """Token budget for memory injection."""

    total_tokens: int = 2048
    l0_max_tokens: int = 512
    l1_max_tokens: int = 1024
    l2_max_tokens: int = 512


class MemoryManager:
    """Basic Phase 1 memory manager."""

    def __init__(
        self,
        store: MemoryStore,
        budget: MemoryBudget | None = None,
        token_engine: SimpleTokenEngine | None = None,
        mode_getter=None,
        intent_getter=None,
    ):
        self.store = store
        self.budget = budget or MemoryBudget()
        self.token_engine = token_engine or SimpleTokenEngine()
        self.mode_getter = mode_getter
        self.intent_getter = intent_getter

    async def inject(self, session_id: str) -> str:
        """Return formatted memory text within budget.

        L0 (global) is always injected so cross-session identity persists. L1
        is the current mode's memories. L2 is the cross-mode residue, ranked by
        relevance: higher confidence first, then access frequency (recency of
        use), then recency of update.
        """
        del session_id
        current_mode = self._current_scope()
        l0 = await self.store.list_by_scope(MemoryScope.GLOBAL)
        l1 = await self.store.list_by_scope(current_mode)
        all_memories = await self.store.list_all()
        l2 = sorted(
            (
                memory
                for memory in all_memories
                if memory.scope not in {MemoryScope.GLOBAL, current_mode}
            ),
            key=lambda m: (m.confidence.value, m.access_freq, m.updated_at or datetime.min),
            reverse=True,
        )
        sections = [
            self._format_section("L0 全局记忆", l0, self.budget.l0_max_tokens),
            self._format_section("L1 模式记忆", l1, self.budget.l1_max_tokens),
            self._format_section("L2 相关记忆", l2, self.budget.l2_max_tokens),
        ]
        text = "\n".join(section for section in sections if section)
        return self._truncate_to_tokens(text, self.budget.total_tokens)

    async def cross_mode_transfer(self, old_mode: Mode, new_mode: Mode) -> str:
        """Format intent buffer as bridge context between modes."""
        intent = self.intent_getter() if self.intent_getter is not None else ""
        if not intent:
            return ""
        return f"跨模式上下文: {old_mode.value} -> {new_mode.value}: {intent}"

    async def update_from_conversation(self, messages: list, mode: Mode) -> list[Memory]:
        """Extract and persist memory-worthy facts from the conversation.

        Scans user-role messages for declarative signals (name, preferences,
        "remember X") and writes them with conflict resolution so a later,
        higher-confidence statement supersedes an earlier one. Returns the
        memories actually persisted (unresolved conflicts are skipped and
        logged).
        """
        scope = MemoryScope(mode.value) if isinstance(mode, Mode) else MemoryScope.GLOBAL
        candidates = extract_memories_from_messages(messages, scope=MemoryScope.GLOBAL)
        persisted: list[Memory] = []
        for memory in candidates:
            stored = await self.store.set(memory, on_conflict="resolve")
            if stored is not None:
                persisted.append(stored)
        if persisted:
            logger.info("proactive memory extracted %d fact(s)", len(persisted))
        return persisted

    def _current_scope(self) -> MemoryScope:
        if self.mode_getter is None:
            return MemoryScope.GLOBAL
        mode = self.mode_getter()
        if isinstance(mode, Mode):
            return MemoryScope(mode.value)
        return MemoryScope(str(mode))

    def _format_section(
        self,
        title: str,
        memories: list[Memory],
        token_budget: int,
    ) -> str:
        lines: list[str] = []
        used = 0
        for memory in memories:
            line = f"- ({memory.scope.value}) {memory.key}: {memory.value}"
            tokens = self.token_engine.count_tokens(line)
            if used + tokens > token_budget:
                break
            used += tokens
            lines.append(line)
        if not lines:
            return ""
        return f"{title}:\n" + "\n".join(lines)

    def _truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        words = text.split()
        if len(words) <= max_tokens:
            return text
        return " ".join(words[:max_tokens])

