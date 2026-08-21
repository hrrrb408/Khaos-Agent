"""Memory injection and cross-mode orchestration."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from khaos.agent.core import SimpleTokenEngine
from khaos.memory.extraction import extract_memories_from_messages
from khaos.memory.models import Memory, MemoryScope
from khaos.memory.retrieval import MemoryRetriever
from khaos.memory.store import MemoryStore
from khaos.modes import Mode

logger = logging.getLogger(__name__)

MemoryExtractor = Callable[[list[Any], MemoryScope], list[Memory]]


@dataclass
class MemoryBudget:
    """Token budget for memory injection layers."""

    total_tokens: int = 2048
    l0_max_tokens: int = 512
    l1_max_tokens: int = 1024
    l2_max_tokens: int = 512

    def __post_init__(self) -> None:
        values = {
            "total_tokens": self.total_tokens,
            "l0_max_tokens": self.l0_max_tokens,
            "l1_max_tokens": self.l1_max_tokens,
            "l2_max_tokens": self.l2_max_tokens,
        }
        invalid = [name for name, value in values.items() if value < 0]
        if invalid:
            raise ValueError(f"memory budgets must be non-negative: {invalid}")


class MemoryManager:
    """Coordinate retrieval, formatting, and proactive extraction."""

    def __init__(
        self,
        store: MemoryStore,
        budget: MemoryBudget | None = None,
        token_engine: SimpleTokenEngine | None = None,
        mode_getter: Callable[[], Any] | None = None,
        intent_getter: Callable[[], str] | None = None,
        *,
        retriever: MemoryRetriever | None = None,
        extractor: MemoryExtractor | None = None,
    ) -> None:
        self.store = store
        self.budget = budget or MemoryBudget()
        self.token_engine = token_engine or SimpleTokenEngine()
        self.mode_getter = mode_getter
        self.intent_getter = intent_getter
        self.retriever = retriever or MemoryRetriever()
        self.extractor = extractor or extract_memories_from_messages

    async def inject(self, session_id: str) -> str:
        """Return deterministic L0/L1/L2 memory text within the total budget."""

        del session_id
        current_mode = self._current_scope()
        layers = self.retriever.build_layers(
            await self.store.list_by_scope(MemoryScope.GLOBAL),
            await self.store.list_by_scope(current_mode),
            await self.store.list_all(),
            current_mode,
        )
        sections = [
            self._format_section(
                "L0 全局记忆", layers.global_memories, self.budget.l0_max_tokens
            ),
            self._format_section(
                "L1 模式记忆",
                layers.current_mode_memories,
                self.budget.l1_max_tokens,
            ),
            self._format_section(
                "L2 相关记忆",
                layers.cross_mode_memories,
                self.budget.l2_max_tokens,
            ),
        ]
        text = "\n".join(section for section in sections if section)
        return self._truncate_to_tokens(text, self.budget.total_tokens)

    async def cross_mode_transfer(self, old_mode: Mode, new_mode: Mode) -> str:
        """Format the transient intent buffer between mode switches."""

        intent = self.intent_getter() if self.intent_getter is not None else ""
        if not intent:
            return ""
        return f"跨模式上下文: {old_mode.value} -> {new_mode.value}: {intent}"

    async def update_from_conversation(
        self,
        messages: list[Any],
        mode: Mode,
    ) -> list[Memory]:
        """Extract and persist declarative user facts with conflict policy."""

        del mode
        candidates = self.extractor(messages, MemoryScope.GLOBAL)
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
        if token_budget <= 0:
            return ""
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
        """Truncate on word boundaries while respecting the active tokenizer."""

        if max_tokens <= 0 or not text:
            return ""
        if self.token_engine.count_tokens(text) <= max_tokens:
            return text
        words = text.split()
        low, high = 0, len(words)
        best = ""
        while low <= high:
            middle = (low + high) // 2
            candidate = " ".join(words[:middle])
            if self.token_engine.count_tokens(candidate) <= max_tokens:
                best = candidate
                low = middle + 1
            else:
                high = middle - 1
        return best


__all__ = ["MemoryBudget", "MemoryManager"]
