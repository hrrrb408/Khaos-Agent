"""Context compression with three levels and a circuit breaker."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from khaos.agent.core import Message, SimpleTokenEngine

logger = logging.getLogger(__name__)


class CompressionLevel(Enum):
    """Compression level applied to a message list."""

    MICRO_COMPACT = 0
    CONTEXT_COLLAPSE = 1
    AUTO_COMPACT = 2
    SESSION_MEMORY = 3


@dataclass
class CompressionResult:
    """Result of a compression run."""

    level: CompressionLevel
    original_tokens: int
    compressed_tokens: int
    messages: list[Message]


class ContextCompressor:
    """Three-level context compressor with Level 2 circuit breaker."""

    def __init__(
        self,
        router,
        token_engine: SimpleTokenEngine | None = None,
        memory_manager=None,
        micro_max_chars: int = 10000,
    ):
        self.router = router
        self.token_engine = token_engine or SimpleTokenEngine()
        self.memory_manager = memory_manager
        self.micro_max_chars = micro_max_chars
        self._consecutive_l2_failures = 0

    async def compress(self, messages: list[Message], threshold: int) -> CompressionResult:
        """Compress context while protecting system and recent messages."""
        original_tokens = self._count_messages(messages)
        working = [self._clone_message(message) for message in messages]
        system_messages, middle_messages, recent_messages = self._split_boundaries(working)

        middle_messages = [
            await self._micro_compact(message)
            if self._can_micro_compact(message)
            else message
            for message in middle_messages
        ]
        micro_messages = system_messages + middle_messages + recent_messages
        micro_tokens = self._count_messages(micro_messages)
        if micro_tokens <= threshold or not middle_messages:
            return CompressionResult(
                CompressionLevel.MICRO_COMPACT,
                original_tokens,
                micro_tokens,
                micro_messages,
            )

        if micro_tokens > threshold * 1.5 and not self.is_circuit_open:
            try:
                collapsed = await self._auto_compact(middle_messages)
                result_messages = system_messages + collapsed + recent_messages
                self._consecutive_l2_failures = 0
                return CompressionResult(
                    CompressionLevel.AUTO_COMPACT,
                    original_tokens,
                    self._count_messages(result_messages),
                    result_messages,
                )
            except Exception as exc:
                self._consecutive_l2_failures += 1
                logger.warning("Level 2 compression failed: %s", exc)

        try:
            collapsed = await self._context_collapse(middle_messages)
            result_messages = system_messages + collapsed + recent_messages
            return CompressionResult(
                CompressionLevel.CONTEXT_COLLAPSE,
                original_tokens,
                self._count_messages(result_messages),
                result_messages,
            )
        except Exception as exc:
            logger.warning("Level 1 compression failed: %s", exc)
            compacted = [
                await self._micro_compact(message, max_chars=max(1000, self.micro_max_chars // 5))
                for message in middle_messages[:1]
            ]
            result_messages = system_messages + compacted + recent_messages
            return CompressionResult(
                CompressionLevel.MICRO_COMPACT,
                original_tokens,
                self._count_messages(result_messages),
                result_messages,
            )

    async def _micro_compact(
        self,
        message: Message,
        max_chars: int | None = None,
    ) -> Message:
        """Truncate one oversized message without calling a model."""
        limit = max_chars or self.micro_max_chars
        if len(message.content) <= limit:
            return self._clone_message(message)
        compacted = self._clone_message(message)
        compacted.content = (
            f"{message.content[:limit]}\n\n"
            f"[截断: 原文 {len(message.content)} 字符，已保留前 {limit}]"
        )
        compacted.token_count = self.token_engine.count_tokens(compacted.content)
        return compacted

    async def _context_collapse(self, messages: list[Message]) -> list[Message]:
        """Collapse historical messages into one deterministic local summary."""
        if not messages:
            return []
        protected, collapsible = self._partition_tool_pairs(messages)
        if not collapsible:
            return [self._clone_message(message) for message in protected]
        key_decisions = extract_key_decisions(collapsible)
        summary = Message(
            role="assistant",
            content=(
                f"[摘要开始] 原始 {len(collapsible)} 条消息压缩为 1 条。"
                f"包含关键决策: {key_decisions} [摘要结束]"
            ),
        )
        summary.token_count = self.token_engine.count_tokens(summary.content)
        return [self._clone_message(message) for message in protected] + [summary]

    async def _auto_compact(self, messages: list[Message]) -> list[Message]:
        """Ask the router's compression function for a compact summary."""
        prompt = (
            "请将以下对话历史压缩为摘要，保留关键决策、工具调用及其结果。"
            f"格式必须为：[摘要开始] 原始 {len(messages)} 条消息压缩为 1 条。"
            "包含关键决策: ... [摘要结束]\n\n"
            + "\n".join(f"[{m.role}] {m.content[:500]}" for m in messages)
        )
        chunks = []
        async for chunk in self.router.call("compression", [Message(role="user", content=prompt)]):
            if chunk.content:
                chunks.append(chunk.content)
        summary = "".join(chunks).strip()
        if not summary:
            raise ValueError("compression model returned empty summary")
        if "[摘要开始]" not in summary:
            summary = (
                f"[摘要开始] 原始 {len(messages)} 条消息压缩为 1 条。"
                f"包含关键决策: {summary} [摘要结束]"
            )
        message = Message(role="assistant", content=summary)
        message.token_count = self.token_engine.count_tokens(summary)
        return [message]

    @property
    def is_circuit_open(self) -> bool:
        """Return true after three consecutive Level 2 failures."""
        return self._consecutive_l2_failures >= 3

    def _reset_circuit(self) -> None:
        self._consecutive_l2_failures = 0

    def _split_boundaries(
        self,
        messages: list[Message],
    ) -> tuple[list[Message], list[Message], list[Message]]:
        system_messages = [message for message in messages if message.role == "system"]
        non_system = [message for message in messages if message.role != "system"]
        if len(non_system) <= 4:
            return system_messages, [], non_system
        recent_messages = non_system[-4:]
        middle_messages = non_system[: len(non_system) - len(recent_messages)]
        return system_messages, middle_messages, recent_messages

    def _partition_tool_pairs(
        self,
        messages: list[Message],
    ) -> tuple[list[Message], list[Message]]:
        protected: list[Message] = []
        collapsible: list[Message] = []
        result_by_id = {
            message.tool_call_id: message
            for message in messages
            if message.role == "tool" and message.tool_call_id
        }
        protected_ids: set[str] = set()
        for message in messages:
            if not message.tool_calls:
                continue
            ids = [str(call.get("id")) for call in message.tool_calls if call.get("id")]
            pair_results = [result_by_id[call_id] for call_id in ids if call_id in result_by_id]
            if len(pair_results) == len(ids):
                protected.append(message)
                protected.extend(pair_results)
                protected_ids.update(ids)

        protected_message_ids = {id(message) for message in protected}
        for message in messages:
            if id(message) in protected_message_ids:
                continue
            if message.role == "tool" and message.tool_call_id in protected_ids:
                continue
            collapsible.append(message)
        return protected, collapsible

    def _count_messages(self, messages: list[Message]) -> int:
        return sum(self.token_engine.count_tokens(message.content) for message in messages)

    def _can_micro_compact(self, message: Message) -> bool:
        return len(message.content) > self.micro_max_chars and not message.tool_calls

    @staticmethod
    def _clone_message(message: Message) -> Message:
        return Message(
            role=message.role,
            content=message.content,
            tool_calls=[dict(call) for call in message.tool_calls],
            tool_call_id=message.tool_call_id,
            token_count=message.token_count,
            created_at=message.created_at,
            stop_reason=message.stop_reason,
            event=message.event,
            metadata=dict(message.metadata),
        )


def extract_key_decisions(messages: list[Message]) -> str:
    """Extract a compact deterministic summary from message content."""
    snippets: list[str] = []
    for message in messages:
        text = " ".join(message.content.split())
        if not text:
            continue
        snippets.append(f"{message.role}: {text[:120]}")
        if len(snippets) >= 5:
            break
    return "；".join(snippets) if snippets else "无明确关键决策"
