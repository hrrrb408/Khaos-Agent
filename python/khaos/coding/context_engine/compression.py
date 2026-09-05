"""Deterministic conversation compaction for M8.4."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from khaos.coding.context_engine.contracts import (
    ContextItemKind,
    ContextLayer,
    ContextMessage,
    ContextSource,
    ContextTrust,
    TaskStateSummary,
    approximate_token_count,
)


@dataclass(frozen=True, slots=True)
class CompactionResult:
    messages: tuple[ContextMessage, ...]
    removed_count: int
    summary_digest: str | None
    approximate_tokens: int


class ContextCompactor:
    """Keep recent exact turns and derive older state from canonical facts."""

    def compact(
        self,
        messages: Sequence[ContextMessage],
        *,
        summary: TaskStateSummary | None = None,
        recent_count: int = 12,
    ) -> CompactionResult:
        if type(recent_count) is not int or recent_count < 0:
            raise ValueError("recent_count must be non-negative")
        if len(messages) <= recent_count + 1:
            return CompactionResult(
                messages=tuple(messages),
                removed_count=0,
                summary_digest=None,
                approximate_tokens=sum(
                    approximate_token_count(item.content) for item in messages
                ),
            )
        system = [message for message in messages if message.role == "system"][:1]
        non_system = [message for message in messages if message.role != "system"]
        recent = non_system[-recent_count:] if recent_count else []
        compacted: list[ContextMessage] = list(system)
        summary_digest: str | None = None
        if summary is not None:
            summary_digest = summary.digest()
            compacted.append(
                ContextMessage(
                    role="user",
                    content=(
                        "<task_state_summary source=\"runtime\" trust=\"untrusted_model\">\n"
                        f"{summary.to_text()}\n"
                        "</task_state_summary>"
                    ),
                    metadata={
                        "context_engine": True,
                        "context_kind": ContextItemKind.TASK_STATE.value,
                        "context_layer": ContextLayer.L1.value,
                        "context_source": ContextSource.RUNTIME.value,
                        "context_trust": ContextTrust.UNTRUSTED_MODEL.value,
                        "context_workspace_id": summary.workspace_id,
                        "context_generation": summary.generation,
                        "trusted": False,
                        "authority": "low-trust-data",
                        "summary_digest": summary_digest,
                    },
                )
            )
        compacted.extend(recent)
        return CompactionResult(
            messages=tuple(compacted),
            removed_count=max(0, len(messages) - len(compacted)),
            summary_digest=summary_digest,
            approximate_tokens=sum(
                approximate_token_count(item.content) for item in compacted
            ),
        )
