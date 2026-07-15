"""Context layer labels used by reconstruction and compaction."""

from __future__ import annotations

from enum import Enum


class ContextLayer(str, Enum):
    IMMUTABLE_RULES = "immutable-rules"
    DURABLE_FACTS = "durable-facts"
    CONVERSATION = "conversation"
    CONVERSATION_SUMMARY = "conversation-summary"
    EPHEMERAL_OBSERVATION = "ephemeral-observation"


def is_structured_fact(message) -> bool:
    return bool(message.metadata.get("durable_fact")) or message.metadata.get(
        "context_layer"
    ) in {ContextLayer.IMMUTABLE_RULES.value, ContextLayer.DURABLE_FACTS.value}
