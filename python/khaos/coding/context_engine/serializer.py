"""Stable provider-facing serialization for selected context items."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from khaos.coding.context_engine.contracts import (
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextMessage,
    ContextSelection,
    ContextSource,
    ContextTrust,
    approximate_token_count,
)
from khaos.security.protocol_boundary import canonical_digest


@dataclass(frozen=True, slots=True)
class SerializedContext:
    """Messages plus stable-prefix accounting."""

    messages: tuple[ContextMessage, ...]
    context_digest: str
    stable_prefix_tokens: int
    stable_prefix_bytes: int


class ContextSerializer:
    """Serialize without reinterpreting untrusted content as instructions."""

    def serialize(self, selection: ContextSelection) -> SerializedContext:
        messages: list[ContextMessage] = []
        for item in selection.selected:
            metadata = dict(item.metadata)
            role = str(metadata.get("role") or self._default_role(item))
            tool_call_id = metadata.get("tool_call_id")
            event = metadata.get("event")
            raw_tool_calls = metadata.get("tool_calls", ())
            tool_calls = tuple(
                value for value in raw_tool_calls
                if isinstance(value, Mapping)
            ) if isinstance(raw_tool_calls, (tuple, list)) else ()
            content = self._render(item)
            message_metadata = {
                key: value
                for key, value in metadata.items()
                if key not in {"role", "tool_call_id", "tool_calls", "event"}
            }
            # These fields are derived from the typed item, never from
            # model-controlled metadata, so a rebalance can preserve the
            # original layer/trust/source classification.
            message_metadata.update(
                {
                    # Only messages emitted by this serializer may carry
                    # typed context metadata back through a later
                    # rebalance.  A user/model-controlled message can copy
                    # the field names, but cannot forge this internal marker
                    # and thereby elevate its trust or layer.
                    "context_engine": True,
                    "context_kind": item.kind.value,
                    "context_layer": item.layer.value,
                    "context_source": item.source.value,
                    "context_trust": item.trust.value,
                    "context_workspace_id": item.workspace_id,
                    "context_generation": item.generation,
                }
            )
            messages.append(
                ContextMessage(
                    role=role,
                    content=content,
                    tool_calls=tool_calls,
                    tool_call_id=str(tool_call_id) if tool_call_id is not None else None,
                    event=str(event) if event is not None else None,
                    metadata=message_metadata,
                    item_ids=(item.item_id,),
                )
            )
        digest = canonical_digest(
            [item.to_payload(include_content=True) for item in selection.selected]
        )
        prefix_tokens = 0
        prefix_bytes = 0
        for message in messages:
            if len(messages) > 1 and message.role in {"user", "assistant", "tool"}:
                # The first durable system/project block is the stable prefix;
                # later messages are turn-specific even when their text is
                # unchanged.
                break
            prefix_tokens += approximate_token_count(message.content)
            prefix_bytes += len(message.content.encode("utf-8"))
        return SerializedContext(
            messages=tuple(messages),
            context_digest=digest,
            stable_prefix_tokens=prefix_tokens,
            stable_prefix_bytes=prefix_bytes,
        )

    @staticmethod
    def _default_role(item: ContextItem) -> str:
        if item.layer is ContextLayer.L0:
            return "system"
        if item.kind is ContextItemKind.CONVERSATION:
            return "user"
        if item.kind is ContextItemKind.TOOL_RESULT:
            return "tool"
        return "user"

    @staticmethod
    def _render(item: ContextItem) -> str:
        text = item.payload
        if item.truncated:
            text = f"{text}\n[context truncated; digest={item.digest}]" if text else f"[context truncated; digest={item.digest}]"
        marker = {
            ContextTrust.UNTRUSTED_REPO: ("untrusted_repo_context", "repository"),
            ContextTrust.UNTRUSTED_TOOL: ("untrusted_tool_output", "tool"),
            ContextTrust.UNTRUSTED_MEMORY: ("untrusted_memory", "memory"),
            ContextTrust.UNTRUSTED_MODEL: ("untrusted_model_observation", "model"),
        }.get(item.trust)
        if marker is None:
            if item.source is ContextSource.PROJECT and item.layer is ContextLayer.L0:
                if text.startswith("<project_instructions "):
                    return text
                return f"<project_instructions source=\"project\">\n{text}\n</project_instructions>"
            return text
        name, source = marker
        if text.startswith(f"<{name} "):
            return text
        return f"<{name} source=\"{source}\" digest=\"{item.digest}\">\n{text}\n</{name}>"
