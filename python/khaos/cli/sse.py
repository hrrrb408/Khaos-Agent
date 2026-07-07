"""SSE event encoding for CLI and future gateway integration."""

from __future__ import annotations

import json
from dataclasses import asdict

from khaos.agent.core import Message


def event_name_for(message: Message) -> str:
    """Map an internal message to its SSE event name."""
    if message.event:
        return message.event
    if message.role == "system" and message.content == "done":
        return "done"
    if message.role == "system" and message.stop_reason == "error":
        return "error"
    if message.role == "tool":
        return "tool_result"
    return "message"


def message_to_data(message: Message) -> dict:
    """Convert a message to the public SSE payload shape."""
    if message.event in {"tool_call", "permission_request", "tool_result", "error"}:
        return message.metadata
    if event_name_for(message) == "done":
        return {
            "total_tokens": message.token_count,
            "stop_reason": message.stop_reason,
        }
    return {
        key: value
        for key, value in asdict(message).items()
        if value not in (None, [], 0, 0.0)
    }


def encode_sse(message: Message) -> str:
    """Encode a message as one SSE frame."""
    data = json.dumps(message_to_data(message), ensure_ascii=False)
    return f"event: {event_name_for(message)}\ndata: {data}\n\n"
