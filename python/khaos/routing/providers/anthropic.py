"""Anthropic Claude provider (Messages API + streaming + tool use).

Anthropic's wire format differs from OpenAI's in three places we have to bridge:
- The system prompt is a top-level ``system`` field, not a message.
- Tool definitions use ``input_schema`` instead of ``parameters``.
- Tool calls live in ``content`` blocks of type ``tool_use``, not ``tool_calls``.

The streaming protocol uses SSE events ``message_start`` / ``content_block_start``
/ ``content_block_delta`` / ``message_delta`` / ``message_stop``. We parse those
into Khaos :class:`Message` chunks so the rest of the stack sees a uniform shape.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from khaos.agent.core import Message
from khaos.routing.provider import ModelSpec, ProviderConfig
from khaos.routing.providers.base import BaseProvider, ProviderError, register_provider_type


class AnthropicProvider(BaseProvider):
    """Streams via Anthropic's Messages API."""

    type_name = "anthropic"

    async def stream_chat(
        self,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> AsyncIterator[Message]:
        payload = self.build_payload(model, messages, tools)
        headers = self.build_headers()
        url = self.config.base_url.rstrip("/") + "/v1/messages"
        client, should_close = self._client_or_new(self.http_client, self.config.timeout)
        try:
            async for chunk in self._stream(client, url, headers, payload):
                yield chunk
        finally:
            if should_close:
                await client.aclose()

    # --- payload / header construction (public for unit testing) -----------

    def build_headers(self) -> dict[str, str]:
        """Anthropic uses ``x-api-key`` + a version header, not Bearer auth."""
        headers = {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "accept": "text/event-stream",
        }
        if self.config.api_key:
            headers["x-api-key"] = self.config.api_key
        return headers

    def build_payload(
        self,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None,
    ) -> dict[str, Any]:
        """Convert Khaos messages + tools to the Anthropic request shape."""
        system_text, anthropic_messages = self.convert_messages(messages)
        payload: dict[str, Any] = {
            "model": model.model,
            "messages": anthropic_messages,
            "stream": True,
            "max_tokens": 4096,
        }
        if system_text:
            payload["system"] = system_text
        if tools and model.supports_tools:
            payload["tools"] = [self.convert_tool(tool) for tool in tools]
        return payload

    @staticmethod
    def convert_messages(messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
        """Split system from the rest and rewrite tool blocks.

        Returns ``(system_text, anthropic_messages)``.
        """
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                if message.content:
                    system_parts.append(message.content)
                continue
            if message.role == "tool":
                # Anthropic represents tool results as a user message with a
                # tool_result content block.
                out.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.tool_call_id or "",
                                "content": message.content,
                            }
                        ],
                    }
                )
                continue
            content: list[dict[str, Any]] = []
            if message.content:
                content.append({"type": "text", "text": message.content})
            for call in message.tool_calls:
                content.append(
                    {
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": call.get("name", ""),
                        "input": call.get("arguments", {}),
                    }
                )
            if not content:
                content = [{"type": "text", "text": ""}]
            out.append({"role": message.role, "content": content})
        return "\n\n".join(system_parts), out

    @staticmethod
    def convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
        """Convert an OpenAI-style tool definition to Anthropic's schema.

        Accepts both the full OpenAI envelope (``{type: function, function:
        {...}}``) and the bare function dict Khaos uses internally.
        """
        function = tool.get("function", tool)
        return {
            "name": function.get("name", ""),
            "description": function.get("description", ""),
            "input_schema": function.get("parameters") or function.get("input_schema")
            or {"type": "object", "properties": {}},
        }

    # --- streaming parser --------------------------------------------------

    async def _stream(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> AsyncIterator[Message]:
        async with client.stream("POST", url, headers=headers, json=payload) as response:
            if response.status_code != 200:
                body = (await response.aread()).decode("utf-8", errors="replace")
                raise ProviderError(
                    f"Anthropic HTTP {response.status_code}: {body[:300]}"
                )
            parser = _AnthropicStreamParser()
            async for line in response.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line.removeprefix("data:").strip()
                if not data:
                    continue
                try:
                    event = json.loads(data)
                except json.JSONDecodeError:
                    continue
                for chunk in parser.feed(event):
                    yield chunk
            for chunk in parser.finish():
                yield chunk


class _AnthropicStreamParser:
    """Accumulates Anthropic SSE events into Khaos Message chunks.

    Anthropic streams a single assistant turn as:
      message_start -> [content_block_start (text) -> content_block_delta(text)*]*
                       [content_block_start (tool_use) -> content_block_delta(input_json)*]*
                       -> message_delta(stop_reason) -> message_stop

    We emit one Message per text delta (for streaming UX) and a final tool-call
    Message once a tool_use block closes.
    """

    def __init__(self) -> None:
        # tool_use_id -> {name, args_buffer}
        self._tool_blocks: dict[int, dict[str, Any]] = {}
        self._stop_reason: str | None = None
        self._emitted_tool_indices: set[int] = set()

    def feed(self, event: dict[str, Any]):
        """Yield Message chunks for one SSE event dict."""
        event_type = event.get("type", "")
        if event_type == "content_block_start":
            block = event.get("content_block", {}) or {}
            if block.get("type") == "tool_use":
                index = int(event.get("index", 0))
                self._tool_blocks[index] = {
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "args": "",
                }
        elif event_type == "content_block_delta":
            delta = event.get("delta", {}) or {}
            if delta.get("type") == "text_delta":
                text = delta.get("text", "")
                if text:
                    yield Message(role="assistant", content=text)
            elif delta.get("type") == "input_json_delta":
                index = int(event.get("index", 0))
                block = self._tool_blocks.setdefault(
                    index, {"id": "", "name": "", "args": ""}
                )
                block["args"] += delta.get("partial_json", "")
        elif event_type == "content_block_stop":
            index = int(event.get("index", 0))
            if index in self._tool_blocks and index not in self._emitted_tool_indices:
                yield from self._emit_tool(index)
        elif event_type == "message_delta":
            delta = event.get("delta", {}) or {}
            reason = delta.get("stop_reason")
            if reason:
                self._stop_reason = "tool_use" if reason == "tool_use" else "end_turn"
        elif event_type == "message_stop":
            pass  # handled in finish()

    def _emit_tool(self, index: int):
        block = self._tool_blocks.pop(index, None)
        self._emitted_tool_indices.add(index)
        if block is None:
            return
        raw_args = block.get("args", "") or "{}"
        try:
            arguments = json.loads(raw_args)
        except json.JSONDecodeError:
            arguments = {"_raw": raw_args}
        yield Message(
            role="assistant",
            content="",
            tool_calls=[
                {"id": block.get("id", "") or f"call_{index}", "name": block.get("name", ""), "arguments": arguments}
            ],
            stop_reason="tool_use",
        )

    def finish(self):
        """Yield the terminal message (stop_reason) after the stream ends."""
        # Flush any tool blocks that never got a stop event (defensive).
        for index in sorted(self._tool_blocks):
            if index not in self._emitted_tool_indices:
                yield from self._emit_tool(index)
        yield Message(role="assistant", content="", stop_reason=self._stop_reason or "end_turn")


register_provider_type("anthropic", AnthropicProvider)


__all__ = ["AnthropicProvider"]
