"""Async OpenAI-compatible model client."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from khaos.agent.core import Message
from khaos.agent.error_handler import ModelRateLimitError
from khaos.routing.provider import ModelSpec, ProviderConfig


class ModelClient:
    """OpenAI-compatible chat completions client with SSE streaming."""

    def __init__(
        self,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int = 3,
        base_delay: float = 0.1,
    ):
        self.http_client = http_client
        self.max_retries = max_retries
        self.base_delay = base_delay

    async def stream_chat(
        self,
        provider: ProviderConfig,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> AsyncIterator[Message]:
        """Stream chat completions as Khaos Message chunks."""
        payload: dict[str, Any] = {
            "model": model.model,
            "messages": [_message_to_openai(message) for message in messages],
            "stream": True,
            "max_tokens": model.max_output_tokens,
        }
        if tools and model.supports_tools:
            payload["tools"] = tools

        headers = {"Accept": "text/event-stream"}
        if provider.api_key:
            headers["Authorization"] = f"Bearer {provider.api_key}"

        url = provider.base_url.rstrip("/") + "/chat/completions"
        client = self.http_client or httpx.AsyncClient(timeout=provider.timeout)
        should_close = self.http_client is None
        try:
            async for message in self._stream_with_retries(client, url, headers, payload):
                yield message
        finally:
            if should_close:
                await client.aclose()

    async def _stream_with_retries(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> AsyncIterator[Message]:
        last_rate_limit: ModelRateLimitError | None = None
        for attempt in range(self.max_retries):
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                if response.status_code == 429:
                    last_rate_limit = ModelRateLimitError("model provider rate limited")
                    await response.aread()
                    await asyncio.sleep(self.base_delay * (2**attempt))
                    continue
                if response.is_error:
                    body = (await response.aread()).decode("utf-8", errors="replace").strip()
                    detail = f": {body[:500]}" if body else ""
                    raise RuntimeError(f"model provider returned HTTP {response.status_code}{detail}")
                parser = _OpenAIStreamParser()
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line.removeprefix("data:").strip()
                    if data == "[DONE]":
                        final = parser.final_tool_message()
                        if final is not None:
                            yield final
                        yield Message(role="assistant", content="", stop_reason=parser.stop_reason or "end_turn")
                        return
                    chunk = parser.parse_payload(json.loads(data))
                    if chunk is not None:
                        yield chunk
                final = parser.final_tool_message()
                if final is not None:
                    yield final
                yield Message(role="assistant", content="", stop_reason=parser.stop_reason or "end_turn")
                return
        assert last_rate_limit is not None
        raise last_rate_limit


class _OpenAIStreamParser:
    def __init__(self):
        self.tool_calls: dict[int, dict[str, Any]] = {}
        self.stop_reason: str | None = None

    def parse_payload(self, payload: dict[str, Any]) -> Message | None:
        choice = (payload.get("choices") or [{}])[0]
        delta = choice.get("delta") or {}
        finish_reason = choice.get("finish_reason")
        if finish_reason:
            self.stop_reason = _map_finish_reason(str(finish_reason))
        content = delta.get("content")
        if content:
            return Message(role="assistant", content=str(content))
        if delta.get("tool_calls"):
            self._accumulate_tool_calls(delta["tool_calls"])
        if delta.get("function_call"):
            self._accumulate_legacy_function_call(delta["function_call"])
        return None

    def final_tool_message(self) -> Message | None:
        if not self.tool_calls:
            return None
        calls = []
        for index in sorted(self.tool_calls):
            call = self.tool_calls[index]
            function = call.get("function", {})
            raw_arguments = function.get("arguments", "") or "{}"
            try:
                arguments = json.loads(raw_arguments)
            except json.JSONDecodeError:
                arguments = {"_raw": raw_arguments}
            calls.append(
                {
                    "id": call.get("id") or f"call_{index}",
                    "name": function.get("name", ""),
                    "arguments": arguments,
                }
            )
        return Message(role="assistant", content="", tool_calls=calls, stop_reason="tool_use")

    def _accumulate_tool_calls(self, chunks: list[dict[str, Any]]) -> None:
        for chunk in chunks:
            index = int(chunk.get("index", 0))
            target = self.tool_calls.setdefault(index, {"function": {"name": "", "arguments": ""}})
            if chunk.get("id"):
                target["id"] = chunk["id"]
            function = chunk.get("function") or {}
            if function.get("name"):
                target["function"]["name"] += function["name"]
            if function.get("arguments"):
                target["function"]["arguments"] += function["arguments"]

    def _accumulate_legacy_function_call(self, chunk: dict[str, str]) -> None:
        target = self.tool_calls.setdefault(0, {"id": "function_call", "function": {"name": "", "arguments": ""}})
        if chunk.get("name"):
            target["function"]["name"] += chunk["name"]
        if chunk.get("arguments"):
            target["function"]["arguments"] += chunk["arguments"]


def _message_to_openai(message: Message) -> dict[str, Any]:
    if message.role == "tool":
        return {
            "role": "tool",
            "tool_call_id": message.tool_call_id or "",
            "content": message.content,
        }
    item: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        item["tool_calls"] = [
            {
                "id": call.get("id"),
                "type": "function",
                "function": {
                    "name": call.get("name"),
                    "arguments": json.dumps(call.get("arguments", {}), ensure_ascii=False),
                },
            }
            for call in message.tool_calls
        ]
    return item


def _map_finish_reason(finish_reason: str) -> str:
    if finish_reason in {"tool_calls", "function_call"}:
        return "tool_use"
    if finish_reason == "length":
        return "max_tokens"
    return "end_turn"
