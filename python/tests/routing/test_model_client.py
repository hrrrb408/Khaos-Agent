import json

import httpx
import pytest

from khaos.agent import Message
from khaos.agent.error_handler import ModelRateLimitError
from khaos.routing.model_client import ModelClient
from khaos.routing.provider import ModelSpec, ProviderConfig


def _sse(payloads: list[dict]) -> bytes:
    lines = [f"data: {json.dumps(payload)}\n\n" for payload in payloads]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode("utf-8")


async def test_model_client_streams_text_chunks():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        body = json.loads(request.content)
        assert body["model"] == "qwen/qwen3-8b"
        assert body["max_tokens"] == 2048
        return httpx.Response(
            200,
            content=_sse(
                [
                    {"choices": [{"delta": {"content": "hello "}}]},
                    {"choices": [{"delta": {"content": "world"}, "finish_reason": "stop"}]},
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://integrate.api.nvidia.com/v1", api_key="secret"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768, max_output_tokens=2048),
            [Message("user", "hi")],
        )
    ]

    assert "".join(chunk.content for chunk in chunks if chunk.content) == "hello world"
    assert chunks[-1].stop_reason == "end_turn"


async def test_model_client_parses_tool_calls():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_1",
                                            "function": {"name": "read_file", "arguments": "{\"path\""},
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    {
                        "choices": [
                            {
                                "delta": {"tool_calls": [{"index": 0, "function": {"arguments": ":\"a.txt\"}"}}]},
                                "finish_reason": "tool_calls",
                            }
                        ]
                    },
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "read")],
        )
    ]

    tool_message = next(chunk for chunk in chunks if chunk.tool_calls)
    assert tool_message.stop_reason == "tool_use"
    assert tool_message.tool_calls == [{"id": "call_1", "name": "read_file", "arguments": {"path": "a.txt"}}]


async def test_model_client_maps_length_finish_reason_to_max_tokens():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {"choices": [{"delta": {"content": "truncated"}, "finish_reason": "length"}]},
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "hi")],
        )
    ]

    assert chunks[0].content == "truncated"
    assert chunks[-1].stop_reason == "max_tokens"


async def test_model_client_retries_429_then_succeeds():
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, content=b"rate limited")
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), base_delay=0)
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "hi")],
        )
    ]

    assert calls == 2
    assert chunks[0].content == "ok"


async def test_model_client_raises_after_429_budget():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"rate limited")

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), max_retries=2, base_delay=0)

    with pytest.raises(ModelRateLimitError):
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("nvidia", "https://example.test/v1"),
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                [Message("user", "hi")],
            )
        ]


async def test_model_client_includes_http_error_body():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b'{"error":"bad api key"}')

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    with pytest.raises(RuntimeError, match="HTTP 401.*bad api key"):
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("nvidia", "https://example.test/v1"),
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                [Message("user", "hi")],
            )
        ]
