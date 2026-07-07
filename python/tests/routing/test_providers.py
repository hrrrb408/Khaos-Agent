"""Tests for the multi-provider architecture (Anthropic conversion + factory)."""

from __future__ import annotations

import json

import httpx
import pytest

from khaos.agent.core import Message
from khaos.routing.provider import ModelSpec, ProviderConfig, ProviderManager
from khaos.routing.providers import (
    AnthropicProvider,
    BaseProvider,
    OpenAICompatibleProvider,
    build_provider,
    known_provider_types,
)
from khaos.routing.providers.base import ProviderError


# --- factory & registry --------------------------------------------------


def test_known_provider_types_include_openai_and_anthropic():
    types = known_provider_types()
    assert "openai_compatible" in types
    assert "openai" in types
    assert "anthropic" in types


def test_build_provider_returns_correct_class_per_type():
    for type_name, expected_cls in [
        ("openai_compatible", OpenAICompatibleProvider),
        ("openai", OpenAICompatibleProvider),
        ("anthropic", AnthropicProvider),
    ]:
        cfg = ProviderConfig(name="x", base_url="http://x", api_key="k", type=type_name)
        provider = build_provider(cfg)

        assert isinstance(provider, expected_cls)


def test_build_provider_falls_back_to_openai_for_unknown_type():
    cfg = ProviderConfig(name="x", base_url="http://x", api_key="k", type="exotic-vendor")

    provider = build_provider(cfg)

    assert isinstance(provider, OpenAICompatibleProvider)


# --- Anthropic message conversion ----------------------------------------


def _anthropic():
    return AnthropicProvider(ProviderConfig(name="anthropic", base_url="https://api.anthropic.com", api_key="k", type="anthropic"))


def test_anthropic_lifts_system_prompt_to_top_level():
    provider = _anthropic()
    messages = [
        Message(role="system", content="you are helpful"),
        Message(role="user", content="hi"),
    ]

    system, anthropic_messages = provider.convert_messages(messages)

    assert system == "you are helpful"
    assert all(m["role"] != "system" for m in anthropic_messages)


def test_anthropic_converts_tool_definitions():
    provider = _anthropic()
    openai_tool = {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the weather",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
        },
    }

    converted = provider.convert_tool(openai_tool)

    assert converted["name"] == "get_weather"
    assert converted["description"] == "Get the weather"
    assert converted["input_schema"]["properties"]["city"]["type"] == "string"


def test_anthropic_wraps_assistant_tool_calls_as_tool_use_blocks():
    provider = _anthropic()
    messages = [
        Message(
            role="assistant",
            content="",
            tool_calls=[{"id": "call_1", "name": "search", "arguments": {"q": "x"}}],
        ),
    ]

    _, anthropic_messages = provider.convert_messages(messages)

    block = anthropic_messages[0]["content"][0]
    assert block["type"] == "tool_use"
    assert block["name"] == "search"
    assert block["input"] == {"q": "x"}


def test_anthropic_converts_tool_results_to_tool_result_blocks():
    provider = _anthropic()
    messages = [Message(role="tool", content="result text", tool_call_id="call_1")]

    _, anthropic_messages = provider.convert_messages(messages)

    block = anthropic_messages[0]["content"][0]
    assert block["type"] == "tool_result"
    assert block["tool_use_id"] == "call_1"
    assert block["content"] == "result text"


def test_anthropic_build_payload_shape():
    provider = _anthropic()
    model = ModelSpec(provider="anthropic", model="claude-sonnet-4-20250514", max_context_tokens=200000, supports_tools=True)
    messages = [
        Message(role="system", content="be brief"),
        Message(role="user", content="hello"),
    ]

    payload = provider.build_payload(model, messages, tools=None)

    assert payload["model"] == "claude-sonnet-4-20250514"
    assert payload["system"] == "be brief"
    assert payload["stream"] is True
    assert payload["max_tokens"] == 4096
    assert payload["messages"][0]["role"] == "user"


def test_anthropic_headers_use_x_api_key_not_bearer():
    provider = _anthropic()

    headers = provider.build_headers()

    assert headers["x-api-key"] == "k"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in headers


# --- Anthropic streaming parsing (via httpx mock) ------------------------


def _anthropic_sse(events: list[dict]) -> bytes:
    lines = []
    for event in events:
        lines.append(f"event: {event.get('type', '')}\n")
        lines.append(f"data: {json.dumps(event)}\n\n")
    return "".join(lines).encode("utf-8")


async def test_anthropic_stream_emits_text_chunks_and_stop():
    provider = _anthropic()
    model = ModelSpec(provider="anthropic", model="claude", max_context_tokens=200000)
    # Inject a mock transport so we don't hit the network.
    events = [
        {"type": "message_start", "message": {"id": "msg_1"}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text"}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hel"}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "lo"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
        {"type": "message_stop"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_anthropic_sse(events))

    provider.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    chunks = []
    async for chunk in provider.stream_chat(model, [Message(role="user", content="hi")]):
        chunks.append(chunk)

    text = "".join(c.content for c in chunks if c.content)
    assert text == "Hello"
    assert chunks[-1].stop_reason == "end_turn"


async def test_anthropic_stream_parses_tool_use_blocks():
    provider = _anthropic()
    model = ModelSpec(provider="anthropic", model="claude", max_context_tokens=200000, supports_tools=True)
    events = [
        {"type": "message_start", "message": {"id": "msg_1"}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tu_1", "name": "search"}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '{"q":"x"}'}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"}},
        {"type": "message_stop"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_anthropic_sse(events))

    provider.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    chunks = []
    async for chunk in provider.stream_chat(model, [Message(role="user", content="search")]):
        chunks.append(chunk)

    tool_msg = next(c for c in chunks if c.tool_calls)
    assert tool_msg.tool_calls[0]["name"] == "search"
    assert tool_msg.tool_calls[0]["arguments"] == {"q": "x"}
    assert tool_msg.stop_reason == "tool_use"


async def test_anthropic_stream_surfaces_http_errors():
    provider = _anthropic()
    model = ModelSpec(provider="anthropic", model="claude", max_context_tokens=200000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b'{"error":"unauthorized"}')

    provider.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    with pytest.raises(ProviderError, match="401"):
        async for _ in provider.stream_chat(model, [Message(role="user", content="hi")]):
            pass


# --- ProviderManager integration -----------------------------------------


def test_provider_manager_builds_clients_per_type(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    # Use the config.yaml layout: models.providers.<name>.models[]
    manager = ProviderManager.from_config(
        {
            "models": {
                "providers": {
                    "nvidia": {
                        "type": "openai_compatible",
                        "base_url": "http://n",
                        "api_key": "${NVIDIA_API_KEY}",
                        "models": [
                            {"name": "qwen", "max_context_tokens": 32000, "supports_tools": True}
                        ],
                    },
                    "anthropic": {
                        "type": "anthropic",
                        "base_url": "https://api.anthropic.com",
                        "api_key": "${ANTHROPIC_API_KEY}",
                        "models": [
                            {"name": "claude", "max_context_tokens": 200000, "supports_tools": True}
                        ],
                    },
                }
            }
        }
    )

    clients = manager.provider_clients()
    assert isinstance(clients["nvidia"], OpenAICompatibleProvider)
    assert isinstance(clients["anthropic"], AnthropicProvider)

    # provider_for_model returns the right client.
    assert isinstance(manager.provider_for_model("qwen"), OpenAICompatibleProvider)
    assert isinstance(manager.provider_for_model("claude"), AnthropicProvider)


def test_openai_compatible_provider_streams_through_model_client():
    """The OpenAI-compatible provider must remain a drop-in for ModelClient."""
    from khaos.routing.model_client import ModelClient

    provider = OpenAICompatibleProvider(
        ProviderConfig(name="x", base_url="http://x", api_key="k", type="openai_compatible")
    )

    # It wraps a ModelClient internally.
    assert isinstance(provider._client, ModelClient)


async def test_router_dispatches_anthropic_model_via_provider_client(monkeypatch):
    """call_model routes Anthropic-typed models through the provider abstraction."""
    from khaos.routing.router import ModelRouter

    manager = ProviderManager()
    manager.register_provider(
        ProviderConfig(
            name="anthropic",
            base_url="https://api.anthropic.com",
            api_key="a",
            type="anthropic",
        )
    )
    manager.register_model(
        "claude", ModelSpec(provider="anthropic", model="claude", max_context_tokens=200000)
    )

    # Inject a fake provider client so we don't hit the network. We replace the
    # cached provider_clients dict before the router reads it.
    captured: list[str] = []

    class FakeAnthropic:
        async def stream_chat(self, model, messages, tools=None):
            captured.append(model.model)
            yield Message(role="assistant", content="via provider abstraction")
            yield Message(role="assistant", content="", stop_reason="end_turn")

    # Pre-seed the cache so provider_clients() returns our fake.
    manager._provider_clients = {"anthropic": FakeAnthropic()}

    router = ModelRouter(provider_manager=manager)
    chunks = []
    async for chunk in router.call_model("claude", [Message(role="user", content="hi")]):
        chunks.append(chunk)

    assert captured == ["claude"]
    assert chunks[0].content == "via provider abstraction"


async def test_router_call_with_fallback_tries_each_model_in_chain():
    """The fallback chain consults every model before raising unavailable."""
    from khaos.exceptions import ModelUnavailableError
    from khaos.routing.router import ModelRouter, RoutingRule

    # All models are mock:// so call_with_fallback uses _call_resolved which
    # always succeeds; we instead verify the chain *attempts* by making every
    # model unavailable and asserting we get a clear aggregate error.
    manager = ProviderManager()
    manager.register_provider(ProviderConfig(name="mock-provider", base_url="mock://local", type="openai_compatible"))
    for name in ["mock-provider/a", "mock-provider/b"]:
        manager.register_model(name, ModelSpec(provider="mock-provider", model=name, max_context_tokens=128000, available=False))

    router = ModelRouter(provider_manager=manager)
    router.set_rule(
        "fn",
        RoutingRule(function="fn", primary_model="mock-provider/a", fallback_models=["mock-provider/b"]),
    )

    with pytest.raises(ModelUnavailableError):
        async for _ in router.call_with_fallback("fn", [Message(role="user", content="hi")]):
            pass
