import pytest

from khaos.agent import Message
from khaos.exceptions import ModelUnavailableError
from khaos.routing import ModelSpec, ModelRouter, ProviderConfig, ProviderManager, RoutingRule


def _manager() -> ProviderManager:
    manager = ProviderManager()
    manager.register_provider(ProviderConfig("mock", "mock://local"))
    manager.register_model("primary", ModelSpec("mock", "primary-model", 1000, available=True))
    manager.register_model("fallback", ModelSpec("mock", "fallback-model", 1000, available=True))
    manager.register_model("down", ModelSpec("mock", "down-model", 1000, available=False))
    return manager


async def test_resolve_model_returns_model_spec():
    router = ModelRouter(_manager())
    router.set_rule("chat", RoutingRule("chat", "primary", ["fallback"]))

    spec = await router.resolve_model("chat")

    assert spec.model == "primary-model"


async def test_resolve_falls_back_when_primary_unavailable():
    router = ModelRouter(_manager())
    router.set_rule("chat", RoutingRule("chat", "down", ["fallback"]))

    spec = await router.resolve_model("chat")

    assert spec.model == "fallback-model"


async def test_resolve_raises_when_all_unavailable():
    router = ModelRouter(_manager())
    router.set_rule("chat", RoutingRule("chat", "down", []))

    with pytest.raises(ModelUnavailableError):
        await router.resolve_model("chat")


async def test_call_streams_with_provider_manager():
    router = ModelRouter(_manager(), mock_response="hello model")
    router.set_rule("chat", RoutingRule("chat", "primary", []))

    chunks = [
        chunk.content async for chunk in router.call("chat", [Message("user", "hello")]) if chunk.content
    ]
    content = "".join(chunks)

    assert content == "hello model"


async def test_call_with_fallback_uses_available_fallback():
    router = ModelRouter(_manager(), mock_response="fallback ok")
    router.set_rule("chat", RoutingRule("chat", "down", ["fallback"]))

    chunks = [
        chunk.content
        async for chunk in router.call_with_fallback("chat", [Message("user", "hello")])
        if chunk.content
    ]
    content = "".join(chunks)

    assert content == "fallback ok"
