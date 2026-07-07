import pytest

from khaos.agent.core import Message
from khaos.exceptions import ModelUnavailableError
from khaos.routing.router import RoutingRule, create_default_router


async def test_router_resolves_default_rules():
    router = create_default_router()

    assert await router.resolve("agent_loop") == "mock-provider/mock-office"
    assert await router.resolve("coding") == "mock-provider/mock-coding"


async def test_router_streams_mock_chunks():
    router = create_default_router()
    chunks = [
        chunk.content
        async for chunk in router.call("agent_loop", [Message(role="user", content="hi")])
        if chunk.content
    ]

    assert "".join(chunks) == "Khaos mock response."


async def test_router_requires_rule():
    router = create_default_router()

    with pytest.raises(ModelUnavailableError):
        await router.resolve("missing")


async def test_custom_rule_can_be_registered():
    router = create_default_router()
    router.set_rule("summary", RoutingRule("summary", "mock-provider/mock-summary"))

    assert await router.resolve("summary") == "mock-provider/mock-summary"

