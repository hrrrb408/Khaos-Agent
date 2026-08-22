"""Structural tests for immutable routing state."""

from __future__ import annotations

import pytest
from khaos.routing import ModelRouter, RoutingRule, RoutingTable


def test_routing_rules_and_table_are_immutable() -> None:
    rule = RoutingRule("chat", "primary", ["fallback"])
    table = RoutingTable.empty().with_rule("chat", rule)

    assert rule.fallback_models == ("fallback",)
    assert table.get("chat") is rule
    with pytest.raises(TypeError):
        table.rules["other"] = rule  # type: ignore[index]

    replacement = table.with_rule(
        "chat", RoutingRule("chat", "new-primary")
    )
    assert table.get("chat") is rule
    assert replacement.get("chat").primary_model == "new-primary"


def test_routing_table_rejects_mismatched_keys_and_router_mutation() -> None:
    with pytest.raises(ValueError, match="does not match"):
        RoutingTable.empty().with_rule("chat", RoutingRule("coding", "primary"))

    router = ModelRouter()
    router.set_rule("chat", RoutingRule("chat", "mock-provider/mock-office"))
    with pytest.raises(TypeError):
        router._rules["coding"] = RoutingRule(  # type: ignore[index]
            "coding", "mock-provider/mock-coding"
        )
