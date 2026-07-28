"""Deterministic adversarial fuzzing for production tool schemas."""

from __future__ import annotations

import random

from khaos.tools.registry import create_runtime_registry


def _random_json(randomizer: random.Random, depth: int = 0):
    leaves = [None, True, False, -1, 0, 1, 10**18, "", "x" * 1024]
    if depth >= 3:
        return randomizer.choice(leaves)
    choices = leaves + [
        [_random_json(randomizer, depth + 1) for _ in range(randomizer.randrange(4))],
        {
            f"field_{index}": _random_json(randomizer, depth + 1)
            for index in range(randomizer.randrange(4))
        },
    ]
    return randomizer.choice(choices)


def test_every_production_tool_rejects_unknown_model_fields():
    registry = create_runtime_registry()
    for name in registry.names():
        schema = registry.get(name).parameters
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert registry.validate_call(name, {"__unknown_model_field__": True}) is False


def test_schema_validator_is_total_for_adversarial_json_values():
    registry = create_runtime_registry()
    randomizer = random.Random(0x4B48414F53)
    for name in registry.names():
        for _ in range(64):
            candidate = _random_json(randomizer)
            if not isinstance(candidate, dict):
                candidate = {"value": candidate}
            result = registry.validate_call(name, candidate)
            assert type(result) is bool


def test_model_cannot_inject_internal_capabilities():
    registry = create_runtime_registry()
    injected = (
        "execution_service",
        "workspace_manager",
        "approval_context",
        "principal_id",
        "project_id",
        "runtime_id",
        "network_guard",
        "credential_context",
        "process_supervisor",
        "browser_manager",
        "cron_engine",
        "subagent_spawner",
    )
    for name in registry.names():
        for field in injected:
            assert registry.validate_call(name, {field: object()}) is False
