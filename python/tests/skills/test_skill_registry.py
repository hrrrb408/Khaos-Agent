"""Tests for SkillRegistry CRUD and enable/disable."""

from __future__ import annotations

import pytest

from khaos.skills import Skill, SkillRegistry, SkillParseError


def _skill(name: str, category: str = "general", triggers=None) -> Skill:
    return Skill(
        name=name,
        description=f"{name} description.",
        category=category,
        triggers=triggers or [],
    )


def test_register_and_get():
    registry = SkillRegistry()
    registry.register(_skill("a"))

    assert "a" in registry
    assert registry.get("a").name == "a"
    assert len(registry) == 1


def test_duplicate_register_raises():
    registry = SkillRegistry([_skill("a")])
    with pytest.raises(SkillParseError, match="already registered"):
        registry.register(_skill("a"))


def test_unregister_removes_skill():
    registry = SkillRegistry([_skill("a")])
    removed = registry.unregister("a")

    assert removed.name == "a"
    assert "a" not in registry
    with pytest.raises(SkillParseError):
        registry.unregister("a")


def test_list_filters_by_category_and_enabled():
    registry = SkillRegistry(
        [
            _skill("a", category="coding"),
            _skill("b", category="office"),
            _skill("c", category="coding"),
        ]
    )
    registry.disable("c")

    assert [s.name for s in registry.list(category="coding")] == ["a", "c"]
    assert [s.name for s in registry.list(category="coding", only_enabled=True)] == ["a"]
    assert registry.categories() == ["coding", "office"]


def test_enable_disable_toggles_state():
    registry = SkillRegistry([_skill("a")])
    registry.disable("a")

    assert registry.get("a").enabled is False

    registry.enable("a")
    assert registry.get("a").enabled is True


def test_get_unknown_raises():
    with pytest.raises(SkillParseError):
        SkillRegistry().get("nope")
