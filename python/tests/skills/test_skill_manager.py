"""Tests for SkillManager matching, formatting, and CLI load/unload."""

from __future__ import annotations

from pathlib import Path

from khaos.skills import Skill, SkillManager, SkillRegistry


def _skill(name: str, triggers=None, category="general", body="") -> Skill:
    return Skill(
        name=name,
        description=f"{name} skill.",
        category=category,
        triggers=triggers or [],
        body=body or f"{name} body",
    )


def _registry(*skills: Skill) -> SkillRegistry:
    return SkillRegistry(list(skills))


def test_match_by_trigger_keyword():
    manager = SkillManager(
        _registry(_skill("py", triggers=["python", "pytest"]), _skill("web", triggers=["html"]))
    )

    matched = manager.match("office", "help me write python tests")

    assert [s.name for s in matched] == ["py"]


def test_match_is_case_insensitive_and_dedups():
    manager = SkillManager(_registry(_skill("py", triggers=["python"])))

    matched = manager.match("office", "PYTHON and Python")

    assert len(matched) == 1


def test_match_category_bonus_breaks_ties():
    manager = SkillManager(
        _registry(
            _skill("office-skill", triggers=["report"], category="office"),
            _skill("coding-skill", triggers=["report"], category="coding"),
        )
    )

    matched = manager.match("office", "write a report")

    # Both hit the same trigger once; office category matches mode -> bonus.
    assert matched[0].name == "office-skill"


def test_no_triggers_never_auto_matches():
    manager = SkillManager(_registry(_skill("manual")))  # no triggers
    assert manager.match("office", "anything") == []


def test_disabled_skill_excluded_from_match():
    registry = _registry(_skill("py", triggers=["python"]))
    manager = SkillManager(registry)
    registry.disable("py")

    assert manager.match("office", "python please") == []


def test_load_unload_forced_skills_always_injected():
    manager = SkillManager(_registry(_skill("manual"), _skill("py", triggers=["python"])))

    assert manager.load("manual") is True
    forced = manager.match("office", "nothing relevant")

    assert [s.name for s in forced] == ["manual"]
    assert manager.forced == ["manual"]

    assert manager.unload("manual") is True
    assert manager.match("office", "nothing relevant") == []


def test_load_unknown_skill_returns_false():
    manager = SkillManager(_registry())
    assert manager.load("ghost") is False


def test_format_for_prompt_renders_body():
    manager = SkillManager()
    text = manager.format_for_prompt([_skill("py", body="Use type hints.")])

    assert "# Active skills" in text
    assert "Skill: py" in text
    assert "Use type hints." in text


def test_format_for_prompt_empty_returns_empty():
    assert SkillManager().format_for_prompt([]) == ""


def test_match_limit_caps_results():
    skills = [_skill(f"s{i}", triggers=[f"k{i}"]) for i in range(10)]
    manager = SkillManager(_registry(*skills), match_limit=3)
    haystack = " ".join(f"k{i}" for i in range(10))

    matched = manager.match("office", haystack)

    assert len(matched) == 3


def test_load_from_dir_loads_skills(tmp_path):
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "SKILL.md").write_text(
        "---\nname: disk\ndescription: from disk.\ntriggers: [disk]\n---\nbody\n",
        encoding="utf-8",
    )
    manager = SkillManager()

    loaded = manager.load_from_dir(skills_dir)

    assert [s.name for s in loaded] == ["disk"]
    assert manager.match("office", "disk please")[0].name == "disk"
