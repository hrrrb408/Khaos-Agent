"""Tests for SkillLoader frontmatter parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from khaos.skills import Skill, SkillLoader, SkillParseError


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_load_file_parses_frontmatter_and_body(tmp_path):
    file = _write(
        tmp_path / "SKILL.md",
        "---\n"
        "name: python-expert\n"
        "description: Python development expert.\n"
        "category: coding\n"
        "triggers: [python, pytest]\n"
        "---\n"
        "# Python expert\n"
        "Prefer type hints.\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.name == "python-expert"
    assert skill.description == "Python development expert."
    assert skill.category == "coding"
    assert skill.triggers == ["python", "pytest"]
    assert "Prefer type hints." in skill.body


def test_load_file_normalizes_triggers_lowercase_dedup(tmp_path):
    file = _write(
        tmp_path / "SKILL.md",
        "---\nname: s\ndescription: d.\ntriggers: [Python, python, PYTEST]\n---\nbody\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.triggers == ["python", "pytest"]


def test_load_file_missing_required_field_raises(tmp_path):
    file = _write(
        tmp_path / "SKILL.md", "---\nname: s\n---\nbody\n"
    )
    with pytest.raises(SkillParseError, match="description"):
        SkillLoader().load_file(file)


def test_load_all_skips_invalid_and_keeps_valid(tmp_path):
    _write(
        tmp_path / "good.md",
        "---\nname: good\ndescription: good skill.\n---\nbody\n",
    )
    _write(
        tmp_path / "bad.md",
        "---\nname: bad\n---\nbody\n",  # missing description
    )
    skills = SkillLoader([tmp_path]).load_all()

    assert [s.name for s in skills] == ["good"]


def test_load_all_first_match_wins_on_collision(tmp_path):
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    _write(root_a / "SKILL.md", "---\nname: dup\ndescription: first.\n---\nA\n")
    _write(root_b / "SKILL.md", "---\nname: dup\ndescription: second.\n---\nB\n")

    skills = SkillLoader([root_a, root_b]).load_all()

    assert len(skills) == 1
    assert skills[0].description == "first."


def test_file_without_frontmatter_raises(tmp_path):
    file = _write(tmp_path / "SKILL.md", "just markdown, no front matter at all\n")
    with pytest.raises(SkillParseError, match="frontmatter"):
        SkillLoader().load_file(file)


def test_hermes_minimal_format_supported(tmp_path):
    # Hermes/ZCode skills only carry name + description, no triggers/category.
    file = _write(
        tmp_path / "SKILL.md",
        "---\nname: minimalist\ndescription: A minimal skill.\n---\nbody\n",
    )
    skill = SkillLoader().load_file(file)

    assert skill.category == "general"
    assert skill.triggers == []


def test_load_from_subdirectory(tmp_path):
    sub = tmp_path / "python-expert"
    sub.mkdir()
    _write(
        sub / "SKILL.md",
        "---\nname: python-expert\ndescription: nested skill.\n---\nbody\n",
    )
    skills = SkillLoader([tmp_path]).load_all()

    assert [s.name for s in skills] == ["python-expert"]
