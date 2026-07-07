"""Tests for /skills slash-command parsing."""

from __future__ import annotations

from khaos.cli.skills_commands import handle_skills_command
from khaos.skills import Skill, SkillManager, SkillRegistry


def _manager() -> SkillManager:
    return SkillManager(
        SkillRegistry(
            [
                Skill(name="py", description="py.", triggers=["python"], body="py body"),
                Skill(name="manual", description="manual."),
            ]
        )
    )


def test_non_skills_command_not_handled():
    result = handle_skills_command("hello world", _manager())

    assert result.handled is False


def test_list_shows_all_skills():
    result = handle_skills_command("/skills", _manager())

    assert result.handled is True
    assert "py" in result.message
    assert "manual" in result.message


def test_load_marks_forced_and_annotates():
    manager = _manager()
    result = handle_skills_command("/skills load manual", manager)

    assert result.handled is True
    assert "manual" in result.message
    assert "manual" in manager.forced


def test_load_unknown_reports_error():
    result = handle_skills_command("/skills load ghost", _manager())

    assert result.handled is True
    assert "ghost" in result.message


def test_unload_removes_forced():
    manager = _manager()
    handle_skills_command("/skills load manual", manager)

    result = handle_skills_command("/skills unload manual", manager)

    assert result.handled is True
    assert "manual" not in manager.forced


def test_bad_subcommand_shows_usage():
    result = handle_skills_command("/skills frobnicate", _manager())

    assert result.handled is True
    assert "usage" in result.message.lower()
