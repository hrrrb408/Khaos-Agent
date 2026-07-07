"""Integration test: AgentLoop injects matched skills into the system prompt."""

from __future__ import annotations

from khaos.agent import AgentConfig, AgentLoop
from khaos.db import Database
from khaos.modes import ModeManager
from khaos.routing.router import create_default_router
from khaos.skills import Skill, SkillManager, SkillRegistry


async def _setup(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.load()
    return db, mode_manager


def _skill_manager() -> SkillManager:
    return SkillManager(
        SkillRegistry(
            [
                Skill(
                    name="python-expert",
                    description="Python expert.",
                    triggers=["python"],
                    body="Always prefer type hints.",
                )
            ]
        )
    )


async def test_matched_skill_body_injected_into_system_prompt(tmp_path):
    db, mode_manager = await _setup(tmp_path)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        skill_manager=_skill_manager(),
    )

    # The system prompt is built internally per turn; assert via the helper.
    prompt = await loop._build_system_prompt("s1", "help with python")

    assert "office prompt" in prompt
    assert "Always prefer type hints." in prompt
    await db.close()


async def test_non_matching_skill_not_injected(tmp_path):
    db, mode_manager = await _setup(tmp_path)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        skill_manager=_skill_manager(),
    )

    prompt = await loop._build_system_prompt("s1", "tell me a joke")

    assert "office prompt" in prompt
    assert "Always prefer type hints." not in prompt
    await db.close()


async def test_no_skill_manager_keeps_existing_behavior(tmp_path):
    """skill_manager=None must not change the system prompt (backward compat)."""
    db, mode_manager = await _setup(tmp_path)
    loop = AgentLoop(AgentConfig(), mode_manager, create_default_router(), db)

    prompt = await loop._build_system_prompt("s1", "hello")

    assert prompt == "office prompt"
    await db.close()
