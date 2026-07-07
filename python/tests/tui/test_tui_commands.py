"""Tests for TUI command dispatch (pure functions, no Textual app needed)."""

from __future__ import annotations

import pytest

from khaos.db import Database
from khaos.memory import Memory, MemoryScope, MemoryStore
from khaos.modes import Mode, ModeManager
from khaos.routing.router import create_default_router
from khaos.skills import Skill, SkillManager, SkillRegistry
from khaos.tui.commands import TuiContext, handle_command, is_command


async def _ctx(tmp_path, **kw) -> TuiContext:
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.load()
    store = MemoryStore(db)
    return TuiContext(
        mode_manager=mode_manager,
        memory_store=store,
        registry=_registry(),
        router=create_default_router(),
        db=db,
        skill_manager=_skill_manager(),
        **kw,
    )


def _registry():
    from khaos.tools import create_builtin_registry

    return create_builtin_registry()


def _skill_manager() -> SkillManager:
    return SkillManager(
        SkillRegistry([Skill(name="py", description="py.", triggers=["python"])])
    )


def test_is_command_detects_slash():
    assert is_command("/help")
    assert is_command("  /mode coding")
    assert not is_command("hello world")
    assert not is_command("")


async def test_help_command(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/help", ctx)

    assert result.handled is True
    assert "/mode" in result.message
    assert "/skills" in result.message


async def test_quit_command_signals_exit(tmp_path):
    quit_called = []
    ctx = await _ctx(tmp_path, on_quit=lambda: quit_called.append(True))
    result = await handle_command("/quit", ctx)

    assert result.handled is True
    assert result.should_quit is True
    assert quit_called == [True]


async def test_clear_command_signals_clear(tmp_path):
    cleared = []
    ctx = await _ctx(tmp_path, on_clear=lambda: cleared.append(True))
    result = await handle_command("/clear", ctx)

    assert result.handled is True
    assert result.should_clear is True
    assert cleared == [True]


async def test_mode_switch(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/mode coding", ctx)

    assert result.handled is True
    assert "coding" in result.message
    assert ctx.mode_manager.current_mode is Mode.CODING


async def test_mode_query_without_arg(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/mode", ctx)

    assert "office" in result.message


async def test_skills_list_delegates(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/skills list", ctx)

    assert result.handled is True
    assert "py" in result.message


async def test_memory_list_and_search(tmp_path):
    ctx = await _ctx(tmp_path)
    await ctx.memory_store.set(Memory(None, MemoryScope.GLOBAL, "user", "Ruibang"))

    listed = await handle_command("/memory list", ctx)
    searched = await handle_command("/memory search Ruibang", ctx)

    assert "Ruibang" in listed.message
    assert "Ruibang" in searched.message


async def test_tools_list(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/tools", ctx)

    assert result.handled is True
    assert "read_file" in result.message


async def test_unknown_command_reports_error(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("/frobnicate", ctx)

    assert result.handled is True
    assert "unknown" in result.message.lower()


async def test_non_command_not_handled(tmp_path):
    ctx = await _ctx(tmp_path)
    result = await handle_command("hello there", ctx)

    assert result.handled is False
