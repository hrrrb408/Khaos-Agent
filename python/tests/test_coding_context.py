"""Tests for coding-mode context injection in AgentLoop._build_context."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.routing.router import create_default_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeIndexer:
    """Minimal RepoIndexer stand-in returning a fixed tree."""

    def __init__(self, tree: str):
        self._tree = tree

    def scan(self, project_root: Path) -> dict:
        return {
            "tree": self._tree,
            "files": [],
            "entry_files": [],
            "config_files": [],
            "test_dirs": [],
            "total_files": 3,
            "total_dirs": 1,
        }


class _FakeContextBuilder:
    """CodingContextBuilder stand-in capturing the build call + fixed output.

    Exposes ``.indexer`` (required by AgentLoop._build_project_structure) and
    records the task description it was called with.
    """

    def __init__(self, files: list[dict], tree: str = "fake_tree\n  main.py"):
        self._files = files
        self.indexer = _FakeIndexer(tree)
        self.calls: list[tuple[str, Path]] = []

    def build(self, task_description: str, project_root: Path, target_files=None):
        self.calls.append((task_description, project_root))
        return list(self._files)


async def _make_loop(
    tmp_path: Path,
    *,
    mode: Mode,
    builder=None,
    file_fingerprint_cache=None,
    cost_tracker=None,
) -> tuple[AgentLoop, Database]:
    """Build a minimal AgentLoop with the given mode + optional coding builder."""
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode=mode.value)
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.switch(mode)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        project_root=tmp_path,
        coding_context_builder=builder,
        file_fingerprint_cache=file_fingerprint_cache,
        cost_tracker=cost_tracker,
    )
    return loop, db


# ---------------------------------------------------------------------------
# Coding mode: project structure + relevant files injected
# ---------------------------------------------------------------------------


async def test_coding_mode_injects_project_structure_and_relevant_files(tmp_path):
    builder = _FakeContextBuilder(
        files=[
            {"path": tmp_path / "main.py", "content": "print('hi')\n", "relevance": "target"},
        ],
        tree="khaos/\n  main.py\n  tests/",
    )
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=builder)

    messages = await loop._build_context("s1", "edit main.py")
    await db.close()

    system_prompt = messages[0].content
    assert "# Project Structure" in system_prompt
    assert "main.py" in system_prompt
    # Relevant-files block is appended after persisted history as its own msg.
    relevant_msgs = [m for m in messages if "# Relevant Files" in m.content]
    assert len(relevant_msgs) == 1
    assert "## main.py" in relevant_msgs[0].content
    assert "```python" in relevant_msgs[0].content
    assert "print('hi')" in relevant_msgs[0].content
    # The builder received the task description.
    assert builder.calls == [("edit main.py", tmp_path.resolve())]


async def test_coding_mode_trims_large_project_tree_to_token_budget(tmp_path):
    huge_tree = "\n".join(f"file_{i}.py" for i in range(2000))
    builder = _FakeContextBuilder(files=[], tree=huge_tree)
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=builder)
    loop.config.project_structure_token_budget = 50  # force trimming

    messages = await loop._build_context("s1", "anything")
    await db.close()

    tree_block = messages[0].content.split("# Project Structure", 1)[1]
    assert "trimmed" in tree_block
    # Must be well under the untrimmed 2000-line tree.
    assert len(tree_block) < len(huge_tree)


async def test_coding_mode_omits_relevant_files_when_builder_returns_empty(tmp_path):
    builder = _FakeContextBuilder(files=[], tree="only_tree")
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=builder)

    messages = await loop._build_context("s1", "nothing matches")
    await db.close()

    assert "# Project Structure" in messages[0].content
    # No "# Relevant Files" message when build() returns [].
    assert not any("# Relevant Files" in m.content for m in messages)


# ---------------------------------------------------------------------------
# Office mode + no project_root: no injection
# ---------------------------------------------------------------------------


async def test_office_mode_does_not_inject_coding_context(tmp_path):
    # Builder present but mode is office → neither injection should happen.
    builder = _FakeContextBuilder(
        files=[{"path": tmp_path / "main.py", "content": "x\n", "relevance": "r"}],
        tree="should_not_appear",
    )
    loop, db = await _make_loop(tmp_path, mode=Mode.OFFICE, builder=builder)

    messages = await loop._build_context("s1", "summarize this")
    await db.close()

    assert "should_not_appear" not in messages[0].content
    assert "# Project Structure" not in messages[0].content
    assert not any("# Relevant Files" in m.content for m in messages)
    assert builder.calls == []


async def test_coding_mode_without_project_root_skips_injection(tmp_path):
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="coding")
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.switch(Mode.CODING)
    # project_root deliberately None — e.g. an office-only caller.
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        coding_context_builder=_FakeContextBuilder(files=[]),
    )

    messages = await loop._build_context("s1", "edit something")
    await db.close()

    assert "# Project Structure" not in messages[0].content
    assert not any("# Relevant Files" in m.content for m in messages)


async def test_coding_mode_without_builder_skips_injection(tmp_path):
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=None)

    messages = await loop._build_context("s1", "edit something")
    await db.close()

    assert "# Project Structure" not in messages[0].content
    assert not any("# Relevant Files" in m.content for m in messages)


# ---------------------------------------------------------------------------
# Robustness: a failing scan/build must not break the agent loop
# ---------------------------------------------------------------------------


class _ExplodingBuilder:
    def __init__(self):
        self.indexer = SimpleNamespace(scan=self._boom)

    @staticmethod
    def _boom(_root):
        raise RuntimeError("disk on fire")

    def build(self, _task, _root, target_files=None):
        raise RuntimeError("disk on fire")


async def test_coding_mode_survives_scan_and_build_failures(tmp_path):
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=_ExplodingBuilder())

    messages = await loop._build_context("s1", "edit something")
    await db.close()

    # System prompt still loads (no structure), no relevant-files message, no raise.
    assert messages[0].content.startswith("coding prompt")
    assert "# Project Structure" not in messages[0].content
    assert not any("# Relevant Files" in m.content for m in messages)


# ---------------------------------------------------------------------------
# Language hint mapping for fenced blocks
# ---------------------------------------------------------------------------


def test_language_for_path_maps_common_suffixes():
    assert AgentLoop._language_for_path("a.py") == "python"
    assert AgentLoop._language_for_path("b.go") == "go"
    assert AgentLoop._language_for_path("c.rs") == "rust"
    assert AgentLoop._language_for_path("d.tsx") == "tsx"
    assert AgentLoop._language_for_path("README.md") == "markdown"
    assert AgentLoop._language_for_path("Makefile") == ""


# ---------------------------------------------------------------------------
# Phase 6.3: fingerprint cache skips unchanged relevant files
# ---------------------------------------------------------------------------


async def test_relevant_files_skips_unchanged_files_via_fingerprint_cache(tmp_path):
    """On the second build the unchanged file is skipped (cache hit)."""
    from khaos.coding.fingerprint import FileFingerprintCache

    builder = _FakeContextBuilder(
        files=[
            {"path": tmp_path / "main.py", "content": "print('hi')\n", "relevance": "target"},
        ],
    )
    cache = FileFingerprintCache()
    loop, db = await _make_loop(
        tmp_path, mode=Mode.CODING, builder=builder, file_fingerprint_cache=cache
    )

    # First build: file is new → injected as (changed).
    first = await loop._build_context("s1", "edit main.py")
    first_relevant = next(m for m in first if "# Relevant Files" in m.content)
    assert "## main.py (changed)" in first_relevant.content
    assert "print('hi')" in first_relevant.content
    assert cache.size == 1

    # Second build: identical content → file skipped entirely.
    second = await loop._build_context("s1", "edit main.py")
    second_relevant = [m for m in second if "# Relevant Files" in m.content]
    assert second_relevant == []  # nothing to inject this turn
    await db.close()


async def test_relevant_files_injects_only_changed_file_when_one_changes(tmp_path):
    """When one of two files changes, only the changed one is injected."""
    from khaos.coding.fingerprint import FileFingerprintCache

    builder = _FakeContextBuilder(
        files=[
            {"path": tmp_path / "a.py", "content": "A1\n", "relevance": "r"},
            {"path": tmp_path / "b.py", "content": "B1\n", "relevance": "r"},
        ],
    )
    cache = FileFingerprintCache()
    loop, db = await _make_loop(
        tmp_path, mode=Mode.CODING, builder=builder, file_fingerprint_cache=cache
    )

    # Prime the cache with both files.
    await loop._build_context("s1", "edit")
    assert cache.size == 2

    # Now mutate only b.py.
    builder._files = [
        {"path": tmp_path / "a.py", "content": "A1\n", "relevance": "r"},
        {"path": tmp_path / "b.py", "content": "B2-CHANGED\n", "relevance": "r"},
    ]

    second = await loop._build_context("s1", "edit")
    relevant = next(m for m in second if "# Relevant Files" in m.content)
    # a.py skipped (unchanged), only b.py injected and annotated (changed).
    assert "a.py" not in relevant.content
    assert "## b.py (changed)" in relevant.content
    assert "B2-CHANGED" in relevant.content
    await db.close()


async def test_relevant_files_logs_skipped_count(caplog, tmp_path):
    """When the cache skips files, an info log records the count."""
    import logging as _logging

    from khaos.coding.fingerprint import FileFingerprintCache

    builder = _FakeContextBuilder(
        files=[
            {"path": tmp_path / "a.py", "content": "A1\n", "relevance": "r"},
            {"path": tmp_path / "b.py", "content": "B1\n", "relevance": "r"},
        ],
    )
    cache = FileFingerprintCache()
    loop, db = await _make_loop(
        tmp_path, mode=Mode.CODING, builder=builder, file_fingerprint_cache=cache
    )
    # Prime cache.
    await loop._build_context("s1", "edit")

    with caplog.at_level(_logging.INFO, logger="khaos.agent.core"):
        await loop._build_context("s1", "edit")

    assert any("skipped 2 unchanged files" in r.message for r in caplog.records)
    await db.close()


async def test_relevant_files_without_cache_always_annotates_changed(tmp_path):
    """No fingerprint cache → every file is annotated (changed)."""
    builder = _FakeContextBuilder(
        files=[
            {"path": tmp_path / "main.py", "content": "print('hi')\n", "relevance": "r"},
        ],
    )
    loop, db = await _make_loop(tmp_path, mode=Mode.CODING, builder=builder)

    messages = await loop._build_context("s1", "edit main.py")
    relevant = next(m for m in messages if "# Relevant Files" in m.content)
    assert "## main.py (changed)" in relevant.content
    await db.close()


async def test_agent_loop_yields_cost_summary_when_tracker_configured(tmp_path):
    """With a CostTracker, run() emits a cost_summary system message at the end."""
    from khaos.coding.cost_tracker import CostTracker

    builder = _FakeContextBuilder(files=[], tree="t")
    tracker = CostTracker("s1")
    loop, db = await _make_loop(
        tmp_path, mode=Mode.CODING, builder=builder, cost_tracker=tracker
    )

    events = [message async for message in loop.run("hello", "s1")]

    cost_msgs = [m for m in events if m.event == "cost_summary"]
    assert len(cost_msgs) == 1
    assert "📊 Session Cost:" in cost_msgs[0].content
    # At least one turn was recorded.
    assert tracker.get_report().turn_count >= 1
    await db.close()
