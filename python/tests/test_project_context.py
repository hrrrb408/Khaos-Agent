"""Tests for ProjectContextLoader (Phase 6)."""

from __future__ import annotations

from pathlib import Path

from khaos.project_context import ProjectContextLoader


def test_load_reads_khaos_md_from_project_root(tmp_path):
    (tmp_path / "KHAOS.md").write_text("# Khaos rules\nUse f-strings.", encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    assert "# Khaos rules" in content
    assert "Use f-strings." in content


def test_load_reads_agents_md_when_no_khaos_md(tmp_path):
    (tmp_path / "AGENTS.md").write_text("# Agent rules\nsnake_case only.", encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    assert "# Agent rules" in content
    assert "snake_case only." in content


def test_load_returns_empty_when_no_files(tmp_path):
    loader = ProjectContextLoader(tmp_path)
    assert loader.load() == ""


def test_load_returns_empty_when_project_root_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    loader = ProjectContextLoader(missing)
    assert loader.load() == ""


def test_load_returns_empty_when_project_root_is_none():
    loader = ProjectContextLoader(None)
    assert loader.load() == ""


def test_load_walks_up_to_find_root_context(tmp_path):
    """If project_root has no KHAOS.md, walk up the parent chain."""
    root = tmp_path / "project"
    nested = root / "python" / "khaos"
    nested.mkdir(parents=True)
    # KHAOS.md lives at the repo root, not the nested directory.
    (root / "KHAOS.md").write_text("ROOT_RULES_HERE", encoding="utf-8")

    loader = ProjectContextLoader(nested)
    content = loader.load()

    assert "ROOT_RULES_HERE" in content


def test_load_does_not_read_above_home(tmp_path, monkeypatch):
    """The upward walk must stop at home without reading home-level files."""
    # Force "home" to a controlled temp dir so we don't touch the real one.
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()
    (fake_home / "KHAOS.md").write_text("HOME_LEVEL_SHOULD_NOT_LOAD", encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    project = tmp_path / "project"
    project.mkdir()

    loader = ProjectContextLoader(project)
    content = loader.load()

    assert "HOME_LEVEL_SHOULD_NOT_LOAD" not in content
    assert content == ""


def test_load_scans_first_level_subdirectories(tmp_path):
    (tmp_path / "KHAOS.md").write_text("ROOT", encoding="utf-8")
    sub = tmp_path / "packages"
    sub.mkdir()
    (sub / "KHAOS.md").write_text("SUB_CORE", encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    # Root content comes first, subdirectory content after.
    assert content.index("ROOT") < content.index("SUB_CORE")
    assert "SUB_CORE" in content


def test_load_does_not_descend_into_nested_subdirectories(tmp_path):
    """Per spec, only first-level subdirectories are scanned."""
    (tmp_path / "KHAOS.md").write_text("ROOT", encoding="utf-8")
    nested = tmp_path / "packages" / "core"
    nested.mkdir(parents=True)
    (nested / "KHAOS.md").write_text("DEEP_NESTED_SHOULD_NOT_LOAD", encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    assert "DEEP_NESTED_SHOULD_NOT_LOAD" not in content


def test_load_skips_git_and_node_modules_subdirectories(tmp_path):
    (tmp_path / "KHAOS.md").write_text("ROOT", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "KHAOS.md").write_text("SHOULD_BE_SKIPPED", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "KHAOS.md").write_text("ALSO_SKIPPED", encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    assert "SHOULD_BE_SKIPPED" not in content
    assert "ALSO_SKIPPED" not in content


def test_load_dedupes_subdirectory_identical_to_root(tmp_path):
    identical = "SAME CONTENT EVERYWHERE"
    (tmp_path / "KHAOS.md").write_text(identical, encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "AGENTS.md").write_text(identical, encoding="utf-8")

    loader = ProjectContextLoader(tmp_path)
    content = loader.load()

    # Identical subdirectory content must not be duplicated.
    assert content.count(identical) == 1


def test_load_uses_cache_on_second_call(tmp_path):
    (tmp_path / "KHAOS.md").write_text("FIRST", encoding="utf-8")
    loader = ProjectContextLoader(tmp_path)

    first = loader.load()
    assert "FIRST" in first

    # Mutate the file on disk; cached result must be returned unchanged.
    (tmp_path / "KHAOS.md").write_text("SECOND", encoding="utf-8")
    second = loader.load()
    assert second == first
    assert "SECOND" not in second


def test_reload_clears_cache(tmp_path):
    (tmp_path / "KHAOS.md").write_text("FIRST", encoding="utf-8")
    loader = ProjectContextLoader(tmp_path)
    assert "FIRST" in loader.load()

    (tmp_path / "KHAOS.md").write_text("SECOND", encoding="utf-8")
    reloaded = loader.reload()
    assert "SECOND" in reloaded
    assert "FIRST" not in reloaded
