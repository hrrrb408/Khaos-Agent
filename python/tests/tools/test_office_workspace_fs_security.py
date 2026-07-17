import os

import pytest

from khaos.coding.workspace.boundary import (
    DEFAULT_FILE_TOOL_BYTES,
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
)
from khaos.tools.file_tools import copy_file, move_file, read_file


async def test_office_read_requires_internal_workspace_capability(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("safe", encoding="utf-8")

    with pytest.raises(PermissionError, match="Workspace root capability"):
        await read_file(str(target))


async def test_office_read_cannot_escape_capability_root(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    with pytest.raises(WorkspaceBoundaryError, match="outside task worktree"):
        await read_file(str(outside), workspace_root=workspace)


async def test_office_read_rejects_runtime_memory_dos_file(tmp_path):
    target = tmp_path / "large.txt"
    target.write_bytes(b"x" * (DEFAULT_FILE_TOOL_BYTES + 1))

    with pytest.raises(WorkspaceBoundaryError, match="bounded file size"):
        await read_file("large.txt", workspace_root=tmp_path)


async def test_office_recursive_copy_is_bounded_and_no_follow(tmp_path):
    workspace = tmp_path / "workspace"
    source = workspace / "bundle"
    source.mkdir(parents=True)
    (source / "safe.txt").write_text("safe", encoding="utf-8")
    outside = tmp_path / "host-secret"
    outside.mkdir()
    (outside / "secret.txt").write_text("HOST_SECRET", encoding="utf-8")
    (source / "leak").symlink_to(outside, target_is_directory=True)

    result = await copy_file("bundle", "copied", workspace_root=workspace)

    assert result["ok"] is False
    assert "symlink" in result["error"]
    assert not (workspace / "copied").exists()
    assert not any(workspace.glob(".khaos-tree-*"))


async def test_office_recursive_copy_rejects_hardlinks(tmp_path):
    workspace = tmp_path / "workspace"
    source = workspace / "bundle"
    source.mkdir(parents=True)
    original = source / "original.txt"
    original.write_text("secret", encoding="utf-8")
    os.link(original, source / "alias.txt")

    result = await copy_file("bundle", "copied", workspace_root=workspace)

    assert result["ok"] is False
    assert "hardlink" in result["error"]
    assert not (workspace / "copied").exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
async def test_office_recursive_copy_rejects_fifo(tmp_path):
    workspace = tmp_path / "workspace"
    source = workspace / "bundle"
    source.mkdir(parents=True)
    os.mkfifo(source / "pipe")

    result = await copy_file("bundle", "copied", workspace_root=workspace)

    assert result["ok"] is False
    assert "special file" in result["error"]
    assert not (workspace / "copied").exists()


async def test_office_recursive_copy_succeeds_without_unsafe_objects(tmp_path):
    source = tmp_path / "bundle"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (source / "a.txt").write_text("a", encoding="utf-8")
    (nested / "b.txt").write_text("bb", encoding="utf-8")

    result = await copy_file("bundle", "copied", workspace_root=tmp_path)

    assert result["ok"] is True
    assert result["size_bytes"] == 3
    assert (tmp_path / "copied" / "nested" / "b.txt").read_text() == "bb"


async def test_office_copy_and_move_reject_destination_inside_source(tmp_path):
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")

    copy_result = await copy_file(
        "bundle", "bundle/copied", workspace_root=tmp_path
    )
    move_result = await move_file(
        "bundle", "bundle/moved", workspace_root=tmp_path
    )

    assert copy_result["ok"] is False
    assert "inside the source tree" in copy_result["error"]
    assert move_result["ok"] is False
    assert "inside the source tree" in move_result["error"]
    assert source.exists()


async def test_office_move_rejects_tree_with_nested_symlink(tmp_path):
    source = tmp_path / "bundle"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source / "leak").symlink_to(outside, target_is_directory=True)

    result = await move_file("bundle", "moved", workspace_root=tmp_path)

    assert result["ok"] is False
    assert "symlink" in result["error"]
    assert source.exists()
    assert not (tmp_path / "moved").exists()


def test_recursive_copy_enforces_bytes_entries_and_depth(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("abcd", encoding="utf-8")
    (source / "b.txt").write_text("efgh", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    (nested / "c.txt").write_text("i", encoding="utf-8")

    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(WorkspaceBoundaryError, match="byte limit"):
            filesystem.copy_path("source", "bytes", max_bytes=4)
        with pytest.raises(WorkspaceBoundaryError, match="entry limit"):
            filesystem.copy_path("source", "entries", max_entries=1)
        with pytest.raises(WorkspaceBoundaryError, match="depth limit"):
            filesystem.copy_path("source", "depth", max_depth=0)

    assert not any((tmp_path / name).exists() for name in ("bytes", "entries", "depth"))


def test_recursive_copy_detects_source_swap_after_check(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    target = source / "value.txt"
    target.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    real_open = os.open
    swapped = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "value.txt" and not swapped and not flags & os.O_CREAT:
            swapped = True
            target.unlink()
            target.symlink_to(outside)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(OSError):
            filesystem.copy_path("source", "copied")

    assert not (tmp_path / "copied").exists()
    assert not any(tmp_path.glob(".khaos-tree-*"))
