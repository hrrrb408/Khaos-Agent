import json
import os
from types import SimpleNamespace

import pytest

from khaos.coding.workspace.boundary import (
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
)
from khaos.tools.file_tools import (
    copy_file,
    file_search_content,
    list_directory,
    move_file,
    multi_edit,
    patch,
    read_file,
    search_files,
    tree_view,
    write_file,
)


def test_safe_workspace_fs_atomic_create_update_and_read(tmp_path):
    target = tmp_path / "module.py"
    with SafeWorkspaceFS(tmp_path) as filesystem:
        filesystem.write_bytes("module.py", b"one\n")
        assert filesystem.read_bytes("module.py") == b"one\n"
        first_inode = target.stat().st_ino
        filesystem.write_bytes("module.py", b"two\n")
        assert filesystem.read_bytes("module.py") == b"two\n"
        assert target.stat().st_ino != first_inode


@pytest.mark.parametrize("protected", [".git/config", ".agents/policy", ".codex/config", ".khaos/state"])
def test_safe_workspace_fs_rejects_protected_metadata(tmp_path, protected):
    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(WorkspaceBoundaryError, match="protected"):
            filesystem.write_bytes(protected, b"blocked")


def test_safe_workspace_fs_rejects_traversal_symlink_and_hardlink(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    original = tmp_path / "original"
    original.write_text("data", encoding="utf-8")
    os.link(original, tmp_path / "alias")

    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(WorkspaceBoundaryError, match="outside"):
            filesystem.write_bytes("../escape", b"blocked")
        with pytest.raises(WorkspaceBoundaryError):
            filesystem.write_bytes("link/secret", b"blocked")
        with pytest.raises(WorkspaceBoundaryError, match="hardlink"):
            filesystem.write_bytes("alias", b"blocked")
    assert (outside / "secret").read_text(encoding="utf-8") == "secret"
    assert original.read_text(encoding="utf-8") == "data"


async def test_coding_file_tools_share_safe_workspace_capability(tmp_path):
    workspace = SimpleNamespace(task_id="task", worktree_path=tmp_path)
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == "ws" else None)
    context = {"workspace_manager": manager, "task_id": "task", "workspace_id": "ws"}

    assert (await write_file("a.txt", "alpha beta", **context))["bytes"] == 10
    assert (await patch("a.txt", "beta", "gamma", fuzzy=False, **context))["replaced"] == 1
    edited = json.loads(await multi_edit(
        "a.txt", [{"old_text": "alpha", "new_text": "omega"}], **context
    ))
    assert edited["applied"] == 1
    assert (await copy_file("a.txt", "b.txt", **context))["ok"] is True
    assert (await move_file("b.txt", "c.txt", **context))["ok"] is True
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "omega gamma"
    assert (tmp_path / "c.txt").read_text(encoding="utf-8") == "omega gamma"


async def test_coding_file_tools_reject_symlink_parent(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-tools"
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    workspace = SimpleNamespace(task_id="task", worktree_path=tmp_path)
    manager = SimpleNamespace(get=lambda _workspace_id: workspace)
    with pytest.raises(WorkspaceBoundaryError):
        await write_file(
            "link/escape.txt", "blocked", workspace_manager=manager,
            task_id="task", workspace_id="ws",
        )
    assert not (outside / "escape.txt").exists()


async def test_coding_read_and_search_do_not_follow_workspace_symlinks(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-read"
    outside.mkdir()
    (outside / "secret.txt").write_text("HOST_SECRET", encoding="utf-8")
    (tmp_path / "safe.txt").write_text("visible needle", encoding="utf-8")
    (tmp_path / "leak.txt").symlink_to(outside / "secret.txt")
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    workspace = SimpleNamespace(task_id="task", worktree_path=tmp_path)
    manager = SimpleNamespace(get=lambda _workspace_id: workspace)
    context = {"workspace_manager": manager, "task_id": "task", "workspace_id": "ws"}

    with pytest.raises(WorkspaceBoundaryError):
        await read_file("leak.txt", **context)
    searched = await search_files(".", "HOST_SECRET", content=True, **context)
    assert searched["matches"] == []
    content_matches = await file_search_content(".", "HOST_SECRET", **context)
    assert content_matches["matches"] == []
    listing = await list_directory(".", **context)
    assert {item["name"] for item in listing["files"]} == {"safe.txt"}
    tree = await tree_view(".", **context)
    assert "leak.txt" not in tree["tree"] and "escape" not in tree["tree"]
