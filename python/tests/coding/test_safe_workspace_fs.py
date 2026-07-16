import json
import os
import sys
from types import SimpleNamespace

import pytest

from khaos.coding.workspace.boundary import (
    DEFAULT_FILE_TOOL_BYTES,
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
)
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState
from khaos.coding.workspace.storage import capture_workspace_snapshot
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


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="dirfd/O_NOFOLLOW workspace capability is POSIX-only",
)


def _workspace_manager(root):
    manager = WorkspaceManager(root=root.parent / "managed-worktrees")
    workspace = TaskWorkspace(
        id="ws",
        task_id="task",
        repository_root=root.parent,
        worktree_path=root,
        base_ref="HEAD",
        base_sha="base",
        branch_name="task/test",
        state=WorkspaceState.READY,
        writable_roots=(root,),
        storage_baseline=capture_workspace_snapshot(root),
        storage_limits=manager.storage_limits,
    )
    manager._workspaces[workspace.id] = workspace
    manager._task_ids.add(workspace.task_id)
    return manager


def test_safe_workspace_fs_atomic_create_update_and_read(tmp_path):
    target = tmp_path / "module.py"
    with SafeWorkspaceFS(tmp_path) as filesystem:
        filesystem.write_bytes("module.py", b"one\n")
        assert filesystem.read_bytes("module.py") == b"one\n"
        first_inode = target.stat().st_ino
        filesystem.write_bytes("module.py", b"two\n")
        assert filesystem.read_bytes("module.py") == b"two\n"
        assert target.stat().st_ino != first_inode


@pytest.mark.parametrize(
    "protected",
    [
        ".git/config", ".GIT/config", ".Git/config",
        ".agents/policy", ".AGENTS/policy",
        ".codex/config", ".CODEX/config",
        ".khaos/state", ".KHAOS/state",
    ],
)
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


def test_safe_workspace_fs_rejects_oversized_read_snapshot_and_copy(tmp_path):
    oversized = tmp_path / "oversized.bin"
    with oversized.open("wb") as stream:
        stream.truncate(DEFAULT_FILE_TOOL_BYTES + 1)

    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(WorkspaceBoundaryError, match="bounded|limit"):
            filesystem.read_bytes("oversized.bin")
        with pytest.raises(WorkspaceBoundaryError, match="size limit"):
            filesystem.snapshot_file("oversized.bin")
        with pytest.raises(WorkspaceBoundaryError, match="bounded"):
            filesystem.copy_file("oversized.bin", "copy.bin")
    assert not (tmp_path / "copy.bin").exists()


def test_snapshot_uses_private_recovery_file_and_streaming_restore(tmp_path):
    recovery = tmp_path.parent / f"{tmp_path.name}-recovery"
    recovery.mkdir(mode=0o700)
    target = tmp_path / "target.txt"
    target.write_text("before", encoding="utf-8")

    with SafeWorkspaceFS(tmp_path) as filesystem:
        before = filesystem.snapshot_file(
            "target.txt", recovery_root=recovery
        )
        assert before.recovery_path is not None
        assert before.recovery_path.read_bytes() == b"before"
        filesystem.write_bytes("target.txt", b"after")
        after = filesystem.snapshot_file("target.txt")
        filesystem.restore_file("target.txt", before, expected=after)
        before.cleanup()

    assert target.read_text(encoding="utf-8") == "before"
    assert list(recovery.iterdir()) == []


def test_copy_file_streams_without_read_bytes_heap_buffer(tmp_path, monkeypatch):
    (tmp_path / "source.bin").write_bytes(b"x" * 1024)
    with SafeWorkspaceFS(tmp_path) as filesystem:
        monkeypatch.setattr(
            filesystem,
            "read_bytes",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("copy must not buffer source in Runtime heap")
            ),
        )
        assert filesystem.copy_file("source.bin", "copy.bin") == 1024
    assert (tmp_path / "copy.bin").read_bytes() == b"x" * 1024


async def test_coding_file_tools_share_safe_workspace_capability(tmp_path):
    manager = _workspace_manager(tmp_path)
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
    manager = _workspace_manager(tmp_path)
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
