import os
import subprocess
from pathlib import Path

import pytest

from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import WorkspaceState, WorkspaceTransition
from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES


def _repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    (path / "README.md").write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)
    return path


@pytest.mark.asyncio
async def test_worktree_lifecycle_and_changeset_binding(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-1")
    assert workspace.state is WorkspaceState.READY
    for name in PROTECTED_WORKSPACE_NAMES:
        protected = workspace.worktree_path / name
        assert protected.exists()
        assert not protected.is_symlink()
    (workspace.worktree_path / "README.md").write_text("changed\n")
    changeset = await manager.build_changeset(workspace.id)
    assert "README.md" in changeset.changed_files
    assert (workspace.worktree_path.parent / f"{changeset.id}.patch").is_file()
    assert changeset.approval_key("apply").startswith(f"{workspace.id}:{changeset.id}:")
    assert await manager.transition(workspace.id, WorkspaceState.RUNNING) is WorkspaceTransition.UPDATED
    assert await manager.transition(workspace.id, WorkspaceState.CLEANED) is WorkspaceTransition.INVALID
    assert await manager.transition(workspace.id, WorkspaceState.FAILED) is WorkspaceTransition.UPDATED
    assert await manager.cleanup(workspace.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
async def test_changeset_commit_rejects_diff_drift(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-commit")
    (workspace.worktree_path / "README.md").write_text("one\n")
    changeset = await manager.build_changeset(workspace.id)
    (workspace.worktree_path / "README.md").write_text("two\n")
    with pytest.raises(WorkspaceError, match="stale"):
        await manager.commit_in_worktree(workspace.id, changeset, "change")


@pytest.mark.asyncio
async def test_dirty_main_worktree_is_rejected(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    (repository / "README.md").write_text("dirty\n")
    with pytest.raises(WorkspaceError, match="未提交修改"):
        await WorkspaceManager(tmp_path / "worktrees").create(repository, "task-1")


@pytest.mark.asyncio
async def test_git_pointer_redirection_is_rejected_before_host_git(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-git-pointer")
    main_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
        capture_output=True, text=True,
    ).stdout.strip()

    (workspace.worktree_path / ".git").write_text(
        f"gitdir: {repository / '.git'}\n", encoding="utf-8"
    )
    (workspace.worktree_path / "README.md").write_text("attacker\n")

    with pytest.raises(WorkspaceError, match="pointer"):
        await manager.build_changeset(workspace.id)
    assert subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
        capture_output=True, text=True,
    ).stdout.strip() == main_head


@pytest.mark.asyncio
async def test_git_pointer_inode_replacement_is_rejected(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-git-inode")
    pointer = workspace.worktree_path / ".git"
    content = pointer.read_bytes()
    replacement = workspace.worktree_path / ".git.replacement"
    replacement.write_bytes(content)
    os.replace(replacement, pointer)

    with pytest.raises(WorkspaceError, match="identity"):
        await manager.build_changeset(workspace.id)


@pytest.mark.asyncio
async def test_verify_execution_root_detects_worktree_swap(tmp_path: Path):
    """Round-14 §1: ``verify_execution_root`` re-checks the worktree root
    ``(dev, ino)`` immediately before subprocess launch, closing the TOCTOU
    window between ``require``/``verify_git_identity`` (early) and
    ``create_subprocess_exec`` (deep in the backend).  A swap that replaces
    the directory with a different inode must be detected here, before exec.
    """
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-swap")
    original = workspace.worktree_path

    # Sanity: the pinned identity matches the live directory.
    await manager.verify_execution_root(workspace.id)

    # Swap the worktree directory for a freshly-created one (different inode).
    # macOS refuses ``os.replace`` over a non-empty directory, so do a
    # two-step rename: move the original aside, then move a fresh directory
    # into its path.  The path now resolves to a different inode.
    parent = original.parent
    moved_aside = parent / "moved-aside-swap"
    os.rename(original, moved_aside)
    staging = parent / "staging-swap"
    staging.mkdir()
    os.rename(staging, original)

    with pytest.raises(WorkspaceError, match="drifted"):
        await manager.verify_execution_root(workspace.id)


@pytest.mark.asyncio
async def test_verify_execution_root_passes_for_stable_worktree(tmp_path: Path):
    """Round-14 §1: positive case — an unchanged worktree passes the
    pre-exec root-inode revalidation."""
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-stable")
    # No mutation between create and verify → must not raise.
    await manager.verify_execution_root(workspace.id)


@pytest.mark.asyncio
async def test_workspace_commit_disables_repository_hooks(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    marker = tmp_path / "hook-ran"
    hook = repository / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-no-hooks")
    (workspace.worktree_path / "README.md").write_text("safe\n")
    changeset = await manager.build_changeset(workspace.id)

    await manager.commit_in_worktree(workspace.id, changeset, "safe commit")

    assert not marker.exists()


@pytest.mark.asyncio
async def test_host_git_does_not_inherit_git_configuration_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    marker = tmp_path / "injected-git-alias-ran"
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "alias.status")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", f"!touch {marker}")

    assert await manager._git(repository, "status", "--porcelain") == ""
    assert not marker.exists()


@pytest.mark.asyncio
async def test_host_git_digest_drift_fails_before_execution(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    manager._git_digest = "0" * 64

    with pytest.raises(WorkspaceError, match="content digest drifted"):
        await manager._git(repository, "status", "--porcelain")


@pytest.mark.skipif(os.name == "nt", reason="Windows uses a fixed system Git path")
def test_host_git_authority_ignores_caller_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attacker = tmp_path / "git"
    attacker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    attacker.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    manager = WorkspaceManager(tmp_path / "worktrees")

    assert manager._git_executable == Path("/usr/bin/git").resolve(strict=True)


@pytest.mark.asyncio
async def test_workspace_authority_root_mode_drift_fails_before_git(
    tmp_path: Path,
):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    manager.root.chmod(0o777)

    try:
        with pytest.raises(WorkspaceError, match="authority root identity drifted"):
            await manager._git(repository, "status", "--porcelain")
    finally:
        manager.root.chmod(0o700)


def test_workspace_authority_rejects_preexisting_shared_root(tmp_path: Path):
    shared = tmp_path / "shared-worktrees"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)

    with pytest.raises(WorkspaceError, match="user-owned and not group/other writable"):
        WorkspaceManager(shared)
