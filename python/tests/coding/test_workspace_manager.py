import asyncio
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.posix_host
from khaos.coding.workspace import manager as workspace_manager_module
from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES
from khaos.coding.workspace.git_identity import GitIdentityError
from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import WorkspaceState, WorkspaceTransition
from khaos.coding.workspace.trusted_git import WorkspaceBootstrapLimits
from khaos.security.authority_broker import AuthorityBrokerError


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
    assert not (workspace.worktree_path.parent / f"{changeset.id}.patch").exists()


@pytest.mark.asyncio
async def test_cleanup_retries_grant_revocation_after_git_resources_are_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-grant-revoke")
    assert await manager.transition(workspace.id, WorkspaceState.FAILED) is WorkspaceTransition.UPDATED

    original_revoke = manager._authority_broker.revoke_grant
    attempts = 0

    def fail_once(authority):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise AuthorityBrokerError("simulated grant revocation outage")
        return original_revoke(authority)

    monkeypatch.setattr(manager._authority_broker, "revoke_grant", fail_once)

    assert await manager.cleanup(workspace.id, force=True) is WorkspaceTransition.FAILED
    assert workspace.git_cleanup_complete
    assert await manager.cleanup(workspace.id, force=True) is WorkspaceTransition.UPDATED
    assert workspace.state is WorkspaceState.CLEANED


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
async def test_workspace_bootstrap_never_executes_repository_git_extensions(
    tmp_path: Path,
):
    """Host bootstrap must not run hooks, fsmonitor, or checkout filters."""
    repository = _repo(tmp_path / "repo")
    marker = tmp_path / "host-extension-ran"
    extension = tmp_path / "extension.sh"
    extension.write_text(
        f"#!/bin/sh\ntouch {marker}\nexit 0\n",
        encoding="utf-8",
    )
    extension.chmod(0o755)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "post-checkout").write_text(
        f"#!/bin/sh\ntouch {marker}\n",
        encoding="utf-8",
    )
    (hooks / "post-checkout").chmod(0o755)
    (repository / ".gitattributes").write_text(
        "README.md filter=sentinel\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", ".gitattributes"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "attributes"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "core.hooksPath", str(hooks)],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "core.fsmonitor", str(extension)],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "filter.sentinel.process", str(extension)],
        cwd=repository,
        check=True,
    )

    workspace = await WorkspaceManager(tmp_path / "worktrees").create(
        repository,
        "task-untrusted-git-extensions",
    )

    assert (workspace.worktree_path / "README.md").read_text() == "base\n"
    assert not marker.exists()


@pytest.mark.asyncio
async def test_workspace_bootstrap_enforces_independent_blob_quota_and_cleans_pending(
    tmp_path: Path,
):
    repository = _repo(tmp_path / "repo")
    (repository / "large.bin").write_bytes(b"x" * 128)
    subprocess.run(["git", "add", "large.bin"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "large"], cwd=repository, check=True)
    manager = WorkspaceManager(
        tmp_path / "worktrees",
        bootstrap_limits=WorkspaceBootstrapLimits(
            max_materialized_bytes=64,
            max_single_blob_bytes=64,
            max_tree_entries=100,
            max_path_depth=8,
            max_symlinks=4,
            max_duration_seconds=30,
        ),
    )

    with pytest.raises(WorkspaceError, match="single-blob|materialized-byte"):
        await manager.create(repository, "task-bootstrap-quota")

    assert manager._workspaces == {}
    assert list(manager.root.iterdir()) == []
    assert subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.count("worktree ") == 1


@pytest.mark.asyncio
async def test_workspace_bootstrap_publish_failure_cleans_final_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A post-publish identity failure cannot leave an unregistered worktree."""
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    original_capture = workspace_manager_module.capture_git_worktree_identity
    calls = 0

    def fail_after_publish(repository_root: Path, worktree_path: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise GitIdentityError("simulated final identity failure")
        return original_capture(repository_root, worktree_path)

    monkeypatch.setattr(
        workspace_manager_module,
        "capture_git_worktree_identity",
        fail_after_publish,
    )

    with pytest.raises(GitIdentityError, match="simulated final identity failure"):
        await manager.create(repository, "task-publish-failure")

    assert manager._workspaces == {}
    assert list(manager.root.iterdir()) == []
    assert subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.count("worktree ") == 1


@pytest.mark.asyncio
async def test_workspace_bootstrap_cancellation_rolls_back_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Cancellation during materialization cannot orphan a branch/worktree."""
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_materialize(*args, **kwargs):
        entered.set()
        await release.wait()

    monkeypatch.setattr(manager, "_materialize_git_tree", delayed_materialize)
    task = asyncio.create_task(manager.create(repository, "task-cancel-bootstrap"))
    await asyncio.wait_for(entered.wait(), timeout=10)
    assert manager._bootstrap_transactions
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert manager._bootstrap_transactions == {}
    assert manager._quarantined_bootstraps == {}
    assert manager._task_ids == set()
    assert list(manager.root.iterdir()) == []
    assert subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.count("worktree ") == 1


@pytest.mark.asyncio
async def test_workspace_bootstrap_rejects_gitlinks_without_submodule_update(
    tmp_path: Path,
):
    repository = _repo(tmp_path / "repo")
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", f"160000,{base_sha},submodule"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "gitlink"], cwd=repository, check=True)
    manager = WorkspaceManager(tmp_path / "worktrees")

    with pytest.raises(WorkspaceError, match="submodules/gitlinks"):
        await manager.create(repository, "task-gitlink")

    assert manager._workspaces == {}
    assert list(manager.root.iterdir()) == []


@pytest.mark.asyncio
async def test_trusted_diff_and_plumbing_commit_disable_textconv_filters_and_signing(
    tmp_path: Path,
):
    repository = _repo(tmp_path / "repo")
    marker = tmp_path / "extension-ran"
    extension = tmp_path / "extension.sh"
    extension.write_text(
        f"#!/bin/sh\ntouch {marker}\ncat\n",
        encoding="utf-8",
    )
    extension.chmod(0o755)
    (repository / ".gitattributes").write_text(
        "README.md diff=sentinel filter=sentinel\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", ".gitattributes"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "attributes"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "diff.sentinel.textconv", str(extension)],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "filter.sentinel.clean", str(extension)],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "commit.gpgSign", "true"], cwd=repository, check=True)
    subprocess.run(["git", "config", "gpg.program", str(extension)], cwd=repository, check=True)

    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-git-extensions")
    assert not marker.exists()
    (workspace.worktree_path / "README.md").write_text("changed\n", encoding="utf-8")
    changeset = await manager.build_changeset(workspace.id)
    assert changeset.artifact is not None
    assert not marker.exists()

    await manager.commit_in_worktree(workspace.id, changeset, "safe plumbing commit")
    assert not marker.exists()
    assert subprocess.run(
        ["git", "show", "HEAD:README.md"],
        cwd=workspace.worktree_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout == "changed\n"


@pytest.mark.asyncio
async def test_large_changeset_is_streamed_and_inline_read_is_bounded(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-large-diff")
    (workspace.worktree_path / "README.md").write_text("x" * (1024 * 1024 + 32), encoding="utf-8")

    changeset = await manager.build_changeset(workspace.id)
    assert changeset.artifact is not None
    assert changeset.artifact.byte_length > 1024 * 1024
    assert len(changeset.patch.encode("utf-8")) <= 64 * 1024
    with pytest.raises(WorkspaceError, match="large changesets|inline output"):
        await manager.read_changeset_patch(workspace.id, changeset)


@pytest.mark.asyncio
async def test_changeset_artifact_workspace_quota_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-artifact-quota")
    monkeypatch.setattr(workspace_manager_module, "MAX_CHANGESET_ARTIFACTS", 1)

    await manager.build_changeset(workspace.id)
    with pytest.raises(WorkspaceError, match="artifact quota"):
        await manager.build_changeset(workspace.id)


@pytest.mark.asyncio
async def test_plumbing_changeset_covers_untracked_and_deleted_files(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-file-set")
    (workspace.worktree_path / "README.md").unlink()
    (workspace.worktree_path / "new.txt").write_text("new\n", encoding="utf-8")

    changeset = await manager.build_changeset(workspace.id)
    assert set(changeset.changed_files) == {"README.md", "new.txt"}
    await manager.commit_in_worktree(workspace.id, changeset, "raw file set")
    assert not (workspace.worktree_path / "README.md").exists()
    assert (workspace.worktree_path / "new.txt").read_text(encoding="utf-8") == "new\n"


@pytest.mark.asyncio
async def test_sha256_repository_uses_64_character_object_ids(tmp_path: Path):
    repository = tmp_path / "sha256-repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", "--object-format=sha256"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)

    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-sha256")
    assert len(workspace.base_sha) == 64
    (workspace.worktree_path / "README.md").write_text("sha256\n", encoding="utf-8")
    changeset = await manager.build_changeset(workspace.id)
    assert len(changeset.base_sha) == 64
    await manager.commit_in_worktree(workspace.id, changeset, "sha256 plumbing")


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
async def test_host_git_rejects_constructed_authority_envelope(
    tmp_path: Path,
):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    authority = manager._authority_broker.envelope(
        principal_id="principal",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="git.status",
        resource_digest="resource",
    )

    with pytest.raises(WorkspaceError, match="AuthorityEnvelope is context only"):
        await manager._git(repository, "status", "--porcelain", authority=authority)  # type: ignore[arg-type]


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
