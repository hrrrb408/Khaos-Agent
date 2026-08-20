"""M4 control-plane ownership and descriptor-boundary regressions."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.posix_host
from khaos.coding.workspace.boundary import SafeWorkspaceFS
from khaos.coding.workspace.trusted_git import (
    GitEffect,
    TrustedGitError,
    TrustedGitProcessOwner,
    TrustedGitProcessState,
    TrustedGitRunner,
    _run_sync_bounded,
)
from khaos.security.authority_broker import AuthorityBroker


@pytest.mark.asyncio
async def test_cancelled_git_owner_terminates_the_process_group() -> None:
    owner = TrustedGitProcessOwner(
        "test-cancel",
        terminate_grace_seconds=0.2,
        spawn_adoption_seconds=1.0,
    )
    await owner.spawn(
        sys.executable,
        "-c",
        "import time; time.sleep(60)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    task = asyncio.create_task(owner.communicate())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert owner.state is TrustedGitProcessState.CANCELLED
    assert owner.process is not None
    assert owner.process.returncode is not None


@pytest.mark.asyncio
async def test_late_spawn_is_reaped_after_adoption_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = TrustedGitProcessOwner(
        "test-late-cancel",
        terminate_grace_seconds=0.05,
        spawn_adoption_seconds=0.01,
    )
    real_spawn = asyncio.create_subprocess_exec
    release = asyncio.Event()

    async def delayed_spawn(
        *args: object, **kwargs: object
    ) -> asyncio.subprocess.Process:
        await release.wait()
        return await real_spawn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(
        owner.spawn(
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    )
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(TrustedGitError, match="could not be adopted"):
        await task
    release.set()
    for _ in range(100):
        if owner.process is not None and owner.process.returncode is not None:
            break
        await asyncio.sleep(0.01)
    assert owner.process is not None
    assert owner.process.returncode is not None


def test_sync_git_output_is_bounded_before_return(tmp_path: Path) -> None:
    stdout, stderr, returncode = _run_sync_bounded(
        [sys.executable, "-c", "import sys; print('ok'); print('err', file=sys.stderr)"],
        cwd=tmp_path,
        env={"PATH": os.defpath},
        max_stdout_bytes=64,
        max_stderr_bytes=64,
    )
    assert returncode == 0
    assert stdout == b"ok\n"
    assert stderr == b"err\n"

    with pytest.raises(TrustedGitError, match="stdout output exceeds"):
        _run_sync_bounded(
            [sys.executable, "-c", "print('x' * 200)"],
            cwd=tmp_path,
            env={"PATH": os.defpath},
            max_stdout_bytes=16,
            max_stderr_bytes=64,
        )


def test_safe_workspace_file_descriptor_survives_leaf_replacement(
    tmp_path: Path,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    target = worktree / "payload.txt"
    target.write_bytes(b"authority-bound content")
    with SafeWorkspaceFS(worktree) as filesystem:
        descriptor, expected = filesystem.open_regular_file("payload.txt")
        try:
            target.unlink()
            target.symlink_to(Path("/etc/passwd"))
            assert os.read(descriptor, 4096) == b"authority-bound content"
            final = os.fstat(descriptor)
            assert (final.st_dev, final.st_ino) == (expected.st_dev, expected.st_ino)
        finally:
            os.close(descriptor)


def test_git_update_ref_effect_binds_exact_cas_arguments(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    root_info = repository.stat()
    broker = AuthorityBroker()
    try:
        authority = broker.envelope(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            operation_class="git.workspace",
            resource_digest="resource",
        )
        capability = broker.issue(authority, allowed_operation="git.workspace")
        runner = TrustedGitRunner(
            executable=Path(sys.executable),
            git_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            git_digest="unused-for-binding-test",
            authority_root=repository,
            authority_root_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            authority_broker=broker,
        )
        effect = GitEffect.update_ref(
            repository_id=str(repository.resolve()),
            ref_name="refs/heads/khaos/task/task-1",
            new_oid="b" * 40,
            expected_old_oid="a" * 40,
        )
        runner._validate_effect_binding(
            repository,
            effect.args,
            effect,
            capability,
        )
        with pytest.raises(TrustedGitError, match="argv changed"):
            runner._validate_effect_binding(
                repository,
                (*effect.args[:-1], "c" * 40),
                effect,
                capability,
            )
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ["add", "move", "remove"])
def test_git_worktree_effect_is_strictly_bound_to_private_root(
    tmp_path: Path, operation: str
) -> None:
    root = tmp_path / "authority-root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    repository = tmp_path / "repo"
    repository.mkdir()
    root_info = root.stat()
    broker = AuthorityBroker()
    try:
        authority = broker.envelope(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            operation_class="git.workspace",
            resource_digest="resource",
        )
        capability = broker.issue(authority, allowed_operation="git.workspace")
        runner = TrustedGitRunner(
            executable=Path(sys.executable),
            git_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            git_digest="unused-for-binding-test",
            authority_root=root,
            authority_root_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            authority_broker=broker,
        )

        valid = root / "task-valid"
        if operation == "add":
            effect = GitEffect.worktree_add(
                repository_id=str(repository.resolve()),
                branch="khaos/task/valid",
                path=str(valid.resolve()),
                base_oid="b" * 40,
                required_operation="workspace",
            )
        elif operation == "move":
            effect = GitEffect.worktree_move(
                repository_id=str(repository.resolve()),
                source=str((root / "task-source").resolve()),
                destination=str(valid.resolve()),
                required_operation="workspace",
            )
        else:
            effect = GitEffect.worktree_remove(
                repository_id=str(repository.resolve()),
                path=str(valid.resolve()),
                required_operation="workspace",
            )
        runner._validate_effect_binding(repository, effect.args, effect, capability)
        assert runner.owned_resources() == ()

        if operation == "add":
            outside_effect = GitEffect.worktree_add(
                repository_id=str(repository.resolve()),
                branch="khaos/task/outside",
                path=str((outside / "task").resolve()),
                base_oid="b" * 40,
                required_operation="workspace",
            )
        elif operation == "move":
            outside_effect = GitEffect.worktree_move(
                repository_id=str(repository.resolve()),
                source=str((root / "task-source").resolve()),
                destination=str((outside / "task").resolve()),
                required_operation="workspace",
            )
        else:
            outside_effect = GitEffect.worktree_remove(
                repository_id=str(repository.resolve()),
                path=str((outside / "task").resolve()),
                required_operation="workspace",
            )
        with pytest.raises(TrustedGitError, match="outside the authority root"):
            runner._validate_effect_binding(
                repository, outside_effect.args, outside_effect, capability
            )
        assert runner.owned_resources() == ()

        root_effect = GitEffect.worktree_remove(
            repository_id=str(repository.resolve()),
            path=str(root.resolve()),
            required_operation="workspace",
        )
        with pytest.raises(TrustedGitError, match="authority root"):
            runner._validate_effect_binding(
                repository, root_effect.args, root_effect, capability
            )
        assert runner.owned_resources() == ()
    finally:
        broker.close()


def test_git_worktree_effect_rejects_symlink_escape_before_spawn(tmp_path: Path) -> None:
    root = tmp_path / "authority-root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="canonical"):
        GitEffect.worktree_add(
            repository_id=str((tmp_path / "repo").resolve()),
            branch="khaos/task/symlink",
            path=str(link / "task"),
            base_oid="b" * 40,
        )


def test_git_apply_effect_binds_patch_digest_and_length(tmp_path: Path) -> None:
    root = tmp_path / "authority-root"
    root.mkdir()
    repository = tmp_path / "repo"
    repository.mkdir()
    patch = root / "patch.apply"
    payload = b"diff --git a/file b/file\n"
    patch.write_bytes(payload)
    root_info = root.stat()
    broker = AuthorityBroker()
    try:
        authority = broker.envelope(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            operation_class="git.apply",
            resource_digest="resource",
        )
        capability = broker.issue(authority, allowed_operation="git.apply")
        runner = TrustedGitRunner(
            executable=Path(sys.executable),
            git_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            git_digest="unused-for-binding-test",
            authority_root=root,
            authority_root_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            authority_broker=broker,
        )
        effect = GitEffect.apply_index_file(
            repository_id=str(repository.resolve()),
            patch_path=str(patch.resolve()),
            patch_sha256=hashlib.sha256(payload).hexdigest(),
            patch_length=len(payload),
        )
        runner._validate_effect_binding(repository, effect.args, effect, capability)
        runner._verify_patch_file(effect)
        patch.write_bytes(b"tampered\n")
        with pytest.raises(TrustedGitError, match="digest or length"):
            runner._verify_patch_file(effect)
        with pytest.raises(ValueError, match="paired"):
            GitEffect.apply_index_file(
                repository_id=str(repository.resolve()),
                patch_path=str(patch.resolve()),
                patch_sha256=hashlib.sha256(payload).hexdigest(),
                patch_length=None,  # type: ignore[arg-type]
            )
    finally:
        broker.close()


@pytest.mark.asyncio
async def test_all_binary_and_sync_entries_reject_unbound_state_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    root_info = repository.stat()
    broker = AuthorityBroker()
    try:
        authority = broker.envelope(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            operation_class="git.workspace",
            resource_digest="resource",
        )
        runner = TrustedGitRunner(
            executable=Path(sys.executable),
            git_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            git_digest="unused-for-binding-test",
            authority_root=repository,
            authority_root_identity=(
                int(root_info.st_dev),
                int(root_info.st_ino),
                int(root_info.st_uid),
                int(root_info.st_mode),
            ),
            authority_broker=broker,
        )
        monkeypatch.setattr(runner, "_verify", lambda: None)

        def capability() -> object:
            return broker.issue(authority, allowed_operation="git.workspace")

        args = ("update-ref", "refs/heads/main", "b" * 40, "a" * 40)
        with pytest.raises(TrustedGitError, match="structured exact effect"):
            await runner.run_bytes(repository, *args, authority=capability())
        with pytest.raises(TrustedGitError, match="structured exact effect"):
            await runner.run_bytes_limited(
                repository,
                *args,
                authority=capability(),
                max_bytes=1024,
            )
        with pytest.raises(TrustedGitError, match="structured exact effect"):
            runner.run_sync(repository, *args, authority=capability())
        with pytest.raises(TrustedGitError, match="structured exact effect"):
            runner.run_sync_bytes(repository, *args, authority=capability())
    finally:
        broker.close()
