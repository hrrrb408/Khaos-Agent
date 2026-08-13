"""M4 control-plane ownership and descriptor-boundary regressions."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.posix_host
from khaos.coding.workspace.boundary import SafeWorkspaceFS
from khaos.coding.workspace.trusted_git import (
    TrustedGitError,
    TrustedGitProcessOwner,
    TrustedGitProcessState,
)


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
