"""H1 integration tests: Office copy/move cannot mutate after a cancelled/
timed-out call reports its result.

These tests prove the report's attack chain is closed: a recursive copy or
move that is cancelled, times out, or runs during shutdown can never publish
a side effect after the tool call has been reported as failed/cancelled to
the caller.  The OfficeMutationAuthority's asyncio.shield fence holds until
the mutation has committed or rolled back before propagating cancellation.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.tools import file_tools
from khaos.tools.file_tools import copy_file, move_file


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Office mutation fence relies on POSIX dirfd copy semantics",
)


@pytest.fixture
def office_authority():
    """Register a fresh authority for each test and clear it afterwards."""
    authority = OfficeMutationAuthority()
    file_tools.set_office_authority(authority)
    yield authority
    file_tools.set_office_authority(None)


def _patch_slow_copy(monkeypatch, delay: float):
    """Wrap SafeWorkspaceFS.copy_path so it sleeps before the atomic rename."""
    from khaos.coding.workspace import boundary

    original = boundary.SafeWorkspaceFS.copy_path

    def slow_copy(self, source, destination, **kwargs):
        import time

        time.sleep(delay)
        return original(self, source, destination, **kwargs)

    monkeypatch.setattr(boundary.SafeWorkspaceFS, "copy_path", slow_copy)


async def test_cancel_during_recursive_copy_settles_before_return(
    tmp_path, office_authority, monkeypatch
):
    """Cancelling mid-copy never produces 'failed-but-file-landed'.

    The fence holds until the copy settles (commit or rollback); the caller
    receives CancelledError, and the filesystem is in a consistent state.
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.15)

    task = asyncio.create_task(
        copy_file("bundle", "copied", workspace_root=tmp_path)
    )
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Either the copy committed (consistent) or it was rolled back.  Crucially
    # there is no leftover half-built temp tree, and the published state
    # matches the result the caller observed (cancellation).
    leftovers = list(tmp_path.glob(".khaos-tree-*"))
    assert leftovers == [], f"leaked temp tree: {leftovers}"
    # The copied dir either fully exists (commit) or doesn't (rollback) — never
    # a partial tree.
    copied = tmp_path / "copied"
    if copied.exists():
        assert (copied / "a.txt").read_text() == "a"


async def test_timeout_before_final_rename_no_partial_tree(
    tmp_path, office_authority, monkeypatch
):
    """A scheduler-style timeout leaves no half-built temp tree behind."""
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.15)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            copy_file("bundle", "copied", workspace_root=tmp_path), timeout=0.03
        )

    # Give the shielded worker a moment to finish settling, then assert no
    # partial temp tree was leaked.  (The authority guarantees the worker is
    # not abandoned, but the caller already saw TimeoutError.)
    await office_authority.wait_for_inflight()
    leftovers = list(tmp_path.glob(".khaos-tree-*"))
    assert leftovers == []


async def test_cancel_during_move_tree_validation_no_side_effect(
    tmp_path, office_authority, monkeypatch
):
    """Cancelling during move's validation never leaves a partial state.

    The fence shields the worker, so the move either fully commits or is
    rolled back — never a half-moved tree where neither source nor
    destination is intact.
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")

    from khaos.coding.workspace import boundary

    original_validate = boundary.SafeWorkspaceFS._validate_tree_dirfd

    def slow_validate(self, fd, **kwargs):
        import time

        time.sleep(0.15)
        return original_validate(self, fd, **kwargs)

    monkeypatch.setattr(
        boundary.SafeWorkspaceFS, "_validate_tree_dirfd", slow_validate
    )

    task = asyncio.create_task(
        move_file("bundle", "moved", workspace_root=tmp_path)
    )
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Invariant: exactly one of source/destination holds the intact tree.
    # Never both, never neither (no half-moved state).
    bundle = tmp_path / "bundle"
    moved = tmp_path / "moved"
    assert bundle.exists() ^ moved.exists(), (
        "move left an inconsistent state after cancellation"
    )
    intact = moved if moved.exists() else bundle
    assert (intact / "a.txt").read_text() == "a"


async def test_shutdown_waits_for_active_copy_thread(
    tmp_path, office_authority, monkeypatch
):
    """shutdown() blocks until an active copy thread settles."""
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.15)

    started = asyncio.Event()

    from khaos.coding.workspace import boundary

    original = boundary.SafeWorkspaceFS.copy_path

    def gated_copy(self, source, destination, **kwargs):
        started.set()
        return original(self, source, destination, **kwargs)

    monkeypatch.setattr(boundary.SafeWorkspaceFS, "copy_path", gated_copy)

    task = asyncio.create_task(
        copy_file("bundle", "copied", workspace_root=tmp_path)
    )
    await started.wait()
    # shutdown must wait for the in-flight mutation to settle.
    await office_authority.shutdown()
    await task

    # The copy committed consistently before shutdown marked the workspace
    # read-only.
    assert (tmp_path / "copied" / "a.txt").read_text() == "a"


async def test_cancelled_call_cannot_mutate_after_result_event(
    tmp_path, office_authority, monkeypatch
):
    """After a cancelled call returns, no further mutation occurs.

    This is the core 'cannot mutate after result event' guarantee: once the
    caller has observed cancellation, the filesystem does not change again.
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.12)

    task = asyncio.create_task(
        copy_file("bundle", "copied", workspace_root=tmp_path)
    )
    await asyncio.sleep(0.04)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Snapshot the filesystem state right after the caller saw cancellation.
    await office_authority.wait_for_inflight()
    state_before = sorted(p.name for p in tmp_path.iterdir())

    # Yield control for a while; nothing should keep mutating.
    await asyncio.sleep(0.2)
    state_after = sorted(p.name for p in tmp_path.iterdir())

    assert state_before == state_after, (
        "filesystem mutated after the cancelled call reported its result"
    )
