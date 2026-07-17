"""Unit tests for the OfficeMutationAuthority (H1 cancellation fence).

These tests prove the core safety property: a cancelled or timed-out Office
mutation never reports failure to the caller while the underlying thread later
commits a side effect.  The authority mirrors the Coding-mode
``mutate_with_storage_authority`` shield pattern, but is git-independent and
root-keyed.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

from khaos.coding.workspace.office_authority import (
    OfficeMutationAuthority,
    OfficeMutationError,
)
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
)


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Office mutation authority relies on POSIX dirfd semantics",
)


def _empty_mutation(value, *, rollback=None, finalize=None) -> WorkspaceMutation:
    return WorkspaceMutation(
        value=value,
        rollback=rollback or (lambda: None),
        finalize=finalize or (lambda: None),
    )


async def test_workspace_for_root_captures_baseline_once(tmp_path):
    authority = OfficeMutationAuthority(
        storage_limits=WorkspaceStorageLimits(512 * 1024 * 1024, 100_000)
    )
    (tmp_path / "seed.txt").write_text("seed", encoding="utf-8")

    first = await authority.workspace_for_root(tmp_path)
    second = await authority.workspace_for_root(tmp_path)

    assert first is second  # cached, single instance
    assert first.id.startswith("office-")
    assert first.baseline is not None and first.baseline.complete
    assert first.writable is True


async def test_mutation_runs_under_storage_authority(tmp_path):
    authority = OfficeMutationAuthority(
        storage_limits=WorkspaceStorageLimits(512 * 1024 * 1024, 100_000)
    )
    workspace = await authority.workspace_for_root(tmp_path)

    def op():
        (tmp_path / "created.txt").write_text("ok", encoding="utf-8")
        return _empty_mutation({"ok": True})

    result = await authority.mutate(workspace, op)
    assert result == {"ok": True}
    assert (tmp_path / "created.txt").read_text() == "ok"


async def test_cancelled_mutation_settles_before_propagating(tmp_path):
    """H1 core: cancelling the awaiting task does not abandon the worker.

    The worker sleeps (simulating a long copy) then commits.  Cancellation
    must NOT prevent the commit from finishing; the caller receives
    CancelledError, but the side effect has already settled consistently.
    """
    authority = OfficeMutationAuthority()
    workspace = await authority.workspace_for_root(tmp_path)

    started = asyncio.Event()
    committed = asyncio.Event()

    def op():
        started.set()
        # Simulate the blocking work of a recursive copy / final rename.
        import time

        time.sleep(0.15)
        (tmp_path / "settled.txt").write_text("committed", encoding="utf-8")
        committed.set()
        return _empty_mutation({"ok": True})

    task = asyncio.create_task(authority.mutate(workspace, op))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The worker was shielded — by the time the CancelledError propagated, the
    # side effect had already settled.  We never observe an inconsistent
    # state where the call "failed" but the filesystem later changed.
    assert committed.is_set()
    assert (tmp_path / "settled.txt").exists()


async def test_timeout_does_not_return_before_mutation_settles(tmp_path):
    """A scheduler timeout propagates only after the mutation settles."""
    authority = OfficeMutationAuthority()
    workspace = await authority.workspace_for_root(tmp_path)

    settled = asyncio.Event()

    def op():
        import time

        time.sleep(0.12)
        (tmp_path / "delayed.txt").write_text("done", encoding="utf-8")
        settled.set()
        return _empty_mutation({"ok": True})

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(authority.mutate(workspace, op), timeout=0.02)

    assert settled.is_set()
    assert (tmp_path / "delayed.txt").exists()


async def test_storage_violation_quarantines_and_marks_readonly(tmp_path):
    """A violation with an un-rollbackable mutation quarantines (fail closed).

    When rollback cannot restore the baseline (``quarantine_required=True``),
    the workspace is marked read-only so no further mutation runs without
    accounting.  A cleanly-rolled-back violation leaves it writable.
    """
    authority = OfficeMutationAuthority(
        storage_limits=WorkspaceStorageLimits(1, 1_000)  # 1 byte budget
    )
    workspace = await authority.workspace_for_root(tmp_path)

    def op():
        (tmp_path / "big.txt").write_text("x" * 64, encoding="utf-8")
        # rollback that "fails" → quarantine_required becomes True.
        def rollback():
            raise OSError("cannot undo")

        return _empty_mutation({"ok": True}, rollback=rollback)

    with pytest.raises(WorkspaceStorageViolation) as caught:
        await authority.mutate(workspace, op)
    assert caught.value.quarantine_required is True

    assert workspace.writable is False
    # Subsequent mutations fail closed immediately.
    with pytest.raises(OfficeMutationError, match="not writable"):
        await authority.mutate(workspace, lambda: _empty_mutation({"ok": True}))


async def test_cleanly_rolled_back_violation_keeps_workspace_writable(tmp_path):
    """A violation whose rollback restores the baseline is not quarantined."""
    authority = OfficeMutationAuthority(
        storage_limits=WorkspaceStorageLimits(1, 1_000)
    )
    workspace = await authority.workspace_for_root(tmp_path)

    def op():
        (tmp_path / "big.txt").write_text("x" * 64, encoding="utf-8")

        def rollback():
            (tmp_path / "big.txt").unlink(missing_ok=True)

        return _empty_mutation({"ok": True}, rollback=rollback)

    with pytest.raises(WorkspaceStorageViolation) as caught:
        await authority.mutate(workspace, op)
    assert caught.value.quarantine_required is False
    assert workspace.writable is True
    assert not (tmp_path / "big.txt").exists()


async def test_shutdown_waits_for_inflight_mutation(tmp_path):
    """shutdown() blocks until every in-flight worker has settled."""
    authority = OfficeMutationAuthority()
    workspace = await authority.workspace_for_root(tmp_path)

    started = asyncio.Event()
    settled = asyncio.Event()

    def op():
        started.set()
        import time

        time.sleep(0.1)
        (tmp_path / "during_shutdown.txt").write_text("ok", encoding="utf-8")
        settled.set()
        return _empty_mutation({"ok": True})

    # Start a mutation and do NOT await it.
    task = asyncio.create_task(authority.mutate(workspace, op))
    await started.wait()
    # shutdown must wait for the worker.
    await authority.shutdown()
    assert settled.is_set()
    assert (tmp_path / "during_shutdown.txt").exists()
    # Workspace is now read-only.
    assert workspace.writable is False
    # Clean up the task (it already settled).
    await task


async def test_incomplete_baseline_opens_readonly(tmp_path, monkeypatch):
    """If the baseline cannot be captured stably, the workspace fails closed."""

    def _incomplete_snapshot(root):
        from khaos.coding.workspace.storage import WorkspaceStorageSnapshot

        return WorkspaceStorageSnapshot({}, 0, False, {}, None)

    monkeypatch.setattr(
        "khaos.coding.workspace.office_authority.capture_workspace_snapshot",
        _incomplete_snapshot,
    )
    authority = OfficeMutationAuthority()
    workspace = await authority.workspace_for_root(tmp_path)

    assert workspace.writable is False
    with pytest.raises(OfficeMutationError, match="not writable"):
        await authority.mutate(workspace, lambda: _empty_mutation({"ok": True}))
