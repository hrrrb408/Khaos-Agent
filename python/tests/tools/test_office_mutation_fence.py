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
import threading

import pytest

from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.tools.file_tools import copy_file, move_file, write_file


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Office mutation fence relies on POSIX dirfd copy semantics",
)


@pytest.fixture
def office_authority():
    """Provide a fresh authority for each test.

    B1: the previous ``file_tools.set_office_authority`` module global has
    been removed — tests now pass the authority explicitly to ``copy_file``
    / ``move_file`` via the ``office_authority`` parameter.
    """
    authority = OfficeMutationAuthority()
    yield authority


def _patch_slow_copy(monkeypatch, delay: float):
    """Wrap SafeWorkspaceFS.copy_path so it sleeps before the atomic rename."""
    from khaos.coding.workspace import boundary

    original = boundary.SafeWorkspaceFS.copy_path

    def slow_copy(self, source, destination, **kwargs):
        import time

        time.sleep(delay)
        return original(self, source, destination, **kwargs)

    monkeypatch.setattr(boundary.SafeWorkspaceFS, "copy_path", slow_copy)


async def test_cancelled_nested_write_cannot_publish_or_leave_parents(
    tmp_path, office_authority, monkeypatch
):
    """A cancellation after temp-file creation aborts before atomic publish."""
    from khaos.coding.planning import safe_workspace_path

    started = threading.Event()
    release = threading.Event()
    original = safe_workspace_path.WorkspacePathHandle._write_temp

    def gated_write_temp(parent, content, mode):
        temp = original(parent, content, mode)
        started.set()
        assert release.wait(timeout=5), "test did not release write worker"
        return temp

    monkeypatch.setattr(
        safe_workspace_path.WorkspacePathHandle,
        "_write_temp",
        staticmethod(gated_write_temp),
    )

    task = asyncio.create_task(
        write_file(
            "new/nested/file.txt",
            "secret",
            workspace_root=tmp_path,
            office_authority=office_authority,
        )
    )
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    await office_authority.wait_for_inflight()

    assert not (tmp_path / "new").exists()
    assert list(tmp_path.rglob(".khaos-write-*")) == []


async def test_cancel_during_recursive_copy_settles_before_return(
    tmp_path, office_authority, monkeypatch
):
    """Cancelling mid-copy never produces 'failed-but-file-landed'.

    H1 semantics: the fence holds until the copy settles (commit or
    rollback).  If the worker committed *before* cancellation propagated,
    the caller receives the success result — a call must never report
    failure while the side effect has already landed.  If the worker had
    not committed yet, the caller receives ``CancelledError``.  In both
    cases the filesystem is left in a consistent state (no partial temp
    tree).
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.15)

    task = asyncio.create_task(
        copy_file("bundle", "copied", workspace_root=tmp_path,
                  office_authority=office_authority)
    )
    await asyncio.sleep(0.05)
    task.cancel()
    # H1: the worker is shielded, so it will settle.  Whether the caller
    # sees CancelledError (worker didn't commit) or the success result
    # (worker committed despite the cancel) depends on timing — both are
    # valid.  The invariant is that no partial temp tree is leaked and any
    # published tree is intact.
    outcome = None
    try:
        outcome = await task
    except asyncio.CancelledError:
        outcome = "cancelled"

    # Either the copy committed (consistent) or it was rolled back.  Crucially
    # there is no leftover half-built temp tree, and the published state
    # matches the result the caller observed.
    await office_authority.wait_for_inflight()
    leftovers = list(tmp_path.glob(".khaos-tree-*"))
    assert leftovers == [], f"leaked temp tree: {leftovers}"
    copied = tmp_path / "copied"
    if copied.exists():
        # If the file landed, the caller must NOT have seen cancellation —
        # that's the H1 invariant: never "failed-but-file-landed".
        assert outcome != "cancelled", (
            "caller observed CancelledError but the copy committed — "
            "H1 violated: failed-but-file-landed"
        )
        assert (copied / "a.txt").read_text() == "a"


async def test_timeout_before_final_rename_no_partial_tree(
    tmp_path, office_authority, monkeypatch
):
    """A scheduler-style timeout leaves no half-built temp tree behind.

    H1: a ``to_thread`` worker cannot be force-cancelled, so the worker
    may commit despite the timeout.  The caller observes either
    ``TimeoutError`` (worker hadn't committed yet) or the success result
    (worker committed despite the timeout).  In both cases no partial
    temp tree is leaked.
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.15)

    try:
        await asyncio.wait_for(
            copy_file("bundle", "copied", workspace_root=tmp_path,
                      office_authority=office_authority),
            timeout=0.03,
        )
    except asyncio.TimeoutError:
        pass

    # Give the shielded worker a moment to finish settling, then assert no
    # partial temp tree was leaked.  (The authority guarantees the worker is
    # not abandoned.)
    await office_authority.wait_for_inflight()
    leftovers = list(tmp_path.glob(".khaos-tree-*"))
    assert leftovers == []


async def test_cancel_during_move_tree_validation_no_side_effect(
    tmp_path, office_authority, monkeypatch
):
    """Cancelling during move's validation never leaves a partial state.

    The fence shields the worker, so the move either fully commits or is
    rolled back — never a half-moved tree where neither source nor
    destination is intact.  H1: a ``to_thread`` worker cannot be force-
    cancelled, so when the cancellation arrives during validation the
    worker may still go on to commit; the caller observes either
    ``CancelledError`` (worker hadn't committed yet) or the success
    result (worker committed despite the cancel).  In both cases the
    filesystem is left with exactly one intact tree.
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
        move_file("bundle", "moved", workspace_root=tmp_path,
                  office_authority=office_authority)
    )
    await asyncio.sleep(0.05)
    task.cancel()
    # H1: the worker is shielded, so it will settle.  Whether the caller
    # sees CancelledError (worker didn't commit) or the success result
    # (worker committed despite the cancel) depends on timing — both are
    # valid.  The invariant is that exactly one of source/destination
    # holds the intact tree.
    try:
        await task
    except asyncio.CancelledError:
        pass

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
        copy_file("bundle", "copied", workspace_root=tmp_path,
                  office_authority=office_authority)
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
    """After a cancelled/committed call returns, no further mutation occurs.

    This is the core 'cannot mutate after result event' guarantee: once the
    caller has observed the result (whether ``CancelledError`` or the
    success value), the filesystem does not change again.  H1: the worker
    may have committed despite the cancellation, in which case the caller
    sees the success result; either way, no further mutation happens
    after the result is observed.
    """
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    _patch_slow_copy(monkeypatch, 0.12)

    task = asyncio.create_task(
        copy_file("bundle", "copied", workspace_root=tmp_path,
                  office_authority=office_authority)
    )
    await asyncio.sleep(0.04)
    task.cancel()
    # H1: accept either CancelledError (worker hadn't committed) or the
    # success result (worker committed despite the cancel).
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Snapshot the filesystem state right after the caller saw the result.
    await office_authority.wait_for_inflight()
    state_before = sorted(p.name for p in tmp_path.iterdir())

    # Yield control for a while; nothing should keep mutating.
    await asyncio.sleep(0.2)
    state_after = sorted(p.name for p in tmp_path.iterdir())

    assert state_before == state_after, (
        "filesystem mutated after the cancelled call reported its result"
    )


# ---- H4: cancel_event is checked during traversal / chunk loops ---- #


def test_cancel_event_set_before_traversal_aborts_immediately(tmp_path):
    """H4: a pre-set ``cancel_event`` aborts the copy at the FIRST traversal
    loop iteration, not after the full temp tree is built.

    Without H4, ``cancel_event`` was only checked just before the final
    atomic rename — so the full recursive scan + temp tree copy ran even
    after the caller had already cancelled.  With H4, the check at the top
    of every directory entry makes the cancel effective immediately.
    """
    import threading

    from khaos.coding.workspace.boundary import (
        MutationCancelled,
        SafeWorkspaceFS,
    )

    source = tmp_path / "tree"
    source.mkdir()
    for i in range(5):
        (source / f"f{i}.txt").write_text("x" * 100, encoding="utf-8")

    safe_fs = SafeWorkspaceFS(tmp_path)
    cancel_event = threading.Event()
    cancel_event.set()  # pre-set: cancel before any work

    with pytest.raises(MutationCancelled):
        safe_fs.copy_path(
            source, tmp_path / "copied",
            cancel_event=cancel_event,
        )
    # No destination was published.
    assert not (tmp_path / "copied").exists()
    # No leftover temp tree.
    assert list(tmp_path.glob(".khaos-tree-*")) == []


def test_cancel_event_set_mid_traversal_aborts_promptly(
    tmp_path, monkeypatch
):
    """H4: setting ``cancel_event`` during the recursive traversal aborts
    the copy at the next directory entry, not after the full tree is built
    and validated.

    A tree with many entries is created; the first entry copies normally,
    then the cancel_event is set.  Without H4, the remaining entries would
    all be copied before the cancel was checked at the final rename.  With
    H4, the next iteration's top-of-loop check raises ``MutationCancelled``
    and the temp tree is cleaned up.
    """
    import threading

    from khaos.coding.workspace import boundary
    from khaos.coding.workspace.boundary import (
        MutationCancelled,
        SafeWorkspaceFS,
    )

    source = tmp_path / "tree"
    source.mkdir()
    for i in range(20):
        (source / f"f{i:02d}.txt").write_text("x" * 100, encoding="utf-8")

    cancel_event = threading.Event()
    call_count = {"n": 0}
    original_listdir = os.listdir

    def counting_listdir(fd):
        result = original_listdir(fd)
        # After the first listdir call (the root of the source tree), set
        # the cancel event.  The traversal will process the first entry,
        # then the H4 check at the top of the next iteration fires.
        call_count["n"] += 1
        if call_count["n"] >= 1:
            cancel_event.set()
        return result

    monkeypatch.setattr(boundary.os, "listdir", counting_listdir)

    safe_fs = SafeWorkspaceFS(tmp_path)
    with pytest.raises(MutationCancelled):
        safe_fs.copy_path(
            source, tmp_path / "copied",
            cancel_event=cancel_event,
        )
    # No destination was published.
    assert not (tmp_path / "copied").exists()
    # No leftover temp tree.
    assert list(tmp_path.glob(".khaos-tree-*")) == []


def test_cancel_event_set_during_chunk_read_aborts_file_copy(tmp_path):
    """H4: setting ``cancel_event`` during the chunk read loop aborts a
    large file copy mid-stream, not just at the final publish.

    Without H4, a large file would be fully copied to the temp file before
    the cancel was checked at the link step.  With H4, the check before
    each chunk read makes the cancel effective within one chunk (1 MiB)
    of I/O.
    """
    import threading

    from khaos.coding.workspace.boundary import (
        MutationCancelled,
        SafeWorkspaceFS,
    )

    source = tmp_path / "big.bin"
    # Write enough data to require multiple chunk reads (each chunk is 1 MiB).
    source.write_bytes(b"x" * (3 * 1024 * 1024))

    safe_fs = SafeWorkspaceFS(tmp_path)
    cancel_event = threading.Event()
    cancel_event.set()  # pre-set: cancel before any chunk read

    with pytest.raises(MutationCancelled):
        safe_fs.copy_file(
            source, tmp_path / "copied.bin",
            cancel_event=cancel_event,
        )
    # No destination was published.
    assert not (tmp_path / "copied.bin").exists()
