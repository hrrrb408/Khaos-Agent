"""M1: Office aggregate storage accounting and limit enforcement.

Before the OfficeMutationAuthority, Office copy/move had only a *per-call*
cap (64 MiB / 4096 entries).  Repeated copies of the same directory could
grow the workspace and host disk without bound: 64 MiB × N calls in a single
budget cycle.

With the authority, every Office root now has a durable baseline +
WorkspaceStorageLimits (aggregate bytes / entries).  Repeated mutations that
exceed the *total* budget raise WorkspaceStorageViolation and roll back.
"""

import sys
from pathlib import Path

import pytest

from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
)
from khaos.tools.file_tools import copy_file


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Office storage accounting relies on POSIX dirfd semantics",
)


@pytest.fixture
def bounded_authority():
    """Register an authority with a tight aggregate byte budget.

    Filesystems allocate in blocks (4 KiB on APFS), so a file of any size up
    to 4 KiB counts as 4 KiB of allocated bytes.  The authority deliberately
    accounts for block allocation.  A 8 KiB budget allows exactly two 4 KiB
    allocations; a third pushes the *cumulative* total over and is rolled back.

    B1: the previous ``file_tools.set_office_authority`` module global has
    been removed; tests now pass the authority explicitly to ``copy_file`` /
    ``move_file`` via the ``office_authority`` parameter.
    """
    authority = OfficeMutationAuthority(
        storage_limits=WorkspaceStorageLimits(
            bytes=8 * 1024,  # 8 KiB total budget
            entries=10_000,
        )
    )
    yield authority


async def test_repeated_copy_accumulates_and_violates_aggregate_budget(
    tmp_path, bounded_authority
):
    """M1 core: copies accumulate against the workspace baseline.

    The first one or two copies succeed; eventually the *total* crosses the
    aggregate budget and the violating copy is rolled back, proving the limit
    is on the whole workspace, not a single call.  Each individual copy is
    tiny (~4 KiB allocated) — far below any sane per-call cap — yet the
    cumulative total eventually violates.
    """
    source = tmp_path / "payload"
    source.mkdir()
    (source / "chunk.txt").write_bytes(b"x" * 100)  # tiny, but 4 KiB allocated

    succeeded = 0
    violated = False
    for i in range(1, 20):
        try:
            result = await copy_file(
                "payload", f"copy{i}", workspace_root=tmp_path,
                office_authority=bounded_authority,
            )
            if result.get("ok"):
                succeeded += 1
            else:
                break
        except WorkspaceStorageViolation:
            violated = True
            break

    # At least one copy succeeded, and accumulation eventually hit the limit.
    assert succeeded >= 1, "no copy succeeded — budget too small"
    assert violated, (
        "all copies succeeded — aggregate accounting is not cumulative"
    )
    # The violating copy's destination must not exist (rolled back).
    assert not (tmp_path / f"copy{succeeded + 1}").exists()


async def test_aggregate_limit_is_per_workspace_not_per_call(
    tmp_path, bounded_authority
):
    """A copy that pushes the cumulative total over budget is rejected —
    confirming the accounting is cumulative, not per-call.

    Seed files consume the whole 8 KiB budget in the baseline; copying a
    directory with several files pushes the total well over and is rolled
    back.  Each file in the copied directory is individually tiny — far below
    any per-call cap — yet their cumulative allocation violates the budget.
    """
    source = tmp_path / "data"
    source.mkdir()
    # Seed 2 × 4 KiB = 8 KiB into the baseline (the whole budget).
    for i in range(2):
        (tmp_path / f"seed{i}.bin").write_bytes(b"y" * 4096)

    workspace = await bounded_authority.workspace_for_root(tmp_path)

    # Copy a directory with 3 files (3 × 4 KiB allocated = 12 KiB delta),
    # pushing the cumulative total to 20 KiB — well over the 8 KiB budget.
    for i in range(3):
        (source / f"f{i}.txt").write_bytes(b"z" * 100)
    with pytest.raises(WorkspaceStorageViolation):
        await copy_file(
            "data", "moredata", workspace_root=tmp_path,
            office_authority=bounded_authority,
        )

    # The violating copy's destination must not exist (rolled back).
    assert not (tmp_path / "moredata").exists()
