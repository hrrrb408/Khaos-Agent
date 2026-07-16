import os
from pathlib import Path

import pytest

from khaos.coding.workspace.storage import (
    capture_workspace_snapshot,
    workspace_storage_delta,
)


def test_workspace_delta_handles_rename_and_hardlinks(tmp_path: Path):
    original = tmp_path / "original"
    original.write_bytes(b"x" * 8192)
    baseline = capture_workspace_snapshot(tmp_path)

    original.rename(tmp_path / "renamed")
    after_rename = capture_workspace_snapshot(tmp_path)
    assert workspace_storage_delta(baseline, after_rename) == (0, 0)

    payload = tmp_path / "payload"
    payload.write_bytes(b"y" * 8192)
    try:
        os.link(payload, tmp_path / "payload-link")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    allocated_growth, entry_growth = workspace_storage_delta(
        baseline, capture_workspace_snapshot(tmp_path)
    )
    assert 8192 <= allocated_growth < 16384
    assert entry_growth == 2


def test_workspace_delta_counts_growth_of_existing_inode(tmp_path: Path):
    payload = tmp_path / "payload"
    payload.write_bytes(b"x" * 4096)
    baseline = capture_workspace_snapshot(tmp_path)
    payload.write_bytes(b"x" * 16384)

    allocated_growth, entry_growth = workspace_storage_delta(
        baseline, capture_workspace_snapshot(tmp_path)
    )
    assert allocated_growth >= 12288
    assert entry_growth == 0
