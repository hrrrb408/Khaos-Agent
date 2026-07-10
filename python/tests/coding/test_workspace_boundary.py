from pathlib import Path

import pytest

from khaos.coding.workspace.boundary import WorkspaceBoundaryError, resolve_write_target


def test_boundary_rejects_parent_absolute_and_symlink_escape(tmp_path: Path):
    root = tmp_path / "worktree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(WorkspaceBoundaryError):
        resolve_write_target(root, "../outside/file")
    with pytest.raises(WorkspaceBoundaryError):
        resolve_write_target(root, outside / "file")
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkspaceBoundaryError):
        resolve_write_target(root, "link/secret.txt")
