"""Regression tests for cumulative Windows trust-path traversal."""

from pathlib import Path

from khaos.security import windows_trust


def test_windows_acl_components_are_cumulative(tmp_path: Path) -> None:
    root = tmp_path / "Git"
    candidate = root / "cmd" / "git.exe"

    assert windows_trust._windows_acl_components(candidate, root) == (
        root,
        root / "cmd",
        candidate,
    )
