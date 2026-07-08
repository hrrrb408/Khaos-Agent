"""CLI entry point tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the package CLI in a subprocess."""
    project_root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, "-m", "khaos.cli", *args],
        capture_output=True,
        cwd=str(project_root),
        env={"PYTHONPATH": str(project_root / "python")},
        text=True,
        timeout=10,
    )


def test_version():
    result = run_cli("version")

    assert result.returncode == 0
    assert "Khaos" in result.stdout


def test_no_command():
    result = run_cli()

    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_test_help():
    result = run_cli("test", "--help")

    assert result.returncode == 0
    assert "Run tests" in result.stdout
