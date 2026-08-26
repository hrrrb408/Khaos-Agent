"""Regression tests for the strict Pyright configuration contract."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_type_check_contract_matches_machine_config_and_docs() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/validate_type_check_contract.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "TYPE_CHECK_CONTRACT: PASS" in result.stdout
