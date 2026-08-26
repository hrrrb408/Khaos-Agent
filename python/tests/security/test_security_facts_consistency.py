"""Regression tests for the cross-file security-facts contract."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_security_facts_consistency_contract() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/validate_security_facts_consistency.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SECURITY_FACTS_CONSISTENCY: PASS" in result.stdout
