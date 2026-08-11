"""Generated security inventory must stay synchronized with source."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_security_inventory_is_current():
    result = subprocess.run(
        [sys.executable, "scripts/generate_security_inventory.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_privileged_spawn_inventory_is_current():
    result = subprocess.run(
        [sys.executable, "scripts/check_privileged_spawn_sites.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
