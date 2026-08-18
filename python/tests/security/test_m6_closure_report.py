"""M6 closure reports refuse to turn missing evidence into CLOSED."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_m6_closure_report.py"


def _module():
    spec = importlib.util.spec_from_file_location("m6_report", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_native_and_ci_evidence_cannot_be_closed():
    report = _module().render(commit="a" * 40)
    assert "Status: **NOT CLOSED" in report
    assert "UNKNOWN" in report


def test_two_real_native_artifacts_and_explicit_gate_can_close(tmp_path):
    mac = tmp_path / "mac.json"
    windows = tmp_path / "windows.json"
    mac.write_text("{}", encoding="utf-8")
    windows.write_text("{}", encoding="utf-8")
    report = _module().render(
        commit="a" * 40,
        ci_run="12345",
        test_counts="1000 passed",
        native_evidence=(str(mac), str(windows)),
        all_gates_success=True,
    )
    assert "Status: **CLOSED**" in report
