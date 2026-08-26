"""RustSec exception policy and stale-ignore regression tests."""

from __future__ import annotations

import importlib.util
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "validate_cargo_advisory_policy",
    ROOT / "scripts" / "validate_cargo_advisory_policy.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_current_lock_has_no_stale_rustsec_suppression() -> None:
    assert MODULE.validate() == []
    lock = (ROOT / "rust/khaos-core/Cargo.lock").read_text(encoding="utf-8")
    audit = (ROOT / "rust/khaos-core/audit.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/supply-chain-audit.yml").read_text(
        encoding="utf-8"
    )
    assert 'name = "pyo3"' in lock
    assert 'version = "0.29.0"' in lock
    assert 'ignore = []' in audit
    assert "--ignore RUSTSEC-" not in workflow


def test_patched_dependency_cannot_keep_a_matching_ignore(tmp_path: Path) -> None:
    audit = tmp_path / "audit.toml"
    policy = tmp_path / "advisory-policy.toml"
    lock = tmp_path / "Cargo.lock"
    workflow = tmp_path / "supply-chain-audit.yml"
    audit.write_text(
        '[advisories]\nignore = ["RUSTSEC-2026-0177"]\n', encoding="utf-8"
    )
    policy.write_text(
        """schema_version = 1

[[advisory_exceptions]]
id = "RUSTSEC-2026-0177"
dependency = "pyo3"
current_version = "0.29.0"
affected_range = "< 0.29"
fixed_version = "0.29.0"
reason = "temporary compatibility exception"
owner = "security"
removal_condition = "upgrade pyo3"
expires_on = "2099-01-01"
""",
        encoding="utf-8",
    )
    lock.write_text(
        '[[package]]\nname = "pyo3"\nversion = "0.29.0"\n', encoding="utf-8"
    )
    workflow.write_text("cargo audit --ignore RUSTSEC-2026-0177\n", encoding="utf-8")

    errors = MODULE.validate_paths(
        audit_config=audit,
        policy_path=policy,
        cargo_lock=lock,
        workflow=workflow,
        today=date(2026, 8, 26),
    )

    assert any("outside the vulnerable range" in error for error in errors)
