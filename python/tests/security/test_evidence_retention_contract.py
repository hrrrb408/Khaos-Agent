"""Evidence retention and immutable release-asset contract tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "validate_evidence_retention",
    ROOT / "scripts" / "validate_evidence_retention.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_all_upload_artifacts_are_classified_and_critical_artifacts_are_retained() -> None:
    assert MODULE.validate() == []


def test_saved_evidence_does_not_replace_live_release_authority() -> None:
    assert MODULE.validate() == []
    facts = (ROOT / "docs/security_facts.yaml").read_text(encoding="utf-8")
    assert "saved_evidence_is_audit_only: true" in facts
    assert "live_exact_sha_verifier_remains_authority: true" in facts
