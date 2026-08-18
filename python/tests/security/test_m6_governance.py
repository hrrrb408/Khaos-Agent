"""M6 governance preparation stays explicit and fail-closed."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "validate_m6_governance.py"


def _module():
    spec = importlib.util.spec_from_file_location("m6_governance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hardened_ruleset_is_a_valid_second_maintainer_template():
    assert _module().validate() == []


def test_active_ruleset_reference_still_documents_single_maintainer_boundary():
    text = (ROOT / "scripts" / "github-main-ruleset.json").read_text(encoding="utf-8")
    assert '"required_approving_review_count": 0' in text
    assert '"require_code_owner_review": false' in text
