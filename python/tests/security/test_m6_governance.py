"""M6 governance preparation stays explicit and fail-closed."""

from __future__ import annotations

import importlib.util
import json
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


def test_all_machine_declared_security_paths_are_codeowned():
    assert _module().validate_security_critical_paths() == []


def test_governance_validator_rejects_missing_security_producer_owner():
    module = _module()
    errors = module.security_critical_path_errors(
        ["scripts/new-security-producer.py"],
        "/scripts/old-producer.py @hrrrb408\n",
        require_exists=False,
    )
    assert any("not covered by CODEOWNERS" in error for error in errors)


def test_single_maintainer_mode_does_not_claim_independent_review():
    module = _module()
    facts = module.yaml.safe_load(
        (ROOT / "docs" / "security_facts.yaml").read_text(encoding="utf-8")
    )
    assert facts["governance"]["active_mode"] == "single_maintainer_compatibility"
    assert facts["governance"]["independent_review_claimed"] is False
    assert "independent review achieved" not in (
        ROOT / "docs" / "security-release-governance.md"
    ).read_text(encoding="utf-8").lower()


def test_hardened_ruleset_requires_independent_security_review():
    template = json.loads(
        (ROOT / "scripts" / "github-m6-hardened-ruleset.json").read_text(encoding="utf-8")
    )
    pull_request = next(rule for rule in template["rules"] if rule["type"] == "pull_request")
    parameters = pull_request["parameters"]
    assert parameters["required_approving_review_count"] >= 1
    assert parameters["require_code_owner_review"] is True
    assert parameters["require_last_push_approval"] is True


def test_security_critical_path_inventory_has_no_missing_files():
    errors = _module().validate_security_critical_paths()
    assert not [error for error in errors if "missing" in error]


def test_security_critical_path_inventory_has_no_duplicate_or_dead_entries():
    errors = _module().validate_security_critical_paths()
    assert not [error for error in errors if "duplicate" in error or "missing" in error]
