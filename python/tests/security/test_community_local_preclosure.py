"""Regression tests for the Community Local PR pre-closure contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "validate_community_local_preclosure.py"


def _module():
    spec = importlib.util.spec_from_file_location("community_local_preclosure", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_preclosure_accepts_the_current_live_contract():
    assert _module().validate_preclosure() == []


def test_preclosure_rejects_missing_required_proof():
    module = _module()
    errors = module.validate_proof_mapping(
        ("community_authority", "network_isolation"),
        {"community_authority": ("python/tests/security/test_local_trust.py",)},
        {"community_authority": "ordinary"},
    )
    assert any("missing proof(s)" in error for error in errors)


def test_preclosure_rejects_unknown_proof():
    module = _module()
    errors = module.validate_proof_mapping(
        ("community_authority",),
        {
            "community_authority": ("python/tests/security/test_local_trust.py",),
            "unknown_proof": ("python/tests/security/test_local_trust.py",),
        },
        {"community_authority": "ordinary", "unknown_proof": "ordinary"},
    )
    assert any("unknown proof(s)" in error for error in errors)


def test_preclosure_rejects_producer_mapping_drift():
    module = _module()
    errors = module.validate_proof_mapping(
        ("community_authority",),
        {"community_authority": ("python/tests/security/test_local_trust.py",)},
        {"community_authority": "lifecycle"},
    )
    assert any("mapping drift" in error for error in errors)


def test_preclosure_never_emits_closed():
    module = _module()
    assert "CLOSED" not in module.render_preclosure_result(())
    assert "CLOSED" not in module.render_preclosure_result(("contract drift",))
    assert module.render_preclosure_result(()) == "COMMUNITY_LOCAL_PRE_CLOSURE: PASS"
    assert module.render_preclosure_result(("contract drift",)).startswith(
        "COMMUNITY_LOCAL_PRE_CLOSURE: FAIL"
    )


def test_security_closure_gate_requires_preclosure():
    gate = (ROOT / ".github/workflows/security-closure-gate.yml").read_text(
        encoding="utf-8"
    )
    assert "community-local-preclosure:" in gate
    assert "- community-local-preclosure" in gate
    assert "COMMUNITY_LOCAL_PRECLOSURE: ${{ needs.community-local-preclosure.result }}" in gate
    assert '"$COMMUNITY_LOCAL_PRECLOSURE"' in gate
    assert "COMMUNITY_LOCAL_PRE_CLOSURE" in gate


def test_main_closure_still_requires_verified_github_provenance():
    workflow = (ROOT / ".github/workflows/community-local-closure.yml").read_text(
        encoding="utf-8"
    )
    report = (ROOT / "scripts/build_local_security_closure_report.py").read_text(
        encoding="utf-8"
    )
    assert "workflow_run:" in workflow
    assert 'workflows: ["Security Closure Gate"]' in workflow
    assert "types: [completed]" in workflow
    assert "branches: [main]" in workflow
    assert "github.event.workflow_run.head_sha" in workflow
    assert '--commit "$UPSTREAM_HEAD_SHA"' in workflow
    assert '--run-id "$UPSTREAM_RUN_ID"' in workflow
    assert "aggregation-manifest.json" in workflow
    assert "VerifiedGitHubProvenance" in report
    assert "verify_release_gates_for_closure" in report


def test_preclosure_does_not_accept_saved_release_record_as_live_provenance():
    module = _module()
    facts = module._facts(ROOT)
    local = facts["local_security_closure"]
    assert local["local_json_or_mock_artifact_can_close"] is False
    assert local["pre_closure"]["accepts_saved_release_record_as_live_provenance"] is False
    source = SCRIPT.read_text(encoding="utf-8")
    assert "issue_verified_github_provenance" not in source
    assert "local-security-evidence.json" not in source
    assert "json.loads" not in source
