"""Keep the machine-readable security facts aligned with the implementation."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def test_security_facts_define_the_receipt_and_platform_contract() -> None:
    facts = yaml.safe_load(
        (ROOT / "docs/security_facts.yaml").read_text(encoding="utf-8")
    )

    assert facts["schema_version"] == 1
    authority = facts["authority"]
    assert authority["long_lived_grant"] == "AuthorityGrant"
    assert authority["short_lived_effect"] == "EffectCapability"
    assert authority["receipt_ttl_seconds"] == 300
    assert {
        "prepared",
        "claimed",
        "success",
        "failed",
        "unknown",
        "expired",
        "revoked",
    }.issubset(set(authority["receipt_states"]))
    assert authority["pending_receipt_gc"] == (
        "bounded_with_per_principal_and_global_quotas"
    )
    assert facts["linux"]["job_uid_mapping"] == "bwrap_unshare_user_uid_gid"
    assert facts["linux"]["identity_oracle"] == "proc_status_uid_map_gid_map"
    assert facts["linux"]["docker_outer_profile"] == (
        "seccomp_apparmor_systempaths_unconfined_required_for_bwrap"
    )
    assert facts["linux"]["docker_agent_sys_admin"] == "forbidden"
    assert facts["platform_boundaries"]["unsupported_platform_behavior"] == (
        "fail_closed"
    )
    assert facts["evidence"]["closure_gate"] == (
        "aggregate_required_checks_on_exact_commit"
    )
