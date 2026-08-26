"""Contract tests for the M7.1.2 immutable GoalSpec declaration."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
from khaos.agent.control.goal import (
    AcceptanceCriterion,
    GoalRequirement,
    GoalSource,
    GoalSpec,
    GoalSpecValidationError,
    normalize_goal,
)


def _rich_spec(*, reverse_collections: bool = False) -> GoalSpec:
    requirements = (
        GoalRequirement("second", "第二个用户要求", False, GoalSource.INFERRED),
        GoalRequirement("first", "第一条显式要求", True, GoalSource.EXPLICIT_USER),
    )
    criteria = (
        AcceptanceCriterion(
            "docs",
            "文档存在",
            False,
            GoalSource.EXPLICIT_USER,
            "file_exists",
        ),
        AcceptanceCriterion(
            "tests",
            "回归测试",
            True,
            GoalSource.VERIFICATION_POLICY,
            "test_run",
        ),
    )
    if reverse_collections:
        requirements = tuple(reversed(requirements))
        criteria = tuple(reversed(criteria))
    return GoalSpec.from_parts(
        goal_spec_id="goal-identity",
        raw_goal="  修复审批重复消费的问题\r\n并补充回归测试  ",
        requirements=requirements,
        acceptance_criteria=criteria,
        constraints=("不扩大权限",),
        requested_artifacts=("tests/regression.py",),
        verification_expectations=("targeted test",),
    )


def test_goal_spec_is_deeply_immutable_and_typed() -> None:
    spec = GoalSpec.from_user_goal("修复中文目标中的 /path/to/file.py")

    with pytest.raises(FrozenInstanceError):
        spec.raw_goal = "tampered"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        spec.requirements[0].description = "tampered"  # type: ignore[misc]

    assert type(spec.requirements) is tuple
    assert type(spec.acceptance_criteria) is tuple
    assert all(type(item) is GoalRequirement for item in spec.requirements)
    assert not hasattr(spec, "__dict__")

    requirement = GoalRequirement(
        "r", "required", True, GoalSource.EXPLICIT_USER
    )
    with pytest.raises(GoalSpecValidationError, match="requirements must be a tuple"):
        GoalSpec.from_parts(
            goal_spec_id="bad-list",
            raw_goal="goal",
            requirements=[requirement],  # type: ignore[arg-type]
        )
    with pytest.raises(GoalSpecValidationError, match="requirements must contain"):
        GoalSpec.from_parts(
            goal_spec_id="bad-item",
            raw_goal="goal",
            requirements=({},),  # type: ignore[arg-type]
        )


def test_goal_source_round_trip_and_chinese_goal_preservation() -> None:
    spec = GoalSpec.from_user_goal("  修复 approval.consume() 中的重复消费  ")
    restored = GoalSpec.from_canonical_json(spec.canonical_json())

    assert restored == spec
    assert restored.requirements[0].source is GoalSource.EXPLICIT_USER
    assert restored.raw_goal == "  修复 approval.consume() 中的重复消费  "
    assert restored.normalized_goal == "修复 approval.consume() 中的重复消费"
    assert normalize_goal("a\r\nb\rc") == "a\nb\nc"


def test_semantic_digest_is_deterministic_and_identity_independent() -> None:
    first = _rich_spec()
    reordered = _rich_spec(reverse_collections=True)
    different_identity = GoalSpec.from_parts(
        goal_spec_id="another-identity",
        raw_goal=first.raw_goal,
        normalized_goal=first.normalized_goal,
        requirements=first.requirements,
        acceptance_criteria=first.acceptance_criteria,
        constraints=first.constraints,
        requested_artifacts=first.requested_artifacts,
        verification_expectations=first.verification_expectations,
    )

    assert first.semantic_digest == reordered.semantic_digest
    assert first.semantic_digest == different_identity.semantic_digest

    changed = GoalSpec.from_parts(
        goal_spec_id="goal-identity",
        raw_goal=first.raw_goal,
        normalized_goal=first.normalized_goal,
        requirements=(
            GoalRequirement(
                "first", "第一条显式要求已改变", True, GoalSource.EXPLICIT_USER
            ),
            first.requirements[0],
        ),
        acceptance_criteria=first.acceptance_criteria,
        constraints=first.constraints,
        requested_artifacts=first.requested_artifacts,
        verification_expectations=first.verification_expectations,
    )
    assert changed.semantic_digest != first.semantic_digest
    assert len(first.semantic_digest) == 64


def test_canonical_schema_has_no_mutable_assessment_or_arbitrary_metadata() -> None:
    spec = GoalSpec.from_user_goal("保留原始 goal")
    mapping = spec.to_canonical_mapping()

    assert set(mapping) == {
        "schema_version",
        "goal_spec_id",
        "raw_goal",
        "normalized_goal",
        "requirements",
        "acceptance_criteria",
        "constraints",
        "requested_artifacts",
        "verification_expectations",
        "semantic_digest",
    }
    assert "status" not in mapping
    assert "evidence_refs" not in mapping
    with pytest.raises(GoalSpecValidationError, match="unknown fields"):
        payload = spec.to_canonical_mapping()
        payload["status"] = "satisfied"
        GoalSpec.from_canonical_json(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def test_field_ordering_in_json_does_not_change_semantic_digest() -> None:
    first = _rich_spec()
    semantic = first.semantic_payload
    reordered = {
        "verification_expectations": semantic["verification_expectations"],
        "requested_artifacts": semantic["requested_artifacts"],
        "constraints": semantic["constraints"],
        "acceptance_criteria": semantic["acceptance_criteria"],
        "requirements": semantic["requirements"],
        "normalized_goal": semantic["normalized_goal"],
        "raw_goal": semantic["raw_goal"],
        "schema_version": semantic["schema_version"],
    }
    from khaos.security.protocol_boundary import canonical_digest

    assert canonical_digest(semantic) == canonical_digest(reordered)
