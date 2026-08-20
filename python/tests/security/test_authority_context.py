"""Regression tests for the canonical authority-owner context."""

from __future__ import annotations

from dataclasses import replace

import pytest
from khaos.security.authority_context import AuthorityContextV1


def _context() -> AuthorityContextV1:
    return AuthorityContextV1(
        principal_id="principal",
        principal_kind="subagent",
        parent_principal_id="parent",
        project_id="project",
        session_id="session",
        runtime_id="runtime",
        source_transport="transport",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=3,
        policy_digest="policy",
        authorization_epoch=7,
        delegation_digest="a" * 64,
    )


def test_payload_contains_every_owner_binding() -> None:
    payload = _context().payload()
    assert set(payload) == {
        "schema_version",
        "principal_id",
        "principal_kind",
        "parent_principal_id",
        "project_id",
        "session_id",
        "runtime_id",
        "source_transport",
        "task_id",
        "workspace_id",
        "workspace_generation",
        "policy_digest",
        "authorization_epoch",
        "delegation_digest",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal_id", "other-principal"),
        ("principal_kind", "human"),
        ("parent_principal_id", "other-parent"),
        ("project_id", "other-project"),
        ("session_id", "other-session"),
        ("runtime_id", "other-runtime"),
        ("source_transport", "other-transport"),
        ("task_id", "other-task"),
        ("workspace_id", "other-workspace"),
        ("workspace_generation", 4),
        ("policy_digest", "other-policy"),
        ("authorization_epoch", 8),
        ("delegation_digest", "b" * 64),
    ],
)
def test_digest_changes_for_each_owner_binding(field: str, value: object) -> None:
    original = _context()
    changed = replace(original, **{field: value})
    assert changed.digest() != original.digest()


def test_digest_is_deterministic() -> None:
    assert _context().digest() == _context().digest()


def test_invalid_delegation_digest_fails_closed() -> None:
    with pytest.raises(ValueError, match="delegation digest"):
        replace(_context(), delegation_digest="not-a-digest")
