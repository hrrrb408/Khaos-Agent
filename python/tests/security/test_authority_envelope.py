"""Common privileged-effect authority envelope contracts."""

from __future__ import annotations

import dataclasses

import pytest

from khaos.security.authority import AuthorityEnvelope


def _envelope() -> AuthorityEnvelope:
    return AuthorityEnvelope(
        principal_id="local-uid:501",
        project_id="project-1",
        runtime_id="runtime-1",
        task_id="task-1",
        workspace_id="workspace-1",
        workspace_generation=3,
        policy_digest="policy-1",
        operation_class="git.bootstrap",
        resource_digest="resource-1",
        authorization_epoch=4,
    )


def test_envelope_digest_binds_every_context_field() -> None:
    envelope = _envelope()
    assert envelope.matches_context(
        principal_id="local-uid:501",
        project_id="project-1",
        runtime_id="runtime-1",
        task_id="task-1",
        workspace_id="workspace-1",
        workspace_generation=3,
        policy_digest="policy-1",
    )
    assert not envelope.matches_context(
        principal_id="local-uid:502",
        project_id="project-1",
        runtime_id="runtime-1",
        task_id="task-1",
        workspace_id="workspace-1",
        workspace_generation=3,
        policy_digest="policy-1",
    )
    assert envelope.digest() != envelope.derive(
        operation_class="git.cleanup"
    ).digest()


def test_derived_envelope_keeps_owner_binding() -> None:
    derived = _envelope().derive(
        operation_class="git.cleanup",
        resource_digest="resource-2",
    )
    assert derived.principal_id == "local-uid:501"
    assert derived.workspace_generation == 3
    assert derived.operation_class == "git.cleanup"
    assert derived.resource_digest == "resource-2"


def test_envelope_is_frozen_and_rejects_invalid_identifiers() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _envelope().operation_class = "git.host"  # type: ignore[misc]
    with pytest.raises(ValueError, match="operation_class"):
        AuthorityEnvelope(
            principal_id="local",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            operation_class="git/unsafe",
            resource_digest="resource",
        )
