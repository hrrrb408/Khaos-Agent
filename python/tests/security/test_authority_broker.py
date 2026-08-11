from __future__ import annotations

import time
from dataclasses import replace

import pytest
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)


def _authority() -> AuthorityEnvelope:
    return AuthorityEnvelope(
        principal_id="principal",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="git.bootstrap",
        resource_digest="resource",
    )


def _tamper(capability: EffectCapability, **changes: object) -> EffectCapability:
    """Build an invalid test handle without invoking the opaque constructor."""
    clone = object.__new__(EffectCapability)
    for field_name in capability.__dataclass_fields__:
        object.__setattr__(
            clone,
            field_name,
            changes.get(field_name, getattr(capability, field_name)),
        )
    return clone


def test_envelope_is_not_enough_for_effect_boundary() -> None:
    broker = AuthorityBroker()
    try:
        capability = broker.issue(_authority(), allowed_operation="git.*")
        assert isinstance(capability, EffectCapability)
        broker.validate(capability, expected_operation="git.status")
        with pytest.raises(AuthorityBrokerError):
            broker.validate(capability.derive(operation_class="network.connect"))
    finally:
        broker.close()


def test_forged_and_mutated_capabilities_are_rejected() -> None:
    broker = AuthorityBroker()
    try:
        capability = broker.issue(_authority(), allowed_operation="git.*")
        forged = _tamper(capability, token="attacker-token")
        with pytest.raises(AuthorityBrokerError):
            broker.validate(forged)
        changed_context = _tamper(
            capability,
            authority=replace(capability.authority, task_id="other-task"),
        )
        with pytest.raises(AuthorityBrokerError):
            broker.validate(changed_context)
        broker.revoke(capability)
        with pytest.raises(AuthorityBrokerError):
            broker.validate(capability)
    finally:
        broker.close()


def test_capability_expiry_is_enforced_by_broker() -> None:
    broker = AuthorityBroker()
    try:
        capability = broker.issue(
            _authority(),
            allowed_operation="git.*",
            ttl_seconds=0.01,
        )
        time.sleep(0.03)
        with pytest.raises(AuthorityBrokerError, match="expired"):
            broker.validate(capability)
    finally:
        broker.close()


def test_reissue_mints_a_new_live_resource_capability() -> None:
    broker = AuthorityBroker()
    try:
        source_authority = replace(
            _authority(),
            operation_class="network.connect",
            resource_digest="initial-network-resource",
        )
        source = broker.issue(source_authority, allowed_operation="network.*")
        network = broker.reissue(
            source,
            operation_class="network.connect",
            resource_digest="network-policy-resource",
        )

        broker.validate(
            network,
            expected_operation="network.connect",
            expected_resource_digest="network-policy-resource",
        )
        with pytest.raises(AuthorityBrokerError, match="resource"):
            broker.validate(
                network,
                expected_operation="network.connect",
                expected_resource_digest="different-resource",
            )
        with pytest.raises(ValueError, match="reissue"):
            source.derive(
                operation_class="network.connect",
                resource_digest="another-resource",
            )
    finally:
        broker.close()
