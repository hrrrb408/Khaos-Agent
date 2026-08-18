"""Property-based tests for the pure M6 protocol/TCB boundary."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from khaos.security.protocol_boundary import (
    EffectBinding,
    OwnerState,
    ProtocolBoundaryError,
    ProtocolNegotiation,
    ReceiptState,
    canonical_digest,
    canonical_json_bytes,
    require_owner_transition,
    require_receipt_transition,
    validate_object_schema,
)


@given(st.dictionaries(st.text(min_size=1, max_size=20), st.integers(), max_size=8))
def test_canonical_digest_is_stable_for_mapping_insertion_order(value: dict[str, int]) -> None:
    reordered = dict(reversed(tuple(value.items())))
    assert canonical_json_bytes(value) == canonical_json_bytes(reordered)
    assert canonical_digest(value) == canonical_digest(reordered)


@given(
    st.text(alphabet=st.characters(blacklist_characters="\x00"), min_size=1, max_size=30),
    st.dictionaries(st.text(min_size=1, max_size=12), st.integers(), max_size=4),
)
def test_effect_binding_rejects_any_effect_mutation(operation: str, resource: dict[str, int]) -> None:
    binding = EffectBinding.create(
        operation=operation,
        resource=resource,
        effect={"argv": ["/bin/echo", "approved"]},
    )
    assert binding.matches(
        operation=operation,
        resource=resource,
        effect={"argv": ["/bin/echo", "approved"]},
    )
    assert not binding.matches(
        operation=operation,
        resource=resource,
        effect={"argv": ["/bin/echo", "mutated"]},
    )


@given(st.sampled_from(["unknown", "terminal", "claimed"]))
def test_receipt_state_machine_rejects_non_authority_states(state: str) -> None:
    with pytest.raises(ProtocolBoundaryError):
        require_receipt_transition(state, ReceiptState.CLAIMED)


def test_receipt_state_machine_allows_only_explicit_transitions() -> None:
    assert require_receipt_transition(ReceiptState.PREPARED, ReceiptState.CLAIMING)
    with pytest.raises(ProtocolBoundaryError):
        require_receipt_transition(ReceiptState.PREPARED, ReceiptState.TERMINAL)


def test_closed_owner_requires_external_postcondition_and_empty_registry() -> None:
    with pytest.raises(ProtocolBoundaryError):
        require_owner_transition(
            OwnerState.CLOSING,
            OwnerState.CLOSED,
            terminal_proven=True,
            owned_resources=("process:123",),
        )
    assert require_owner_transition(
        OwnerState.CLOSING,
        OwnerState.CLOSED,
        terminal_proven=True,
        owned_resources=(),
    ) is OwnerState.CLOSED


def test_schema_validation_returns_immutable_view_and_rejects_unknown_fields() -> None:
    view = validate_object_schema(
        {"method": "probe"},
        allowed_fields=frozenset({"method"}),
        required_fields=frozenset({"method"}),
        label="rpc envelope",
    )
    assert view["method"] == "probe"
    with pytest.raises(ProtocolBoundaryError):
        validate_object_schema(
            {"method": "probe", "extra": True},
            allowed_fields=frozenset({"method"}),
            required_fields=frozenset({"method"}),
            label="rpc envelope",
        )


def test_protocol_negotiation_binds_features_and_schema() -> None:
    result = ProtocolNegotiation.negotiate(
        minimum=2,
        maximum=2,
        supported_version=2,
        schema_version=1,
        supported_schema_version=1,
        method_schema_version=1,
        supported_method_schema_version=1,
        features=["hmac-v2", "unknown-fields-reject"],
        required_features=frozenset({"hmac-v2", "unknown-fields-reject"}),
    )
    assert result.feature_digest == canonical_digest(["hmac-v2", "unknown-fields-reject"])
