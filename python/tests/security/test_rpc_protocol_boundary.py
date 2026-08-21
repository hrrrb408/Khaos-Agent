"""Contract tests for the standalone authenticated RPC protocol boundary."""

import pytest
from khaos.rpc.protocol import (
    RPC_FEATURES,
    RPC_METHOD_SCHEMA_VERSION,
    RPC_PROTOCOL_VERSION,
    RPC_SCHEMA_VERSION,
    GatewayRPCAuthenticator,
    RPCProtocolError,
    rpc_binding_claim_error,
    rpc_feature_digest,
    rpc_initialize_response,
    rpc_protocol_metadata,
)


def _metadata(*, features: list[str] | None = None) -> dict[str, object]:
    selected = list(RPC_FEATURES if features is None else features)
    return {
        "min_version": RPC_PROTOCOL_VERSION,
        "max_version": RPC_PROTOCOL_VERSION,
        "schema_version": RPC_SCHEMA_VERSION,
        "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
        "features": selected,
        "feature_digest": rpc_feature_digest(selected),
        "unknown_field_policy": "reject",
    }


def test_protocol_module_is_the_single_owner():
    """The transport module must not expose a second protocol surface."""
    import khaos.grpc_server as grpc_server
    import khaos.rpc as rpc_package

    assert not hasattr(grpc_server, "GatewayRPCAuthenticator")
    assert not hasattr(grpc_server, "RPCProtocolError")
    assert not hasattr(grpc_server, "_rpc_feature_digest")
    assert not hasattr(grpc_server, "_rpc_initialize_response")
    assert not hasattr(grpc_server, "_rpc_protocol_metadata")
    assert not hasattr(rpc_package, "GatewayRPCAuthenticator")
    assert not hasattr(rpc_package, "RPCProtocolError")


def test_metadata_contract_accepts_only_the_negotiated_security_features():
    assert rpc_protocol_metadata({"protocol": _metadata()}, require=True) == _metadata()

    invalid = _metadata()
    invalid["feature_digest"] = "0" * 64
    with pytest.raises(RPCProtocolError) as error:
        rpc_protocol_metadata({"protocol": invalid}, require=True)
    assert error.value.code == "rpc_feature_mismatch"


def test_initialize_contract_rejects_unknown_fields_and_missing_features():
    payload = {
        "min_protocol_version": RPC_PROTOCOL_VERSION,
        "max_protocol_version": RPC_PROTOCOL_VERSION,
        "schema_version": RPC_SCHEMA_VERSION,
        "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
        "features": list(RPC_FEATURES),
        "unexpected": True,
    }
    with pytest.raises(RPCProtocolError) as error:
        rpc_initialize_response(payload)
    assert error.value.code == "rpc_unknown_field"

    payload.pop("unexpected")
    payload["features"] = list(RPC_FEATURES[:-1])
    with pytest.raises(RPCProtocolError) as error:
        rpc_initialize_response(payload)
    assert error.value.code == "rpc_feature_mismatch"


def test_binding_claims_fail_closed_on_missing_or_drifting_scope():
    assert rpc_binding_claim_error(
        {}, bound_project_id="project", bound_policy_digest="policy", require_claims=True,
    ) == ("rpc_claim_missing", "project_id claim is required for production RPC v2")
    assert rpc_binding_claim_error(
        {"project_id": "other", "policy_digest": "policy"},
        bound_project_id="project",
        bound_policy_digest="policy",
        require_claims=True,
    )[0] == "project_drift"
    assert rpc_binding_claim_error(
        {"project_id": "project", "policy_digest": "other"},
        bound_project_id="project",
        bound_policy_digest="policy",
        require_claims=True,
    )[0] == "policy_drift"


def test_authenticator_is_constructed_from_the_protocol_boundary():
    authenticator = GatewayRPCAuthenticator("c" * 48, require_protocol_v2=True)
    assert authenticator._require_protocol_v2 is True
