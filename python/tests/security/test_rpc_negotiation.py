"""Internal JSON-line RPC negotiation and envelope-binding coverage."""

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

import pytest

import khaos.audit.logger as logger_module
from khaos.grpc_server import serve_json_lines
from khaos.rpc.protocol import (
    RPC_FEATURES,
    RPC_INITIALIZE_METHOD,
    RPC_METHOD_SCHEMA_VERSION,
    RPC_PROTOCOL_VERSION,
    RPC_SCHEMA_VERSION,
    GatewayRPCAuthenticator,
    RPCProtocolError,
    rpc_feature_digest as _rpc_feature_digest,
    rpc_initialize_response as _rpc_initialize_response,
)
from khaos.security.effective_policy import load_effective_policy
from khaos.db.state_root import project_id as compute_project_id


CAPABILITY = "c" * 48


def _request(method: str, payload: dict, *, features=None, nonce="n" * 32) -> dict:
    selected_features = list(RPC_FEATURES if features is None else features)
    issued_at = int(time.time())
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    payload_digest = hashlib.sha256(canonical).hexdigest()
    principal = "gateway"
    protocol = {
        "min_version": RPC_PROTOCOL_VERSION,
        "max_version": RPC_PROTOCOL_VERSION,
        "schema_version": RPC_SCHEMA_VERSION,
        "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
        "features": selected_features,
        "feature_digest": _rpc_feature_digest(selected_features),
        "unknown_field_policy": "reject",
    }
    signed = (
        f"{RPC_PROTOCOL_VERSION}\n{method}\n{nonce}\n{issued_at}\n"
        f"{principal}\n{payload_digest}\n"
        f"{protocol['min_version']}\n{protocol['max_version']}\n"
        f"{protocol['schema_version']}\n{protocol['method_schema_version']}\n"
        f"{protocol['feature_digest']}"
    ).encode("utf-8")
    method_key = hmac.new(
        CAPABILITY.encode("utf-8"),
        f"khaos-rpc-method-v{RPC_PROTOCOL_VERSION}\n{method}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return {
        "protocol_version": RPC_PROTOCOL_VERSION,
        "protocol": protocol,
        "method": method,
        "payload": payload,
        "auth": {
            "nonce": nonce,
            "issued_at": issued_at,
            "principal_id": principal,
            "payload_digest": payload_digest,
            "mac": hmac.new(method_key, signed, hashlib.sha256).hexdigest(),
        },
    }


def test_initialize_selects_explicit_security_contract():
    response = _rpc_initialize_response({
        "min_protocol_version": RPC_PROTOCOL_VERSION,
        "max_protocol_version": RPC_PROTOCOL_VERSION,
        "schema_version": RPC_SCHEMA_VERSION,
        "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
        "features": list(RPC_FEATURES),
    })

    assert response["ok"] is True
    assert response["protocol"]["selected_version"] == RPC_PROTOCOL_VERSION
    assert response["protocol"]["unknown_field_policy"] == "reject"
    assert "project_id" in response["protocol"]["required_security_fields"]
    assert "policy_drift" in response["protocol"]["error_codes"]


def test_initialize_rejects_unknown_fields_and_missing_security_features():
    payload = {
        "min_protocol_version": RPC_PROTOCOL_VERSION,
        "max_protocol_version": RPC_PROTOCOL_VERSION,
        "schema_version": RPC_SCHEMA_VERSION,
        "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
        "features": list(RPC_FEATURES),
        "unexpected": True,
    }
    with pytest.raises(RPCProtocolError) as unknown:
        _rpc_initialize_response(payload)
    assert unknown.value.code == "rpc_unknown_field"

    payload.pop("unexpected")
    payload["features"] = list(RPC_FEATURES[:-1])
    with pytest.raises(RPCProtocolError) as missing:
        _rpc_initialize_response(payload)
    assert missing.value.code == "rpc_feature_mismatch"


def test_production_authenticator_binds_negotiated_metadata_to_hmac():
    authenticator = GatewayRPCAuthenticator(
        CAPABILITY,
        require_protocol_v2=True,
        require_protocol_metadata=True,
    )
    request = _request(
        "TaskService.List",
        {"project_id": "project", "policy_digest": "digest"},
    )
    assert authenticator.authenticate(request) == "gateway"

    request["protocol"]["unknown_field_policy"] = "ignore"
    with pytest.raises(RPCProtocolError) as invalid:
        authenticator.authenticate(request)
    assert invalid.value.code == "rpc_unknown_field"


def test_initialize_method_name_is_stable():
    assert RPC_INITIALIZE_METHOD == "RPC.Initialize"


@pytest.mark.skipif(os.name == "nt", reason="production RPC uses a Unix socket")
async def test_production_uds_negotiates_before_dispatch(tmp_path, monkeypatch):
    """Exercise the real two-frame Initialize → service request contract."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    trusted = tmp_path / "home" / ".khaos" / "audit"
    trusted.parent.parent.mkdir(mode=0o700)
    monkeypatch.setattr(logger_module, "AUDIT_LOG_TRUSTED_DIR", trusted)
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")

    socket_parent = Path("/tmp") / f"khaos-rpc-negotiation-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path),
            str(tmp_path / "khaos.db"),
            project_root=tmp_path,
            gateway_capability=CAPABILITY,
        )
    )
    try:
        for _ in range(300):
            if socket_path.exists() or server_task.done():
                break
            await asyncio.sleep(0.01)
        if server_task.done():
            try:
                await server_task
            except (PermissionError, OSError) as exc:
                pytest.skip(f"sandbox does not allow RPC UDS: {exc}")
        try:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
        except (PermissionError, OSError) as exc:
            pytest.skip(f"sandbox does not allow RPC UDS: {exc}")

        initialize = _request(
            RPC_INITIALIZE_METHOD,
            {
                "min_protocol_version": RPC_PROTOCOL_VERSION,
                "max_protocol_version": RPC_PROTOCOL_VERSION,
                "schema_version": RPC_SCHEMA_VERSION,
                "method_schema_version": RPC_METHOD_SCHEMA_VERSION,
                "features": list(RPC_FEATURES),
            },
            nonce="i" * 32,
        )
        writer.write((json.dumps(initialize) + "\n").encode("utf-8"))
        await writer.drain()
        negotiated = json.loads((await reader.readline()).decode("utf-8"))
        assert negotiated["ok"] is True
        assert negotiated["protocol"]["selected_version"] == RPC_PROTOCOL_VERSION

        service_request = _request(
            "ChannelService.List",
            {
                "project_id": compute_project_id(tmp_path),
                "policy_digest": load_effective_policy(tmp_path).digest,
            },
            nonce="s" * 32,
        )
        writer.write((json.dumps(service_request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert isinstance(response.get("channels"), list), response
        writer.close()
        await writer.wait_closed()
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()
