"""Negative and contract tests for native authority transport admission."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from khaos.security.authorityd_protocol import AuthorityDaemonClient
from khaos.security.identity_isolation import AuthorityIdentityContract
from khaos.security.native_authority import (
    NativeAuthorityError,
    NativeAuthorityProof,
    build_native_authority_adapter,
)


def _proof_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "platform": "darwin",
        "transport": "xpc",
        "service_id": "com.khaos.authorityd",
        "service_pid": 1234,
        "service_identity": "com.khaos.authorityd",
        "peer_identity": "com.khaos.agent",
        "protected_key_ref": "khaos-authority-signing-key",
        "challenge_digest": "a" * 64,
        "peer_verified": True,
        "transport_verified": True,
        "protected_key_verified": True,
    }
    payload.update(overrides)
    return payload


def test_native_proof_requires_every_independent_postcondition() -> None:
    proof = NativeAuthorityProof.from_payload(
        _proof_payload(),
        expected_platform="darwin",
        expected_transport="xpc",
        expected_service_id="com.khaos.authorityd",
        expected_key_ref="khaos-authority-signing-key",
    )
    assert proof.transport_verified is True
    with pytest.raises(NativeAuthorityError, match="does not match"):
        NativeAuthorityProof.from_payload(
            _proof_payload(peer_verified=False),
            expected_platform="darwin",
            expected_transport="xpc",
            expected_service_id="com.khaos.authorityd",
            expected_key_ref="khaos-authority-signing-key",
        )


def test_native_proof_rejects_extra_or_missing_fields() -> None:
    payload = _proof_payload()
    payload.pop("protected_key_verified")
    with pytest.raises(NativeAuthorityError, match="fields are incomplete"):
        NativeAuthorityProof.from_payload(
            payload,
            expected_platform="darwin",
            expected_transport="xpc",
            expected_service_id="com.khaos.authorityd",
            expected_key_ref="khaos-authority-signing-key",
        )


def test_native_adapter_factory_never_emulates_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(NativeAuthorityError, match="no native"):
        build_native_authority_adapter(
            production=True,
            contract=AuthorityIdentityContract(10001, 10003, 10004),
        )


def test_macos_adapter_requires_native_client_and_key_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delenv("KHAOS_MACOS_AUTHORITY_XPC_CLIENT", raising=False)
    contract = AuthorityIdentityContract(
        501,
        502,
        503,
        launchd_service="com.khaos.authorityd",
        code_signature="com.khaos.agent",
        keychain_access_group="TEAMID.com.khaos.authority",
        protected_key_ref="khaos-authority-signing-key",
    )
    with pytest.raises(NativeAuthorityError, match="CLIENT is missing"):
        build_native_authority_adapter(production=True, contract=contract)


def test_authority_client_uses_injected_native_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")

    class FakeAdapter:
        def request(self, payload: dict[str, object]) -> dict[str, object]:
            assert payload["protocol"] == 1
            return {
                "ok": True,
                "native_transport": "xpc",
                "proof_digest": "a" * 64,
                "value": "native",
            }

    client = AuthorityDaemonClient(Path("/unused.sock"), native_adapter=FakeAdapter())
    assert client.request({"operation": "probe"})["value"] == "native"
