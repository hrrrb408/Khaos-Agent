"""Signed challenge-response native authority proof tests (M6.9 BATCH 3).

The old proof was a static deployment digest (SHA256 of service|peer|key)
that never changed between requests, so a captured proof could be replayed
and the protected key only had to exist.  Now every probe/request carries
a fresh client nonce and the backend signs an attestation covering the
nonce and the exact request digest; the adapter verifies the signature
with the public key it owns.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from khaos.security.authorityd import (
    AuthorityControlPlaneError,
    AuthorityDaemon,
    _dispatch,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    Ed25519KeyStore,
)
from khaos.security.native_authority import (
    MAX_NATIVE_REQUEST_BYTES,
    PROBE_INNER_REQUEST,
    NativeAuthorityError,
    _SubprocessNativeAdapter,
)
from khaos.security.protocol_boundary import canonical_json_bytes


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


def _daemon(tmp_path: Path) -> AuthorityDaemon:
    return AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(
            tmp_path / "authorityd-key.pem", create=True
        ),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )


def _proof_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "platform": "darwin",
        "transport": "xpc",
        "service_id": "com.khaos.authorityd",
        "service_pid": "4242",
        "service_identity": "com.khaos.authorityd",
        "peer_identity": "com.khaos.agent",
        "peer_team_id": "TEAMID123",
        "peer_cdhash": "ab" * 20,
        "designated_requirement_digest": "c" * 64,
        "service_instance_id": "d" * 32,
        "protected_key_ref": "khaos-authority-signing-key",
    }
    fields.update(overrides)
    return fields


def _attest_request(
    *,
    challenge: str = "a" * 64,
    request: bytes = PROBE_INNER_REQUEST.encode("utf-8"),
    proof_fields: dict[str, object] | None = None,
    request_digest: str | None = None,
) -> dict[str, object]:
    return {
        "protocol": AUTHORITYD_PROTOCOL,
        "operation": "attest",
        "challenge_nonce": challenge,
        "request_raw_hex": request.hex(),
        "request_digest": request_digest
        or hashlib.sha256(request).hexdigest(),
        "proof_fields": proof_fields if proof_fields is not None else _proof_fields(),
    }


def test_attest_signs_challenge_and_request_digest(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    challenge = "f" * 64
    request = b'{"operation":"ping","protocol":1}'
    response = _dispatch(daemon, _attest_request(challenge=challenge, request=request))
    assert response["ok"] is True
    attestation = response["attestation"]
    assert attestation["challenge_nonce"] == challenge
    assert attestation["request_digest"] == hashlib.sha256(request).hexdigest()
    assert response["response"]["ok"] is True
    # The signature must verify under the daemon's public key.
    signature = base64.b64decode(attestation["signature"])
    unsigned = {k: v for k, v in attestation.items() if k != "signature"}
    daemon.signing_key.public_key().verify(
        signature, canonical_json_bytes(unsigned)
    )


def test_attest_rejects_digest_mismatch(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    with pytest.raises(AuthorityControlPlaneError, match="digest does not match"):
        _dispatch(daemon, _attest_request(request_digest="0" * 64))


def test_attest_rejects_malformed_challenge_or_payload(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    with pytest.raises(AuthorityControlPlaneError, match="challenge or request digest"):
        _dispatch(daemon, _attest_request(challenge="short"))
    with pytest.raises(AuthorityControlPlaneError, match="request is malformed JSON"):
        _dispatch(
            daemon,
            _attest_request(request=b"this is not json"),
        )
    with pytest.raises(AuthorityControlPlaneError, match="not an authorityd request"):
        _dispatch(
            daemon,
            _attest_request(request=b'{"protocol":999,"operation":"ping"}'),
        )
    with pytest.raises(AuthorityControlPlaneError, match="out of bounds"):
        _dispatch(
            daemon,
            _attest_request(request=b'{"operation":"ping","protocol":1}' + b" " * (1024 * 1024)),
        )


def test_attest_rejects_incomplete_proof_fields(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    fields = _proof_fields()
    fields.pop("peer_team_id")
    with pytest.raises(AuthorityControlPlaneError, match="proof fields are incomplete"):
        _dispatch(daemon, _attest_request(proof_fields=fields))
    fields = _proof_fields(peer_team_id="")
    with pytest.raises(AuthorityControlPlaneError, match="proof field is empty"):
        _dispatch(daemon, _attest_request(proof_fields=fields))
    fields = _proof_fields(service_pid="not-a-number")
    with pytest.raises(AuthorityControlPlaneError, match="service pid is invalid"):
        _dispatch(daemon, _attest_request(proof_fields=fields))


class _FakeAdapter(_SubprocessNativeAdapter):
    """Adapter double exercising only the attestation verification path."""

    expected_platform = "darwin"
    expected_transport = "xpc"
    service_id = "com.khaos.authorityd"
    protected_key_ref = "khaos-authority-signing-key"
    expected_requirement_digest = "c" * 64

    def __init__(self, public_key_path: Path) -> None:
        self.public_key_path = public_key_path
        self.proof = None  # type: ignore[assignment]


def _attested_response(
    daemon: AuthorityDaemon,
    *,
    challenge: str,
    request: bytes,
    transport: str = "xpc",
    instance_id: str = "d" * 32,
) -> dict[str, object]:
    proof_fields = _proof_fields(service_instance_id=instance_id)
    envelope = _dispatch(
        daemon,
        _attest_request(
            challenge=challenge, request=request, proof_fields=proof_fields
        ),
    )
    assert envelope["ok"] is True
    return {
        "native_transport": transport,
        "proof_digest": "e" * 64,
        **{k: v for k, v in envelope.items() if k != "ok"},
    }


def _adapter(tmp_path: Path) -> _FakeAdapter:
    key_path = tmp_path / "authorityd-key.pem"
    key = Ed25519KeyStore.load_or_create(key_path, create=True)
    public_path = tmp_path / "authorityd.pub"
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    public_path.chmod(0o644)
    adapter = _FakeAdapter(public_path)
    return adapter


# Observed Windows runner AV/indexer holds on a just-written key file have
# outlived a 5 s budget under load; keep the non-Windows budget tight.
_KEY_LOAD_RETRY_SECONDS = 30.0 if sys.platform == "win32" else 5.0


def _public_key(adapter: _FakeAdapter) -> Ed25519PublicKey:
    """Load the adapter's public key, tolerating transient file locks.

    Windows runners can briefly hold an exclusive handle on a just-written
    key file (antivirus/indexer); a momentary PermissionError must not be
    reported as an attestation regression.  Bounded retry, then fail.
    """
    deadline = time.monotonic() + _KEY_LOAD_RETRY_SECONDS
    while True:
        try:
            return adapter._load_public_key()
        except NativeAuthorityError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def test_adapter_accepts_fresh_signed_attestation(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    challenge = "1" * 64
    request = PROBE_INNER_REQUEST.encode("utf-8")
    response = _attested_response(daemon, challenge=challenge, request=request)
    attestation = adapter._verify_attestation(
        response,
        challenge_nonce=challenge,
        request_bytes=request,
        public_key=_public_key(adapter),
    )
    assert attestation["service_instance_id"] == "d" * 32


def test_adapter_rejects_replayed_nonce(tmp_path: Path) -> None:
    """A captured response replayed against a new challenge fails closed."""
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    request = PROBE_INNER_REQUEST.encode("utf-8")
    old_response = _attested_response(daemon, challenge="1" * 64, request=request)
    fresh_challenge = "2" * 64
    # The key load must happen before the raises window: a key-load flake
    # surfacing inside pytest.raises reads as a matcher mismatch, hiding the
    # real error.  The same applies to every rejection test below.
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="nonce does not match"):
        adapter._verify_attestation(
            old_response,
            challenge_nonce=fresh_challenge,
            request_bytes=request,
            public_key=public_key,
        )


def test_adapter_rejects_substituted_request_digest(tmp_path: Path) -> None:
    """An attestation for request A cannot authenticate request B."""
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    request_a = PROBE_INNER_REQUEST.encode("utf-8")
    request_b = b'{"operation":"ping","protocol":1,"extra":true}'
    response = _attested_response(daemon, challenge="3" * 64, request=request_a)
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="does not cover this request"):
        adapter._verify_attestation(
            response,
            challenge_nonce="3" * 64,
            request_bytes=request_b,
            public_key=public_key,
        )


def test_adapter_rejects_tampered_attestation(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    challenge = "4" * 64
    request = PROBE_INNER_REQUEST.encode("utf-8")
    response = _attested_response(daemon, challenge=challenge, request=request)
    tampered = json.loads(json.dumps(response))
    tampered["attestation"]["peer_team_id"] = "EVILTEAM"
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="signature is invalid"):
        adapter._verify_attestation(
            tampered,
            challenge_nonce=challenge,
            request_bytes=request,
            public_key=public_key,
        )


def test_adapter_rejects_stale_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    challenge = "5" * 64
    request = PROBE_INNER_REQUEST.encode("utf-8")
    response = _attested_response(daemon, challenge=challenge, request=request)
    future = time.time() + 3600.0
    monkeypatch.setattr(
        "khaos.security.native_authority.time.time", lambda: future
    )
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="stale"):
        adapter._verify_attestation(
            response,
            challenge_nonce=challenge,
            request_bytes=request,
            public_key=public_key,
        )


def test_adapter_rejects_wrong_service_instance(tmp_path: Path) -> None:
    """A response from a different service instance cannot continue a session."""
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    challenge = "6" * 64
    request = PROBE_INNER_REQUEST.encode("utf-8")
    response = _attested_response(
        daemon, challenge=challenge, request=request, instance_id="e" * 32
    )
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="service instance changed"):
        adapter._verify_attestation(
            response,
            challenge_nonce=challenge,
            request_bytes=request,
            public_key=public_key,
            expected_instance_id="d" * 32,
        )


def test_adapter_rejects_unsigned_and_cross_transport_responses(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    adapter = _adapter(tmp_path)
    challenge = "7" * 64
    request = PROBE_INNER_REQUEST.encode("utf-8")
    response = _attested_response(daemon, challenge=challenge, request=request)
    unsigned = json.loads(json.dumps(response))
    unsigned["attestation"].pop("signature")
    public_key = _public_key(adapter)
    with pytest.raises(NativeAuthorityError, match="unsigned"):
        adapter._verify_attestation(
            unsigned,
            challenge_nonce=challenge,
            request_bytes=request,
            public_key=public_key,
        )
    wrong_transport = json.loads(json.dumps(response))
    wrong_transport["native_transport"] = "named-pipe"
    with pytest.raises(NativeAuthorityError, match="transport is unbound"):
        adapter._verify_attestation(
            wrong_transport,
            challenge_nonce=challenge,
            request_bytes=request,
            public_key=public_key,
        )


def test_probe_inner_request_matches_frontend_constant() -> None:
    """The C/Rust frontends hardcode the probe request bytes; they must
    hash to exactly what the Python adapter expects."""
    assert PROBE_INNER_REQUEST == '{"operation":"ping","protocol":1}'
    assert MAX_NATIVE_REQUEST_BYTES < 64 * 1024
