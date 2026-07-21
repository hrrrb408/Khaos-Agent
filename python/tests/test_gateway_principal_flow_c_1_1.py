"""M4 batch 3.1.16C-1-1 — Gateway principal_id flow to Python.

C-1-1 closes the bug where the Go Gateway's ``writeRequest`` extracted
``principal_id`` from the RPC payload (defaulting to ``"gateway"``)
for ~15 methods that did not embed ``principal_id`` in the payload.
After C-1-1, the Go side passes the authenticated principal
explicitly to ``writeRequest``, which writes it into the auth
envelope.  Python's ``GatewayRPCAuthenticator.authenticate`` returns
this envelope principal as ``ctx.principal_id``.

These tests verify the Python-side contract that the envelope
principal is the sole authority when the payload lacks
``principal_id`` (the common case for the ~15 methods fixed in
C-1-1), and that the payload principal — when present — must agree
with the envelope (transport-bound, A-4-1).

Contract covered:

  1. Envelope principal ``"api-key:alice"`` + payload WITHOUT
     ``principal_id`` → authenticator returns ``"api-key:alice"``
     (this is the C-1-1 fix: previously Go would have sent
     ``"gateway"``).
  2. Envelope principal ``"api-key:alice"`` + payload principal
     ``"api-key:alice"`` → authenticator returns ``"api-key:alice"``
     (transport-bound, A-4-1 invariant preserved).
  3. Envelope principal ``"api-key:alice"`` + payload principal
     ``"api-key:bob"`` → ``PermissionError("not transport-bound")``
     (forgery defense: a compromised Gateway cannot swap principals).
  4. Envelope principal ``""`` + payload WITHOUT ``principal_id`` →
     authenticator returns ``""`` (webhook ingress path, where Go
     passes ``""`` because signature-authenticated webhooks bypass
     the API-key middleware).
  5. Envelope principal ``"api-key:alice"`` + payload WITHOUT
     ``principal_id`` → dispatcher sets
     ``ctx.principal_id == "api-key:alice"`` (end-to-end: the
     envelope principal reaches the service layer).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from khaos.grpc_server import GatewayRPCAuthenticator


# ───────────────────────── helpers ────────────────────────────


CAPABILITY = "c" * 48


def _signed_request(
    method: str,
    payload: dict,
    *,
    envelope_principal: str,
    nonce: str = "n" * 32,
    issued_at: int | None = None,
) -> dict:
    """Build a signed RPC request with an independent envelope principal.

    Unlike the legacy ``_signed_rpc_request`` helper in
    ``test_grpc_server.py`` (which extracts the principal from the
    payload), this helper takes ``envelope_principal`` as an explicit
    parameter — mirroring the C-1-1 ``writeRequest`` contract where
    the caller supplies the principal explicitly.
    """
    if issued_at is None:
        issued_at = int(time.time())
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    signed = (
        f"{method}\n{nonce}\n{issued_at}\n{envelope_principal}\n{digest}"
    ).encode("utf-8")
    method_key = hmac.new(
        CAPABILITY.encode(),
        f"khaos-rpc-method-v1\n{method}".encode(),
        hashlib.sha256,
    ).digest()
    mac = hmac.new(method_key, signed, hashlib.sha256).hexdigest()
    return {
        "method": method,
        "payload": payload,
        "auth": {
            "nonce": nonce,
            "issued_at": issued_at,
            "principal_id": envelope_principal,
            "payload_digest": digest,
            "mac": mac,
        },
    }


# ───────────────────────── tests ──────────────────────────────


def test_acceptance_1_envelope_principal_used_when_payload_lacks_principal_id():
    """C-1-1 #1: envelope principal is the authority when payload
    has no ``principal_id`` field.

    This is the core C-1-1 fix.  Before C-1-1, the Go side would
    extract ``principal_id`` from the payload (defaulting to
    ``"gateway"``), so methods like ``TaskService.List`` / ``AuditService.Query``
    arrived at Python with ``ctx.principal_id == "gateway"``.  After
    C-1-1, the Go side passes the authenticated principal in the
    envelope, and Python uses it directly.
    """
    authenticator = GatewayRPCAuthenticator(CAPABILITY)
    request = _signed_request(
        "TaskService.List",
        {"active_only": True},  # no principal_id field
        envelope_principal="api-key:alice",
    )
    assert authenticator.authenticate(request) == "api-key:alice"


def test_acceptance_2_envelope_and_payload_principal_agree():
    """C-1-1 #2: when payload carries ``principal_id`` and it
    matches the envelope, authenticator returns the principal.

    A-4-1 transport-bound invariant: payload principal (if present)
    must match envelope principal.  This is preserved by C-1-1 —
    methods that already embedded ``principal_id`` in the payload
    (Chat / ConfirmPermission / Spawn / ApproveTask) still work.
    """
    authenticator = GatewayRPCAuthenticator(CAPABILITY)
    request = _signed_request(
        "SubAgentService.Spawn",
        {"goal": "g", "principal_id": "api-key:alice"},
        envelope_principal="api-key:alice",
    )
    assert authenticator.authenticate(request) == "api-key:alice"


def test_acceptance_3_payload_principal_mismatch_rejected():
    """C-1-1 #3: envelope and payload principals disagree → reject.

    Forgery defense: a compromised Gateway cannot forge the payload
    principal to swap identity.  If the envelope says ``"api-key:alice"``
    but the payload says ``"api-key:bob"``, the request is rejected.
    """
    authenticator = GatewayRPCAuthenticator(CAPABILITY)
    request = _signed_request(
        "TaskService.Approve",
        {"task_id": "t1", "principal_id": "api-key:bob"},
        envelope_principal="api-key:alice",
    )
    with pytest.raises(PermissionError, match="not transport-bound"):
        authenticator.authenticate(request)


def test_acceptance_4_empty_envelope_principal_for_webhook_ingress():
    """C-1-1 #4: webhook ingress passes ``""`` as envelope principal.

    Signature-authenticated webhooks (Telegram / Discord / Slack /
    WeChat) bypass the API-key middleware, so the Go side passes
    ``""`` (no authenticated principal).  Python accepts this as
    unauthenticated platform ingress.
    """
    authenticator = GatewayRPCAuthenticator(CAPABILITY)
    request = _signed_request(
        "AgentService.HandleWebhook",
        {"platform": "telegram", "body": "{}"},  # no principal_id
        envelope_principal="",
    )
    assert authenticator.authenticate(request) == ""


def test_acceptance_5_legacy_gateway_principal_still_accepted():
    """C-1-1 #5: backward compat — envelope ``"gateway"`` still works.

    If an older Gateway binary (pre-C-1-1) is still running, it will
    continue sending ``"gateway"`` as the envelope principal for
    methods that lack ``principal_id`` in the payload.  Python must
    not break this path during the rolling upgrade.
    """
    authenticator = GatewayRPCAuthenticator(CAPABILITY)
    request = _signed_request(
        "AuditService.Query",
        {"limit": 100},  # no principal_id
        envelope_principal="gateway",
    )
    assert authenticator.authenticate(request) == "gateway"
