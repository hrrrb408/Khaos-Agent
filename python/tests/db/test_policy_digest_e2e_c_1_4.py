"""M4 Batch 3.1.16C-1-4 — Policy Digest End-to-End Verification.

Acceptance tests for the RPC-bound policy_digest drift detection
and the Bootstrap.GetPolicyDigest startup handshake introduced by
C-1-4 (built on top of A-5-1b's project_id drift detection).

C-1-3 added project_id drift detection (Gateway stamps project_id
in every RPC payload; Python rejects mismatches as ``project_drift``).
C-1-4 adds the symmetric policy_digest drift detection:

  1. Bootstrap.GetPolicyDigest RPC — Gateway startup handshake that
     fetches the server-bound policy_digest.  Python is the sole
     authority for policy_digest; Go never computes it independently.
  2. policy_drift detection — dispatcher compares
     ``payload["policy_digest"]`` against
     ``agent._effective_policy.digest``; mismatch → fail-closed
     rejection with ``{"error": "policy_drift"}``.
  3. Empty claim accepted — backward compat with older Gateways or
     when the bootstrap handshake failed.

Verifies:
  1. Bootstrap.GetPolicyDigest returns the server-bound digest.
  2. RPC dispatcher rejects ``policy_drift`` when payload
     policy_digest != server-bound policy_digest (fail-closed).
  3. RPC dispatcher accepts matching payload policy_digest.
  4. RPC dispatcher accepts empty payload policy_digest (backward
     compat with older Gateways).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

import pytest

from khaos.grpc_server import serve_json_lines
from khaos.security.effective_policy import load_effective_policy


# ───────────────────────── helpers ─────────────────────────


def _signed_rpc_request(
    method: str,
    payload: dict,
    *,
    nonce: str = "n" * 32,
    capability: str = "c" * 48,
):
    """Build a Gateway-signed JSON-line RPC request (mirrors production)."""
    issued_at = int(time.time())
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    principal = str(payload.get("principal_id") or "gateway")
    signed = f"{method}\n{nonce}\n{issued_at}\n{principal}\n{digest}".encode()
    method_key = hmac.new(
        capability.encode(),
        f"khaos-rpc-method-v1\n{method}".encode(),
        hashlib.sha256,
    ).digest()
    return {
        "method": method,
        "payload": payload,
        "auth": {
            "nonce": nonce,
            "issued_at": issued_at,
            "principal_id": principal,
            "payload_digest": digest,
            "mac": hmac.new(method_key, signed, hashlib.sha256).hexdigest(),
        },
    }


async def _wait_for_socket(socket_path: Path, server_task: asyncio.Task):
    """Wait for UDS to appear or server to fail."""
    for _ in range(200):
        if socket_path.exists() or server_task.done():
            break
        await asyncio.sleep(0.01)
    if server_task.done():
        try:
            await server_task
        except (PermissionError, OSError) as exc:
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")


async def _connect(socket_path: Path):
    """Connect to the UDS, skipping if sandbox disallows."""
    try:
        return await asyncio.open_unix_connection(str(socket_path))
    except (PermissionError, OSError) as exc:
        pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")


# ─────────────── Bootstrap.GetPolicyDigest handshake ───────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_c_1_4_bootstrap_returns_policy_digest(tmp_path):
    """C-1-4 #1: Bootstrap.GetPolicyDigest returns server-bound digest.

    The Gateway calls this RPC once at startup to fetch the
    server-bound policy_digest.  Python is the sole authority —
    Go never computes the digest independently.
    """
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"bootstrap-pd-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        await _wait_for_socket(socket_path, server_task)
        reader, writer = await _connect(socket_path)

        # Bootstrap.GetPolicyDigest — empty payload, empty principal.
        request = _signed_rpc_request(
            "Bootstrap.GetPolicyDigest",
            {},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))

        # The returned digest must match the server's effective policy.
        expected = load_effective_policy(tmp_path).digest
        assert response.get("policy_digest") == expected
        assert "error" not in response

        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ─────────────── RPC policy_drift detection (reject) ───────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_c_1_4_rpc_rejects_policy_drift(tmp_path):
    """C-1-4 #2: RPC dispatcher rejects ``policy_drift`` (fail-closed).

    A request that claims a different ``policy_digest`` in the payload
    is rejected with ``{"error": "policy_drift"}`` BEFORE any service
    method runs.
    """
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"pdrift-reject-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        await _wait_for_socket(socket_path, server_task)
        reader, writer = await _connect(socket_path)

        # Claim a policy_digest that differs from the server's bound value.
        request = _signed_rpc_request(
            "TaskService.List",
            {"policy_digest": "deadbeef" * 8, "principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert response.get("error") == "policy_drift"
        assert "does not match server-bound policy_digest" in response.get("message", "")
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ─────────────── RPC policy_drift detection (accept matching) ─────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_c_1_4_rpc_accepts_matching_policy_digest(tmp_path):
    """C-1-4 #3: RPC dispatcher accepts payload policy_digest == bound."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"pdrift-match-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        await _wait_for_socket(socket_path, server_task)
        reader, writer = await _connect(socket_path)

        # Claim the SAME policy_digest the server booted under.
        bound_pd = load_effective_policy(tmp_path).digest
        request = _signed_rpc_request(
            "ChannelService.List",
            {"policy_digest": bound_pd, "principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        # No drift error — a normal service response (channels list).
        assert "error" not in response
        assert isinstance(response.get("channels"), list)
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


# ─────────────── RPC policy_drift detection (accept empty) ────────────


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_c_1_4_rpc_accepts_empty_policy_digest(tmp_path):
    """C-1-4 #4: RPC dispatcher accepts empty payload policy_digest (backward compat).

    Older Gateways that don't send ``policy_digest`` in the payload
    (or when the bootstrap handshake failed) are accepted —
    ``ctx.policy_digest`` remains the server-bound value, and the
    request proceeds normally.
    """
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")

    socket_parent = Path("/tmp") / f"pdrift-empty-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    try:
        await _wait_for_socket(socket_path, server_task)
        reader, writer = await _connect(socket_path)

        # No policy_digest in payload — backward compat.
        request = _signed_rpc_request(
            "ChannelService.List",
            {"principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert "error" not in response
        assert isinstance(response.get("channels"), list)
        writer.close()
        try:
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()
