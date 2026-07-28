"""Strict privileged kernel-authority client regressions."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

from khaos.security.kernel_helper_client import KernelAuthorityClient

TOKEN = "ab" * 32
STATUS = {
    "helper_authenticated": True,
    "network_namespace": True,
    "nft_default_deny": True,
    "cgroup_attached": True,
    "process_isolated": False,
    "resource_registry_verified": True,
    "quarantined": False,
    "proxy_host": "10.200.10.1",
}


def _read_exact(connection: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        data.extend(connection.recv(length - len(data)))
    return bytes(data)


def _start_fake_helper(
    *,
    mutate_response=None,
) -> tuple[str, threading.Thread, dict[str, object]]:
    """Start a fake framed helper that records one strict request."""
    import secrets

    socket_path = f"/tmp/khaos-helper-test-{secrets.token_hex(4)}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    os.chmod(socket_path, 0o600)
    server.listen(1)
    server.settimeout(2)
    state: dict[str, object] = {"requests": [], "socket_path": socket_path}

    def serve() -> None:
        try:
            connection, _ = server.accept()
            connection.settimeout(2)
            length = struct.unpack(">I", _read_exact(connection, 4))[0]
            request = json.loads(_read_exact(connection, length))
            state["requests"].append(request)  # type: ignore[union-attr]
            response = {
                "protocol_version": 1,
                "request_id": request["request_id"],
                "ok": True,
                "error": None,
                "status": dict(STATUS),
            }
            if mutate_response is not None:
                mutate_response(response)
            body = json.dumps(response, separators=(",", ":")).encode()
            connection.sendall(struct.pack(">I", len(body)) + body)
            connection.close()
        except OSError:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return socket_path, thread, state


def _client(monkeypatch: pytest.MonkeyPatch, socket_path: str) -> KernelAuthorityClient:
    monkeypatch.setattr(KernelAuthorityClient, "_validate_socket_authority", lambda self: None)
    monkeypatch.setattr(
        KernelAuthorityClient, "_validate_peer", staticmethod(lambda stream: None)
    )
    monkeypatch.setattr(
        KernelAuthorityClient, "_boot_id", staticmethod(lambda: "boot-id")
    )
    monkeypatch.setattr(
        KernelAuthorityClient, "_process_start_time", staticmethod(lambda pid: 99)
    )
    return KernelAuthorityClient(
        project_id="project",
        runtime_id="runtime",
        sandbox_token=TOKEN,
        socket_path=socket_path,
    )


def _cleanup(socket_path: str, thread: threading.Thread) -> None:
    thread.join(timeout=2)
    try:
        os.unlink(socket_path)
    except OSError:
        pass


def test_client_unavailable_when_socket_missing(tmp_path: Path) -> None:
    client = KernelAuthorityClient(
        project_id="project",
        runtime_id="runtime",
        sandbox_token=TOKEN,
        socket_path=str(tmp_path / "missing.sock"),
    )
    assert not client.available


def test_setup_sends_only_abstract_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    socket_path, thread, state = _start_fake_helper()
    try:
        evidence = _client(monkeypatch, socket_path).setup()
        assert evidence.nft_default_deny
        thread.join(timeout=2)
        request = state["requests"][0]  # type: ignore[index]
        assert request["op"] == "setup"
        assert request["project_id"] == "project"
        assert request["runtime_id"] == "runtime"
        assert request["sandbox_token"] == TOKEN
        forbidden = {"argv", "netns", "veth", "nft_table", "cgroup", "path"}
        assert forbidden.isdisjoint(request)
    finally:
        _cleanup(socket_path, thread)


def test_proxy_and_process_operations_are_typed(monkeypatch: pytest.MonkeyPatch) -> None:
    for method, expected in [
        (lambda client: client.allow_proxy(8123), ("allow_proxy", 8123, None)),
        (lambda client: client.revoke_proxy(8123), ("revoke_proxy", 8123, None)),
        (lambda client: client.attach_process(4321, 987), ("attach_process", None, 4321)),
    ]:
        socket_path, thread, state = _start_fake_helper()
        try:
            method(_client(monkeypatch, socket_path))
            thread.join(timeout=2)
            request = state["requests"][0]  # type: ignore[index]
            assert (request["op"], request["port"], request["target_pid"]) == expected
        finally:
            _cleanup(socket_path, thread)


def test_unknown_response_field_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    socket_path, thread, _ = _start_fake_helper(
        mutate_response=lambda response: response.update({"resource_name": "attacker"})
    )
    try:
        with pytest.raises(RuntimeError, match="response contract invalid"):
            _client(monkeypatch, socket_path).status()
    finally:
        _cleanup(socket_path, thread)


def test_incomplete_evidence_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def remove_evidence(response: dict[str, object]) -> None:
        response["status"].pop("nft_default_deny")  # type: ignore[union-attr]

    socket_path, thread, _ = _start_fake_helper(mutate_response=remove_evidence)
    try:
        with pytest.raises(RuntimeError, match="status contract invalid"):
            _client(monkeypatch, socket_path).status()
    finally:
        _cleanup(socket_path, thread)


def test_teardown_accepts_exact_absence_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def teardown_evidence(response: dict[str, object]) -> None:
        response["status"] = {
            "helper_authenticated": True,
            "network_namespace": False,
            "nft_default_deny": False,
            "cgroup_attached": False,
            "process_isolated": False,
            "resource_registry_verified": True,
            "quarantined": False,
            "proxy_host": "",
        }

    socket_path, thread, _ = _start_fake_helper(mutate_response=teardown_evidence)
    try:
        evidence = _client(monkeypatch, socket_path).teardown()
        assert evidence.helper_authenticated
        assert evidence.resource_registry_verified
        assert not evidence.network_namespace
        assert evidence.proxy_host == ""
    finally:
        _cleanup(socket_path, thread)


def test_teardown_rejects_partial_resource_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def partial_teardown(response: dict[str, object]) -> None:
        response["status"] = {
            **STATUS,
            "proxy_host": "",
        }

    socket_path, thread, _ = _start_fake_helper(mutate_response=partial_teardown)
    try:
        with pytest.raises(RuntimeError, match="teardown evidence invalid"):
            _client(monkeypatch, socket_path).teardown()
    finally:
        _cleanup(socket_path, thread)


@pytest.mark.parametrize("token", ["short", "g" * 64, "a" * 257])
def test_invalid_tokens_rejected(token: str) -> None:
    with pytest.raises(ValueError, match="sandbox token"):
        KernelAuthorityClient(
            project_id="project",
            runtime_id="runtime",
            sandbox_token=token,
        )
