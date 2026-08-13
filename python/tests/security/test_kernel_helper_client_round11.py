"""Strict privileged kernel-authority client regressions."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.posix_host

from khaos.security.kernel_helper_client import (
    KernelAuthorityClient,
    KernelHelperRejected,
)

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
                "error_code": None,
                "error": None,
                "status": dict(STATUS),
                "runtime_capability": None,
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
        principal_id="principal",
        task_id="task",
        sandbox_token=TOKEN,
        runtime_capability="cd" * 32,
        socket_path=socket_path,
    )


def _cleanup(socket_path: str, thread: threading.Thread) -> None:
    thread.join(timeout=2)
    try:
        os.unlink(socket_path)
    except OSError:
        pass


def _start_capability_helper() -> tuple[str, threading.Thread, dict[str, object]]:
    """Serve authorize + setup and prove the issued capability is replayed."""
    import secrets

    socket_path = f"/tmp/khaos-helper-capability-{secrets.token_hex(4)}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    os.chmod(socket_path, 0o600)
    server.listen(2)
    server.settimeout(2)
    state: dict[str, object] = {"requests": []}
    capability = "ef" * 32

    def serve() -> None:
        try:
            for _ in range(2):
                connection, _ = server.accept()
                length = struct.unpack(">I", _read_exact(connection, 4))[0]
                request = json.loads(_read_exact(connection, length))
                state["requests"].append(request)  # type: ignore[union-attr]
                authorizing = request["op"] == "authorize"
                status = (
                    {
                        **STATUS,
                        "network_namespace": False,
                        "nft_default_deny": False,
                        "cgroup_attached": False,
                        "process_isolated": False,
                        "proxy_host": "",
                    }
                    if authorizing
                    else dict(STATUS)
                )
                response = {
                    "protocol_version": 1,
                    "request_id": request["request_id"],
                    "ok": True,
                    "error_code": None,
                    "error": None,
                    "status": status,
                    "runtime_capability": capability if authorizing else None,
                }
                body = json.dumps(response, separators=(",", ":")).encode()
                connection.sendall(struct.pack(">I", len(body)) + body)
                connection.close()
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return socket_path, thread, state


def test_client_unavailable_when_socket_missing(tmp_path: Path) -> None:
    client = KernelAuthorityClient(
        project_id="project",
        runtime_id="runtime",
        principal_id="principal",
        task_id="task",
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
        assert request["principal_id"] == "principal"
        assert request["task_id"] == "task"
        assert request["runtime_capability"] == "cd" * 32
        assert request["sandbox_token"] == TOKEN
        forbidden = {"argv", "netns", "veth", "nft_table", "cgroup", "path"}
        assert forbidden.isdisjoint(request)
    finally:
        _cleanup(socket_path, thread)


def test_setup_first_obtains_runtime_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    socket_path, thread, state = _start_capability_helper()
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
    client = KernelAuthorityClient(
        project_id="project",
        runtime_id="runtime",
        principal_id="principal",
        task_id="task",
        sandbox_token=TOKEN,
        socket_path=socket_path,
    )
    try:
        assert client.setup().nft_default_deny
        requests = state["requests"]
        assert [request["op"] for request in requests] == ["authorize", "setup"]
        assert requests[0]["runtime_capability"] is None
        assert requests[1]["runtime_capability"] == "ef" * 32
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


def test_rejection_exposes_only_generated_stable_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(response: dict[str, object]) -> None:
        response.update(
            {
                "ok": False,
                "error_code": "authorization_denied",
                "error": "runtime capability invalid",
                "status": None,
                "runtime_capability": None,
            }
        )

    socket_path, thread, _ = _start_fake_helper(mutate_response=reject)
    try:
        with pytest.raises(KernelHelperRejected) as rejected:
            _client(monkeypatch, socket_path).status()
        assert rejected.value.code == "authorization_denied"
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


@pytest.mark.parametrize("token", ["short", "g" * 64, "a" * 129])
def test_invalid_tokens_rejected(token: str) -> None:
    with pytest.raises(ValueError, match="sandbox token"):
        KernelAuthorityClient(
            project_id="project",
            runtime_id="runtime",
            principal_id="principal",
            task_id="task",
            sandbox_token=token,
        )


def test_python_and_rust_protocol_contract_matches_canonical_schema() -> None:
    repository = Path(__file__).resolve().parents[3]
    schema = json.loads(
        (repository / "security/browser-kernel-protocol-v1.json").read_text(
            encoding="utf-8"
        )
    )
    rust_generated = (
        repository
        / "rust/khaos-core/src/browser_kernel_protocol_generated.rs"
    ).read_text(encoding="utf-8")
    helper_source = (
        repository
        / "rust/khaos-core/src/bin/khaos-browser-kernel-helper.rs"
    ).read_text(encoding="utf-8")
    launcher_source = (
        repository / "rust/khaos-core/src/bin/khaos-sandbox-launcher.rs"
    ).read_text(encoding="utf-8")

    assert schema["x-khaos-max-message-bytes"] == 8192
    assert schema["properties"]["sandbox_token"]["pattern"] == (
        "^[0-9a-fA-F]{32,128}$"
    )
    assert set(schema["properties"]["op"]["enum"]) == {
        "authorize",
        "setup",
        "allow_proxy",
        "revoke_proxy",
        "attach_process",
        "join",
        "teardown",
        "status",
    }
    for field in ("principal_id", "project_id", "runtime_id", "task_id"):
        assert field in schema["required"]
        assert f"pub {field}: String" in rust_generated
    assert "validate_hex(&request.sandbox_token, 32, 128" in helper_source
    assert "MAX_MESSAGE_BYTES" in helper_source
    assert "PROTOCOL_VERSION" in helper_source
    assert "BrowserKernelRequest as HelperRequest" in launcher_source
    assert "BrowserKernelResponseOwned as HelperResponse" in launcher_source
    assert "struct HelperRequest" not in launcher_source
    assert "HelperOperation::Authorize" in launcher_source
    assert "HelperOperation::Join" in launcher_source
    for identity_env in (
        "KHAOS_BROWSER_PRINCIPAL_ID",
        "KHAOS_BROWSER_PROJECT_ID",
        "KHAOS_BROWSER_RUNTIME_ID",
        "KHAOS_BROWSER_TASK_ID",
    ):
        assert identity_env in launcher_source
