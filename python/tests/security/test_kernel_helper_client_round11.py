"""Batch 11.4 (round-11 §七): privileged kernel-helper client regressions."""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

from khaos.security.kernel_helper_client import KernelHelperClient


def _start_fake_helper(tmp_path: Path) -> tuple[str, threading.Thread, dict]:
    """Start a fake UDS helper that records requests and responds ok."""
    # Use /tmp (short path) to avoid AF_UNIX path-length limits on macOS.
    import secrets
    socket_path = f"/tmp/khaos-helper-test-{secrets.token_hex(4)}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    os.chmod(socket_path, 0o600)
    server.listen(1)
    server.settimeout(2)
    state: dict = {"requests": [], "socket_path": socket_path}

    def serve():
        try:
            conn, _ = server.accept()
            conn.settimeout(2)
            length = int.from_bytes(conn.recv(4), "big")
            data = conn.recv(length)
            state["requests"].append(json.loads(data))
            conn.sendall(b'{"ok":true}')
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return socket_path, thread, state


def test_client_unavailable_when_socket_missing(tmp_path) -> None:
    """The client reports unavailable when the socket does not exist."""
    client = KernelHelperClient(socket_path=str(tmp_path / "nope.sock"))
    assert not client.available


def test_client_available_when_socket_exists(tmp_path) -> None:
    """The client reports available when the socket exists."""
    socket_path, thread, _ = _start_fake_helper(tmp_path)
    try:
        client = KernelHelperClient(socket_path=socket_path)
        assert client.available
    finally:
        try:
            os.unlink(socket_path)
        except OSError:
            pass
        thread.join(timeout=1)


def test_create_netns_sends_correct_request(tmp_path) -> None:
    """create_netns sends {op: create, token: ...} and returns True on ok."""
    socket_path, thread, state = _start_fake_helper(tmp_path)
    try:
        client = KernelHelperClient(socket_path=socket_path)
        result = client.create_netns("abcdef0123456789")
        assert result is True
        thread.join(timeout=2)
        assert state["requests"] == [{"op": "create", "token": "abcdef0123456789"}]
    finally:
        try:
            os.unlink(socket_path)
        except OSError:
            pass
        thread.join(timeout=1)


def test_delete_netns_sends_correct_request(tmp_path) -> None:
    """delete_netns sends {op: delete, token: ...} and returns True on ok."""
    socket_path, thread, state = _start_fake_helper(tmp_path)
    try:
        client = KernelHelperClient(socket_path=socket_path)
        result = client.delete_netns("abcdef0123456789")
        assert result is True
        thread.join(timeout=2)
        assert state["requests"] == [{"op": "delete", "token": "abcdef0123456789"}]
    finally:
        try:
            os.unlink(socket_path)
        except OSError:
            pass
        thread.join(timeout=1)
