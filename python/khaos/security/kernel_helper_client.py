"""Batch 11.4 (round-11 §七): client for the privileged browser-kernel helper.

When the minimal root-owned ``khaos-browser-kernel-helper`` binary is
available (``KHAOS_BROWSER_KERNEL_HELPER_SOCKET``), this client routes
the privileged netns create/delete operations through it instead of
spawning ``ip``/``nft`` directly from the Python Agent.  This is the
first step toward moving the Python Agent out of the privileged TCB.

The helper derives resource names from the caller-supplied token (same
derivation as ``BrowserNetworkSandbox``), so a compromised Python
process cannot name an arbitrary resource for deletion (Confused Deputy
defense).  The helper validates the peer UID, so only the configured
Khaos user may connect.

When the helper socket is NOT configured, ``KernelHelperClient`` reports
unavailable and the caller falls back to the CLI path — this is the
transition mechanism.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path

logger = logging.getLogger(__name__)

_SOCKET_ENV = "KHAOS_BROWSER_KERNEL_HELPER_SOCKET"


class KernelHelperClient:
    """Client for the privileged browser-kernel helper (UDS)."""

    def __init__(self, socket_path: str | None = None) -> None:
        self._socket_path = socket_path or os.environ.get(_SOCKET_ENV, "")

    @property
    def available(self) -> bool:
        """True if the helper socket is configured and exists."""
        return bool(self._socket_path) and Path(self._socket_path).is_socket()

    def _request(self, op: str, token: str) -> dict[str, object]:
        """Send a single request-response to the helper."""
        if not self.available:
            raise RuntimeError("kernel helper not available")
        request = json.dumps({"op": op, "token": token}).encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(self._socket_path)
            sock.sendall(len(request).to_bytes(4, "big"))
            sock.sendall(request)
            response = sock.recv(4096)
        return json.loads(response.decode("utf-8"))  # type: ignore[no-any-return]

    def create_netns(self, token: str) -> bool:
        """Ask the helper to create the netns for ``token``."""
        result = self._request("create", token)
        if not result.get("ok"):
            logger.error("kernel helper create failed: %s", result.get("error"))
            return False
        return True

    def delete_netns(self, token: str) -> bool:
        """Ask the helper to delete the netns for ``token``."""
        result = self._request("delete", token)
        if not result.get("ok"):
            logger.debug("kernel helper delete: %s", result.get("error"))
            return False
        return True
