"""Strict client for the privileged browser kernel authority.

The Python runtime supplies only project/runtime identity and an opaque
sandbox token.  Kernel resource names, paths, command selection, ownership,
transactions, and recovery remain private to the authenticated Rust helper.
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import socket
import stat
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from khaos.security.browser_kernel_protocol_generated import (
    ERROR_CODES,
    MAX_MESSAGE_BYTES,
    OPERATIONS,
    PROTOCOL_VERSION,
    REQUEST_FIELDS,
    RESPONSE_FIELDS,
    SANDBOX_TOKEN_PATTERN,
    STATUS_FIELDS,
)

_SOCKET_ENV: Final = "KHAOS_BROWSER_KERNEL_HELPER_SOCKET"
_DEFAULT_SOCKET: Final = "/run/khaos/browser-kernel-helper.sock"
_PROTOCOL_VERSION: Final = PROTOCOL_VERSION
_MAX_MESSAGE: Final = MAX_MESSAGE_BYTES
_TOKEN_PATTERN: Final = re.compile(SANDBOX_TOKEN_PATTERN)
_RESPONSE_FIELDS: Final = RESPONSE_FIELDS
_STATUS_FIELDS: Final = STATUS_FIELDS


class KernelHelperRejected(RuntimeError):
    """A fail-closed helper rejection with a stable protocol error code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"kernel helper rejected request [{code}]: {detail}")
        self.code = code


@dataclass(frozen=True)
class KernelIsolationEvidence:
    """Evidence returned by the authenticated kernel authority."""

    helper_authenticated: bool
    network_namespace: bool
    nft_default_deny: bool
    cgroup_attached: bool
    process_isolated: bool
    resource_registry_verified: bool
    quarantined: bool
    proxy_host: str

    @classmethod
    def from_payload(
        cls,
        payload: object,
        *,
        resources_active: bool = True,
    ) -> KernelIsolationEvidence:
        """Parse exact operation-specific helper evidence.

        Active operations must return a private IPv4 proxy endpoint.  A
        successful teardown must instead prove that every kernel resource is
        absent and must not retain a stale endpoint.  Keeping those contracts
        distinct prevents cleanup success from being rejected by setup-only
        validation while still failing closed on partial teardown.
        """
        if not isinstance(payload, dict) or set(payload) != _STATUS_FIELDS:
            raise RuntimeError("kernel helper status contract invalid")
        boolean_fields = _STATUS_FIELDS - {"proxy_host"}
        if any(type(payload[field]) is not bool for field in boolean_fields):
            raise RuntimeError("kernel helper status evidence must be boolean")
        if type(payload["proxy_host"]) is not str or len(payload["proxy_host"]) > 64:
            raise RuntimeError("kernel helper proxy host evidence invalid")
        if resources_active:
            try:
                proxy_host = ipaddress.ip_address(payload["proxy_host"])
            except ValueError as error:
                raise RuntimeError("kernel helper proxy host evidence invalid") from error
            if proxy_host.version != 4 or not proxy_host.is_private or proxy_host.is_loopback:
                raise RuntimeError("kernel helper proxy host authority invalid")
        elif (
            payload["proxy_host"] != ""
            or not payload["helper_authenticated"]
            or not payload["resource_registry_verified"]
            or payload["network_namespace"]
            or payload["nft_default_deny"]
            or payload["cgroup_attached"]
            or payload["process_isolated"]
            or payload["quarantined"]
        ):
            raise RuntimeError("kernel helper teardown evidence invalid")
        return cls(**payload)


class KernelAuthorityClient:
    """Authenticated, deadline-bound client for the Linux kernel helper."""

    def __init__(
        self,
        *,
        project_id: str,
        runtime_id: str,
        principal_id: str,
        task_id: str,
        sandbox_token: str,
        runtime_capability: str | None = None,
        socket_path: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._project_id = self._validate_identifier(project_id, "project_id")
        self._runtime_id = self._validate_identifier(runtime_id, "runtime_id")
        self._principal_id = self._validate_identifier(principal_id, "principal_id")
        self._task_id = self._validate_identifier(task_id, "task_id")
        self._sandbox_token = self._validate_token(sandbox_token)
        self._runtime_capability = (
            self._validate_capability(runtime_capability)
            if runtime_capability is not None
            else None
        )
        self._socket_path = socket_path or os.environ.get(_SOCKET_ENV, _DEFAULT_SOCKET)
        if not Path(self._socket_path).is_absolute():
            raise ValueError("kernel helper socket must be absolute")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("kernel helper timeout must be in (0, 30]")
        self._timeout_seconds = timeout_seconds

    @property
    def available(self) -> bool:
        """Return whether the configured endpoint currently passes TCB checks."""
        try:
            self._validate_socket_authority()
        except (OSError, RuntimeError):
            return False
        return True

    def setup(self) -> KernelIsolationEvidence:
        """Create the complete transactional kernel sandbox."""
        return self._request("setup")

    def allow_proxy(self, port: int) -> KernelIsolationEvidence:
        """Atomically allow one loopback proxy port through default-deny nft."""
        return self._request("allow_proxy", port=self._validate_port(port))

    def revoke_proxy(self, port: int) -> KernelIsolationEvidence:
        """Atomically revoke one loopback proxy port."""
        return self._request("revoke_proxy", port=self._validate_port(port))

    def attach_process(self, pid: int, start_time: int) -> KernelIsolationEvidence:
        """Attach an exact descendant process identity to the helper cgroup."""
        if pid <= 1 or start_time <= 0:
            raise ValueError("target process identity invalid")
        return self._request(
            "attach_process",
            target_pid=pid,
            target_start_time=start_time,
        )

    def teardown(self) -> KernelIsolationEvidence:
        """Transactionally remove all helper-owned kernel resources."""
        return self._request("teardown")

    def status(self) -> KernelIsolationEvidence:
        """Read current evidence from the helper-owned resource registry."""
        return self._request("status")

    def _request(
        self,
        op: str,
        *,
        port: int | None = None,
        target_pid: int | None = None,
        target_start_time: int | None = None,
    ) -> KernelIsolationEvidence:
        if op != "authorize" and self._runtime_capability is None:
            self._request("authorize")
        self._validate_socket_authority()
        request_id = str(uuid.uuid4())
        client_pid = os.getpid()
        request = {
            "protocol_version": _PROTOCOL_VERSION,
            "request_id": request_id,
            "boot_id": self._boot_id(),
            "client_pid": client_pid,
            "client_start_time": self._process_start_time(client_pid),
            "project_id": self._project_id,
            "runtime_id": self._runtime_id,
            "principal_id": self._principal_id,
            "task_id": self._task_id,
            "sandbox_token": self._sandbox_token,
            "runtime_capability": self._runtime_capability,
            "op": op,
            "port": port,
            "target_pid": target_pid,
            "target_start_time": target_start_time,
        }
        if set(request) != REQUEST_FIELDS or op not in OPERATIONS:
            raise RuntimeError("kernel helper request contract invalid")
        body = json.dumps(request, separators=(",", ":"), sort_keys=True).encode()
        if len(body) > _MAX_MESSAGE:
            raise RuntimeError("kernel helper request exceeds protocol limit")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(self._timeout_seconds)
            stream.connect(self._socket_path)
            self._validate_peer(stream)
            stream.sendall(struct.pack(">I", len(body)))
            stream.sendall(body)
            response_length = struct.unpack(">I", self._read_exact(stream, 4))[0]
            if response_length == 0 or response_length > _MAX_MESSAGE:
                raise RuntimeError("kernel helper response length invalid")
            response_body = self._read_exact(stream, response_length)
        try:
            response = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("kernel helper returned invalid JSON") from error
        if not isinstance(response, dict) or set(response) != _RESPONSE_FIELDS:
            raise RuntimeError("kernel helper response contract invalid")
        if (
            type(response["protocol_version"]) is not int
            or response["protocol_version"] != _PROTOCOL_VERSION
            or type(response["request_id"]) is not str
            or response["request_id"] != request_id
            or type(response["ok"]) is not bool
            or response["error_code"] is not None
            and type(response["error_code"]) is not str
            or response["error"] is not None
            and type(response["error"]) is not str
        ):
            raise RuntimeError("kernel helper response identity invalid")
        if not response["ok"]:
            error_code = response["error_code"]
            error = response["error"]
            if (
                error_code not in ERROR_CODES
                or type(error) is not str
                or not error
                or len(error) > 1024
                or response["status"] is not None
                or response["runtime_capability"] is not None
            ):
                raise RuntimeError("kernel helper error response contract invalid")
            raise KernelHelperRejected(error_code, error)
        if response["error"] is not None or response["error_code"] is not None:
            raise RuntimeError("successful kernel helper response carried an error")
        response_capability = response["runtime_capability"]
        if op == "authorize":
            if self._runtime_capability is not None:
                raise RuntimeError("kernel helper replaced an active runtime capability")
            self._runtime_capability = self._validate_capability(response_capability)
        elif response_capability is not None:
            raise RuntimeError("kernel helper leaked runtime capability")
        return KernelIsolationEvidence.from_payload(
            response["status"],
            resources_active=op not in {"authorize", "teardown"},
        )

    def _validate_socket_authority(self) -> None:
        socket_path = Path(self._socket_path)
        metadata = socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("kernel helper socket type or mode invalid")
        current = socket_path.parent
        while current != current.parent:
            parent_metadata = current.lstat()
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise RuntimeError("kernel helper socket parent authority invalid")
            current = current.parent

    @staticmethod
    def _validate_peer(stream: socket.socket) -> None:
        if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("kernel helper peer authentication requires Linux")
        credentials = stream.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, _gid = struct.unpack("3i", credentials)
        if uid != 0 or pid <= 1:
            raise RuntimeError("kernel helper peer is not the root authority")
        KernelAuthorityClient._process_start_time(pid)

    @staticmethod
    def _read_exact(stream: socket.socket, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            chunk = stream.recv(length - len(chunks))
            if not chunk:
                raise RuntimeError("kernel helper closed a partial response")
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _boot_id() -> str:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if not value or len(value) > 128:
            raise RuntimeError("kernel boot identity unavailable")
        return value

    @staticmethod
    def _process_start_time(pid: int) -> int:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        end = value.rfind(")")
        if end < 0:
            raise RuntimeError("process start identity invalid")
        fields = value[end + 2 :].split()
        if len(fields) <= 19:
            raise RuntimeError("process start identity missing")
        start_time = int(fields[19])
        if start_time <= 0:
            raise RuntimeError("process start identity invalid")
        return start_time

    @staticmethod
    def _validate_identifier(value: str, label: str) -> str:
        if (
            not value
            or len(value) > 128
            or any(not (character.isalnum() or character in "-_:.") for character in value)
        ):
            raise ValueError(f"invalid {label}")
        return value

    @staticmethod
    def _validate_token(value: str) -> str:
        if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid sandbox token")
        return value.lower()

    @staticmethod
    def _validate_capability(value: object) -> str:
        if type(value) is not str or len(value) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in value
        ):
            raise ValueError("invalid runtime capability")
        return value.lower()

    @staticmethod
    def _validate_port(value: int) -> int:
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError("invalid proxy port")
        return value


# Compatibility import name.  The old create_netns/delete_netns contract was
# intentionally removed: production callers must request the whole transaction.
KernelHelperClient = KernelAuthorityClient

__all__ = [
    "KernelAuthorityClient",
    "KernelHelperClient",
    "KernelIsolationEvidence",
]
