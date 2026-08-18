"""Windows Named-Pipe backend for the authority control plane.

The native Service-SID frontend
(``rust/khaos-core/src/bin/khaos-authorityd-windows.rs``) is the platform
TCB that authenticates the Agent peer.  It forwards each bounded request to
the backend pipe named by ``KHAOS_AUTHORITYD_BACKEND_PIPE``.  This module is
that backend: it serves a message-mode Named Pipe whose DACL grants access
only to ``NT AUTHORITY\\SYSTEM`` and the configured authority Service SID,
validates the connecting client's process-token SID on every connection, and
dispatches to the same :class:`AuthorityDaemon` control plane used on Linux.

There is no agent-reachable path: the pipe DACL rejects the Agent SID before
a single byte is read, and the per-connection SID check fails closed.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from khaos.security.authorityd import AuthorityDaemon, _dispatch
from khaos.security.authorityd_protocol import MAX_MESSAGE_BYTES
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    read_contract_from_environment,
)

logger = logging.getLogger(__name__)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 0x00000217
ERROR_BROKEN_PIPE = 0x00000109
INVALID_HANDLE_VALUE = -1
TOKEN_QUERY = 0x0008
TokenUser = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_SDDL_TEMPLATE = "D:P(A;;GA;;;SY)(A;;GA;;;{service_sid})"


def build_backend_sddl(service_sid: str) -> str:
    """Build the fail-closed DACL string for the backend pipe.

    Only ``NT AUTHORITY\\SYSTEM`` and the authority Service SID may open the
    pipe.  The Agent SID is deliberately absent: the kernel enforces the
    frontend/backend boundary before any application logic runs.
    """
    sid = service_sid.strip()
    if not sid.startswith("S-1-") or len(sid) > 184:
        raise IdentityIsolationError("authority backend Service SID is malformed")
    return _SDDL_TEMPLATE.format(service_sid=sid)


def _kernel32() -> Any:
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]


def _advapi32() -> Any:
    import ctypes

    return ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]


def _client_process_sid(kernel32: Any, pipe_handle: int) -> str:
    """Return the connecting client process's token-user SID, fail closed."""
    import ctypes

    client_pid = ctypes.c_ulong(0)
    if not kernel32.GetNamedPipeClientProcessId(
        ctypes.c_void_p(pipe_handle), ctypes.byref(client_pid)
    ):
        raise IdentityIsolationError("backend pipe client PID is unavailable")
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, client_pid.value
    )
    if not process:
        raise IdentityIsolationError("backend pipe client process is unavailable")
    try:
        token = ctypes.c_void_p()
        if not kernel32.OpenProcessToken(
            ctypes.c_void_p(process), TOKEN_QUERY, ctypes.byref(token)
        ):
            raise IdentityIsolationError("backend pipe client token is unavailable")
        try:
            advapi32 = _advapi32()
            needed = ctypes.c_ulong(0)
            advapi32.GetTokenInformation(
                token, TokenUser, None, 0, ctypes.byref(needed)
            )
            if needed.value == 0:
                raise IdentityIsolationError("backend pipe client SID is unavailable")
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                token, TokenUser, buffer, needed.value, ctypes.byref(needed)
            ):
                raise IdentityIsolationError("backend pipe client SID is unavailable")
            # TOKEN_USER layout: SID* User.Sid (offset 0 on x64), then attrs.
            sid_ptr = ctypes.c_void_p.from_buffer(buffer).value
            if not sid_ptr:
                raise IdentityIsolationError("backend pipe client SID is malformed")
            text = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(
                ctypes.c_void_p(sid_ptr), ctypes.byref(text)
            ):
                raise IdentityIsolationError("backend pipe client SID is malformed")
            try:
                return text.value or ""
            finally:
                kernel32.LocalFree(ctypes.c_void_p(text))
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(process))


def serve_windows_backend(daemon: AuthorityDaemon, *, production: bool = True) -> None:
    """Serve the authority backend Named Pipe with per-connection SID checks.

    This transport is Windows-only.  Each accepted connection is validated
    against the configured authority Service SID before any request bytes
    are read, and the request/response framing is strictly one bounded
    message per connection.
    """
    if os.name != "nt":
        raise IdentityIsolationError(
            "the Windows authority backend transport requires Windows"
        )
    contract = read_contract_from_environment()
    if production:
        contract.validate(production=True)
    pipe_name = os.environ.get("KHAOS_AUTHORITYD_BACKEND_PIPE", "")
    if (
        not pipe_name
        or not pipe_name.startswith("\\\\.\\pipe\\")
        or len(pipe_name) > 256
    ):
        raise IdentityIsolationError(
            "KHAOS_AUTHORITYD_BACKEND_PIPE must be a bounded local pipe path"
        )
    service_sid = contract.service_sid or ""
    if not service_sid:
        raise IdentityIsolationError(
            "the authority backend requires the authority Service SID contract"
        )
    # The frontend may connect as its dedicated Service SID or as
    # LocalSystem (the OS identity SCM uses when the frontend service has
    # no dedicated account).  Any other peer is rejected before a single
    # request byte is read.
    trusted_peer_sids = {service_sid, "S-1-5-18"}
    import ctypes

    kernel32 = _kernel32()
    advapi32 = _advapi32()
    sddl = ctypes.c_wchar_p(build_backend_sddl(service_sid))
    security_attributes = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(security_attributes), None
    ):
        raise IdentityIsolationError("backend pipe DACL construction failed")

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", ctypes.c_ulong),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", ctypes.c_int),
        ]

    attributes = _SECURITY_ATTRIBUTES(
        ctypes.sizeof(_SECURITY_ATTRIBUTES), security_attributes, 0
    )
    pipe_w = ctypes.c_wchar_p(pipe_name)
    while not daemon._closed:
        handle = kernel32.CreateNamedPipeW(
            pipe_w,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE
            | PIPE_READMODE_MESSAGE
            | PIPE_WAIT
            | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            MAX_MESSAGE_BYTES,
            MAX_MESSAGE_BYTES,
            5000,
            ctypes.byref(attributes),
        )
        if handle == INVALID_HANDLE_VALUE or not handle:
            raise IdentityIsolationError("backend CreateNamedPipeW failed")
        try:
            connected = kernel32.ConnectNamedPipe(ctypes.c_void_p(handle), None)
            last_error = ctypes.get_last_error()
            # ERROR_PIPE_CONNECTED is the legal race where the client
            # connected between CreateNamedPipeW and ConnectNamedPipe.
            if not connected and last_error != ERROR_PIPE_CONNECTED:
                continue
            try:
                observed_sid = _client_process_sid(kernel32, handle)
                if observed_sid not in trusted_peer_sids:
                    raise IdentityIsolationError(
                        "backend pipe peer SID is not a trusted authority identity"
                    )
                request = _read_pipe_message(kernel32, handle)
                response = _dispatch(
                    daemon, json.loads(request.decode("utf-8", errors="strict"))
                )
                body = (
                    json.dumps(response, sort_keys=True, separators=(",", ":"))
                    .encode("utf-8")
                    + b"\n"
                )
                _write_pipe_message(kernel32, handle, body)
            except IdentityIsolationError as exc:
                logger.error("authority backend rejected a peer: %s", exc)
            except (OSError, ValueError, TypeError) as exc:
                logger.error("authority backend request failed: %s", exc)
                try:
                    failure = json.dumps(
                        {"ok": False, "error": str(exc)},
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    _write_pipe_message(kernel32, handle, failure + b"\n")
                except (OSError, ValueError):
                    pass
            finally:
                kernel32.DisconnectNamedPipe(ctypes.c_void_p(handle))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))


def _read_pipe_message(kernel32: Any, handle: int) -> bytes:
    """Read one bounded message-mode frame, failing closed on truncation."""
    import ctypes

    buffer = ctypes.create_string_buffer(MAX_MESSAGE_BYTES)
    read = ctypes.c_ulong(0)
    if not kernel32.ReadFile(
        ctypes.c_void_p(handle),
        buffer,
        MAX_MESSAGE_BYTES,
        ctypes.byref(read),
        None,
    ):
        raise OSError("backend pipe read failed")
    if read.value == 0 or read.value > MAX_MESSAGE_BYTES:
        raise OSError("backend pipe message is empty or oversized")
    return buffer.raw[: read.value]


def _write_pipe_message(kernel32: Any, handle: int, payload: bytes) -> None:
    """Write one bounded message-mode frame."""
    import ctypes

    if len(payload) > MAX_MESSAGE_BYTES:
        raise OSError("backend pipe response exceeds the bounded frame")
    written = ctypes.c_ulong(0)
    if not kernel32.WriteFile(
        ctypes.c_void_p(handle),
        payload,
        len(payload),
        ctypes.byref(written),
        None,
    ):
        raise OSError("backend pipe write failed")
    if written.value != len(payload):
        raise OSError("backend pipe write was incomplete")


__all__ = ["build_backend_sddl", "serve_windows_backend"]
