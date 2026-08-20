"""Windows Named-Pipe backend for the authority control plane.

The native Service-SID frontend
(``rust/khaos-core/src/bin/khaos-authorityd-windows.rs``) is the platform
TCB that authenticates the Agent peer.  It forwards each bounded request to
the backend pipe named by ``KHAOS_AUTHORITYD_BACKEND_PIPE``.  This module is
that backend: it serves a message-mode Named Pipe whose DACL grants access
only to ``NT AUTHORITY\\SYSTEM`` and the configured authority Service SID,
validates the connecting client's process-token identity on every
connection, and dispatches to the same :class:`AuthorityDaemon` control
plane used on Linux.

There is no agent-reachable path: the pipe DACL rejects the Agent SID before
a single byte is read, and the per-connection identity check fails closed.

Every pipe operation runs overlapped under the same
``KHAOS_AUTHORITYD_CONNECTION_TIMEOUT`` budget the Unix transport enforces,
so a stalled-but-trusted frontend cannot hold the backend (or its shutdown)
indefinitely.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import struct
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from khaos.security.authorityd import AuthorityDaemon, _dispatch
from khaos.security.authorityd_protocol import (
    MAX_MESSAGE_BYTES,
    AuthorityControlPlaneError,
)
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    read_contract_from_environment,
)
from khaos.security.windows_native_ffi import (
    ERROR_OPERATION_ABORTED,
    LPWSTR,
    Overlapped,
    SecurityAttributes,
    get_windows_bindings,
    is_invalid_handle,
)

logger = logging.getLogger(__name__)


class _ActiveOverlappedIOError(OSError):
    """The kernel has not proven an overlapped operation is terminal."""

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 0x00000217
ERROR_BROKEN_PIPE = 0x00000109
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
TOKEN_QUERY = 0x0008
TokenUser = 1
TokenGroups = 2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_LOCAL_SYSTEM_SID = "S-1-5-18"


def _last_error(ctypes_module: Any) -> int:
    """Read Win32 last-error through a typed, fail-closed module boundary."""
    getter = getattr(ctypes_module, "get_last_error", None)
    if not callable(getter):
        raise OSError("ctypes Win32 last-error API is unavailable")
    value = getter()
    if not isinstance(value, int):
        raise OSError("ctypes Win32 last-error value is malformed")
    return value


# How long a blocking ConnectNamedPipe wait may hold before the shutdown
# flag is re-checked.  Bound the wake-up latency of daemon close, never the
# total client wait (a server legitimately waits for clients).
_CONNECT_POLL_MILLISECONDS = 1000

_SDDL_TEMPLATE = "D:P(A;;GA;;;SY)(A;;GA;;;{service_sid})"

_INVALID_HANDLES = (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


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
    """Return the process-wide typed kernel32 binding."""
    return get_windows_bindings().kernel32


def _advapi32() -> Any:
    """Return the process-wide typed advapi32 binding."""
    return get_windows_bindings().advapi32


def _is_invalid_handle(handle: Any) -> bool:
    return not handle or is_invalid_handle(handle)


def _connection_timeout_seconds() -> float:
    """Mirror the Unix transport's connection-timeout contract."""
    try:
        timeout = float(os.environ.get("KHAOS_AUTHORITYD_CONNECTION_TIMEOUT", "5"))
    except ValueError as exc:
        raise AuthorityControlPlaneError(
            "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT must be numeric"
        ) from exc
    if not 0 < timeout <= 60:
        raise AuthorityControlPlaneError(
            "KHAOS_AUTHORITYD_CONNECTION_TIMEOUT is outside the safe bound"
        )
    return timeout


def _parse_token_user_sid(raw: bytes) -> int:
    """Return the SID pointer from a TOKEN_USER buffer (SID* at offset 0)."""
    if len(raw) < 8:
        raise IdentityIsolationError("backend pipe client SID is malformed")
    (sid_ptr,) = struct.unpack_from("<Q", raw, 0)
    if not sid_ptr:
        raise IdentityIsolationError("backend pipe client SID is malformed")
    return sid_ptr


def _parse_token_group_sids(
    raw: bytes, *, dereference: Callable[[int], str]
) -> list[str]:
    """Return every group SID string from a TOKEN_GROUPS buffer.

    TOKEN_GROUPS (x64): DWORD GroupCount; SID_AND_ATTRIBUTES Groups[] where
    each entry is ``SID* Sid`` (8 bytes) + ``DWORD Attributes`` + padding,
    i.e. 16 bytes per entry starting at offset 8.
    """
    if len(raw) < 8:
        raise IdentityIsolationError("backend pipe client groups are malformed")
    (count,) = struct.unpack_from("<I", raw, 0)
    capacity = (len(raw) - 8) // 16
    if count > capacity:
        # A kernel-produced buffer can never overflow its own extent.
        raise IdentityIsolationError("backend pipe client groups are malformed")
    sids: list[str] = []
    for index in range(count):
        (sid_ptr,) = struct.unpack_from("<Q", raw, 8 + index * 16)
        if not sid_ptr:
            raise IdentityIsolationError("backend pipe client group SID is malformed")
        sids.append(dereference(sid_ptr))
    return sids


def _sid_to_string(advapi32: Any, kernel32: Any, sid_ptr: int) -> str:
    """Convert a kernel-owned SID pointer with the exact Win32 ABI type."""
    text = LPWSTR()
    if not advapi32.ConvertSidToStringSidW(
        ctypes.c_void_p(sid_ptr), ctypes.byref(text)
    ):
        raise IdentityIsolationError("backend pipe client SID is malformed")
    if not text:
        raise IdentityIsolationError("backend pipe client SID is malformed")
    try:
        value = ctypes.wstring_at(text)
        if not value:
            raise IdentityIsolationError("backend pipe client SID is malformed")
        return value
    finally:
        # ConvertSidToStringSidW allocates the returned string with the
        # process heap API paired with LocalFree; release it only after the
        # Python copy has been made.
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _peer_is_trusted(
    user_sid: str, group_sids: list[str], service_sid: str
) -> bool:
    """A trusted peer is the authority service itself or LocalSystem.

    A Windows Service SID (``S-1-5-80-...``) is a *group* SID in the process
    token, not the token user: the user SID stays the service's logon account
    (e.g. LocalSystem).  Checking TokenUser alone left the Service-SID half
    of the trust set dead code; the decision now covers both placements.
    """
    return (
        user_sid == service_sid
        or user_sid == _LOCAL_SYSTEM_SID
        or service_sid in group_sids
    )


def _client_identity(kernel32: Any, advapi32: Any, pipe_handle: int) -> tuple[str, list[str]]:
    """Return (token-user SID, token-group SIDs); fail closed on any error."""
    client_pid = ctypes.c_ulong(0)
    if not kernel32.GetNamedPipeClientProcessId(
        ctypes.c_void_p(pipe_handle), ctypes.byref(client_pid)
    ):
        raise IdentityIsolationError("backend pipe client PID is unavailable")
    process = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, client_pid.value
    )
    if _is_invalid_handle(process):
        raise IdentityIsolationError("backend pipe client process is unavailable")
    try:
        token = ctypes.c_void_p()
        # OpenProcessToken is exported by advapi32, not kernel32: calling it
        # on the kernel32 binding raised AttributeError and killed the
        # backend loop on the first connection.
        if not advapi32.OpenProcessToken(
            ctypes.c_void_p(process), TOKEN_QUERY, ctypes.byref(token)
        ):
            raise IdentityIsolationError("backend pipe client token is unavailable")
        try:

            def _query(class_id: int) -> bytes:
                needed = ctypes.c_ulong(0)
                advapi32.GetTokenInformation(
                    token, class_id, None, 0, ctypes.byref(needed)
                )
                if needed.value == 0:
                    raise IdentityIsolationError(
                        "backend pipe client token information is unavailable"
                    )
                buffer = ctypes.create_string_buffer(needed.value)
                if not advapi32.GetTokenInformation(
                    token, class_id, buffer, needed.value, ctypes.byref(needed)
                ):
                    raise IdentityIsolationError(
                        "backend pipe client token information is unavailable"
                    )
                return buffer.raw

            user_sid = _sid_to_string(
                advapi32,
                kernel32,
                _parse_token_user_sid(_query(TokenUser)),
            )
            group_sids = _parse_token_group_sids(
                _query(TokenGroups),
                dereference=lambda sid_ptr: _sid_to_string(
                    advapi32, kernel32, sid_ptr
                ),
            )
            return user_sid, group_sids
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(process))


class _OverlappedIOWindow:
    """One overlapped pipe operation with a hard deadline.

    On timeout the operation is cancelled (``CancelIoEx``) and the
    cancellation is reaped before the handle is released, so no overlapped
    I/O can complete against a recycled handle later.
    """

    def __init__(self, kernel32: Any, handle: int) -> None:
        import ctypes

        self._kernel32 = kernel32
        self._handle = handle
        self._ctypes = ctypes
        event = kernel32.CreateEventW(None, True, False, None)
        if _is_invalid_handle(event):
            raise OSError("backend pipe event creation failed")

        self._event = event
        self._overlapped = Overlapped()
        self._overlapped.hEvent = ctypes.c_void_p(event)
        self._terminal = False

    def _start(self, starter: Callable[[Any], int]) -> tuple[bool, int]:
        ctypes = self._ctypes
        self._kernel32.ResetEvent(ctypes.c_void_p(self._event))
        started = starter(ctypes.byref(self._overlapped))
        return bool(started), _last_error(ctypes)

    def _cancel_and_reap(self, *, reason: str) -> None:
        """Cancel and prove terminal completion before releasing OVERLAPPED."""
        ctypes = self._ctypes
        self._kernel32.CancelIoEx(
            ctypes.c_void_p(self._handle), ctypes.byref(self._overlapped)
        )
        wait = self._kernel32.WaitForSingleObject(
            ctypes.c_void_p(self._event), 5000
        )
        if wait != WAIT_OBJECT_0:
            raise OSError(f"{reason}: cancelled I/O did not signal completion")
        transferred = ctypes.c_ulong(0)
        if self._kernel32.GetOverlappedResult(
            ctypes.c_void_p(self._handle),
            ctypes.byref(self._overlapped),
            ctypes.byref(transferred),
            False,
        ):
            self._terminal = True
            return
        error = _last_error(ctypes)
        if error != ERROR_OPERATION_ABORTED:
            raise OSError(
                error,
                f"{reason}: cancelled I/O completion is not terminal",
            )
        self._terminal = True

    def _wait(self, deadline_seconds: float) -> bool:
        ctypes = self._ctypes
        wait = self._kernel32.WaitForSingleObject(
            ctypes.c_void_p(self._event), max(1, int(deadline_seconds * 1000))
        )
        if wait == WAIT_OBJECT_0:
            return True
        if wait == WAIT_TIMEOUT:
            self._cancel_and_reap(reason="overlapped I/O deadline exceeded")
            return False
        raise OSError("overlapped I/O wait failed")

    def run(
        self, starter: Callable[[Any], int], *, deadline_seconds: float
    ) -> int:
        """Run one overlapped operation; return bytes transferred, 0 on miss."""
        ctypes = self._ctypes
        started, last_error = self._start(starter)
        if started:
            transferred = ctypes.c_ulong(0)
            if not self._kernel32.GetOverlappedResult(
                ctypes.c_void_p(self._handle),
                ctypes.byref(self._overlapped),
                ctypes.byref(transferred),
                False,
            ):
                self._terminal = True
                raise OSError("synchronous overlapped I/O completion failed")
            self._terminal = True
            return transferred.value
        if last_error != ERROR_IO_PENDING:
            self._terminal = True
            return 0
        if not self._wait(deadline_seconds):
            return 0
        transferred = ctypes.c_ulong(0)
        if not self._kernel32.GetOverlappedResult(
            ctypes.c_void_p(self._handle),
            ctypes.byref(self._overlapped),
            ctypes.byref(transferred),
            False,
        ):
            self._terminal = True
            raise OSError("overlapped I/O completion failed")
        self._terminal = True
        return transferred.value

    def poll_started(self, starter: Callable[[Any], int]) -> tuple[bool, int]:
        started, last_error = self._start(starter)
        if started or last_error != ERROR_IO_PENDING:
            self._terminal = True
        return started, last_error

    def wait_or_shutdown(self, *, shutdown: Callable[[], bool]) -> bool:
        """Wait for the operation in bounded slices, honoring shutdown."""
        ctypes = self._ctypes
        while True:
            wait = self._kernel32.WaitForSingleObject(
                ctypes.c_void_p(self._event), _CONNECT_POLL_MILLISECONDS
            )
            if wait == WAIT_OBJECT_0:
                # A signalled connect event still needs the kernel completion
                # query before the OVERLAPPED storage can be released.
                self.transferred()
                return True
            if wait != WAIT_TIMEOUT:
                return False
            if shutdown():
                self._cancel_and_reap(reason="overlapped connect shutdown")
                return False

    def transferred(self) -> int:
        ctypes = self._ctypes
        transferred = ctypes.c_ulong(0)
        if not self._kernel32.GetOverlappedResult(
            ctypes.c_void_p(self._handle),
            ctypes.byref(self._overlapped),
            ctypes.byref(transferred),
            False,
        ):
            self._terminal = True
            raise OSError("overlapped connect completion failed")
        self._terminal = True
        return transferred.value

    def close(self) -> None:
        if not self._terminal:
            raise _ActiveOverlappedIOError(
                "refusing to release an active overlapped operation"
            )
        self._kernel32.CloseHandle(self._ctypes.c_void_p(self._event))


def serve_windows_backend(daemon: AuthorityDaemon, *, production: bool = True) -> None:
    """Serve the authority backend Named Pipe with per-connection checks.

    This transport is Windows-only.  Each accepted connection is validated
    against the configured authority Service SID before any request bytes
    are read, and the request/response framing is strictly one bounded
    message per connection under a hard I/O deadline.
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
    connection_timeout = _connection_timeout_seconds()
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    sddl = ctypes.c_wchar_p(build_backend_sddl(service_sid))
    security_attributes = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(security_attributes), None
    ):
        raise IdentityIsolationError("backend pipe DACL construction failed")

    attributes = SecurityAttributes(
        ctypes.sizeof(SecurityAttributes), security_attributes, 0
    )
    pipe_w = ctypes.c_wchar_p(pipe_name)
    try:
        with ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="khaos-authorityd-win"
        ) as dispatch_pool:
            while not daemon._closed:
                handle = kernel32.CreateNamedPipeW(
                    pipe_w,
                    PIPE_ACCESS_DUPLEX
                    | FILE_FLAG_FIRST_PIPE_INSTANCE
                    | FILE_FLAG_OVERLAPPED,
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
                if _is_invalid_handle(handle):
                    raise IdentityIsolationError("backend CreateNamedPipeW failed")
                safe_to_release_handle = False
                try:
                    connect: _OverlappedIOWindow | None = None
                    try:
                        connect = _OverlappedIOWindow(kernel32, handle)
                        started, last_error = connect.poll_started(
                            lambda overlapped, pipe_handle=handle: kernel32.ConnectNamedPipe(
                                ctypes.c_void_p(pipe_handle), overlapped
                            )
                        )
                        if not started and last_error == ERROR_PIPE_CONNECTED:
                            pass  # client won the create/connect race
                        elif not started and last_error != ERROR_IO_PENDING:
                            continue
                        elif not started and connect.wait_or_shutdown(
                            shutdown=lambda: daemon._closed
                        ):
                            pass
                        elif not started:
                            continue
                        _serve_one_connection(
                            daemon,
                            kernel32,
                            advapi32,
                            handle,
                            service_sid=service_sid,
                            connection_timeout=connection_timeout,
                            dispatch_pool=dispatch_pool,
                        )
                    finally:
                        if connect is not None:
                            connect.close()
                            safe_to_release_handle = True
                except _ActiveOverlappedIOError:
                    # Closing this pipe would let a still-running operation
                    # target a recycled handle.  Retain the handle and fail
                    # the service so its process supervisor can terminate the
                    # whole authority domain.
                    safe_to_release_handle = False
                    logger.critical(
                        "retaining backend pipe after un-reaped overlapped I/O"
                    )
                    raise
                finally:
                    if safe_to_release_handle:
                        kernel32.DisconnectNamedPipe(ctypes.c_void_p(handle))
                        kernel32.CloseHandle(ctypes.c_void_p(handle))
    finally:
        kernel32.LocalFree(security_attributes)


def _serve_one_connection(
    daemon: AuthorityDaemon,
    kernel32: Any,
    advapi32: Any,
    handle: int,
    *,
    service_sid: str,
    connection_timeout: float,
    dispatch_pool: ThreadPoolExecutor,
) -> None:
    """Identity check, bounded read, deadline-bounded dispatch, bounded write."""
    try:
        user_sid, group_sids = _client_identity(kernel32, advapi32, handle)
        if not _peer_is_trusted(user_sid, group_sids, service_sid):
            raise IdentityIsolationError(
                "backend pipe peer SID is not a trusted authority identity"
            )
        read_window = _OverlappedIOWindow(kernel32, handle)
        try:
            buffer = _new_buffer(MAX_MESSAGE_BYTES)
            transferred = read_window.run(
                lambda overlapped: kernel32.ReadFile(
                    ctypes.c_void_p(handle),
                    buffer,
                    MAX_MESSAGE_BYTES,
                    None,
                    overlapped,
                ),
                deadline_seconds=connection_timeout,
            )
        finally:
            read_window.close()
        if transferred == 0 or transferred > MAX_MESSAGE_BYTES:
            raise OSError("backend pipe read timed out or failed")
        request = buffer.raw[:transferred]
        try:
            message = json.loads(request.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("backend pipe request is not valid JSON") from exc
        try:
            response = dispatch_pool.submit(_dispatch, daemon, message).result(
                timeout=connection_timeout
            )
        except FutureTimeoutError:
            response = {"ok": False, "error": "backend dispatch deadline exceeded"}
        body = (
            json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        if len(body) > MAX_MESSAGE_BYTES:
            raise OSError("backend pipe response exceeds the bounded frame")
        write_window = _OverlappedIOWindow(kernel32, handle)
        try:
            written = write_window.run(
                lambda overlapped: kernel32.WriteFile(
                    ctypes.c_void_p(handle), body, len(body), None, overlapped
                ),
                deadline_seconds=connection_timeout,
            )
        finally:
            write_window.close()
        if written != len(body):
            raise OSError("backend pipe write timed out or was incomplete")
    except _ActiveOverlappedIOError:
        raise
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
            if len(failure) + 1 <= MAX_MESSAGE_BYTES:
                write_window = _OverlappedIOWindow(kernel32, handle)
                try:
                    write_window.run(
                        lambda overlapped: kernel32.WriteFile(
                            ctypes.c_void_p(handle),
                            failure + b"\n",
                            len(failure) + 1,
                            None,
                            overlapped,
                        ),
                        deadline_seconds=connection_timeout,
                    )
                finally:
                    write_window.close()
        except _ActiveOverlappedIOError:
            raise
        except (OSError, ValueError):
            pass


def _new_buffer(size: int) -> Any:
    return ctypes.create_string_buffer(size)


__all__ = ["build_backend_sddl", "serve_windows_backend"]
