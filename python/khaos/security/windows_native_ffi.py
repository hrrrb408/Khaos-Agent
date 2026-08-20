"""Typed Win32 bindings used by the native authority boundaries.

The authority transports are security-sensitive ctypes consumers.  Keeping
the ABI declarations in one module prevents a local ``WinDLL`` call from
silently falling back to ctypes' 32-bit defaults on 64-bit Windows and gives
the process and pipe owners one place to define terminal-handle semantics.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

HANDLE = ctypes.c_void_p
DWORD = ctypes.c_uint32
UINT = ctypes.c_uint32
BOOL = ctypes.c_int
LPVOID = ctypes.c_void_p
LPCWSTR = ctypes.c_wchar_p
LPWSTR = ctypes.POINTER(ctypes.c_wchar)

ERROR_IO_PENDING = 997
ERROR_OPERATION_ABORTED = 995
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
INFINITE = 0xFFFFFFFF

PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

INVALID_HANDLE_VALUES = frozenset({0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


class Overlapped(ctypes.Structure):
    """ABI-compatible Windows OVERLAPPED storage."""

    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
        ("hEvent", HANDLE),
    ]


class SecurityAttributes(ctypes.Structure):
    """ABI-compatible SECURITY_ATTRIBUTES storage."""

    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]


class JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", DWORD),
        ("SchedulingClass", DWORD),
    ]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount",
        "WriteOperationCount",
        "OtherOperationCount",
        "ReadTransferCount",
        "WriteTransferCount",
        "OtherTransferCount",
    )]


class JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JobObjectBasicLimitInformation),
        ("IoInfo", IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _set_signature(dll: Any, name: str, restype: Any, argtypes: list[Any]) -> None:
    function = getattr(dll, name)
    function.restype = restype
    function.argtypes = argtypes


@dataclass(frozen=True, slots=True)
class Win32Bindings:
    """The typed kernel32/advapi32 API set used by authority code."""

    kernel32: Any
    advapi32: Any

    @classmethod
    def load(cls) -> Win32Bindings:
        if os.name != "nt":
            raise OSError("Win32 authority bindings require Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
        bindings = cls(kernel32=kernel32, advapi32=advapi32)
        bindings._bind()
        return bindings

    def _bind(self) -> None:
        _set_signature(
            self.kernel32,
            "OpenProcess",
            HANDLE,
            [DWORD, BOOL, DWORD],
        )
        _set_signature(
            self.kernel32,
            "CreateNamedPipeW",
            HANDLE,
            [LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, ctypes.POINTER(SecurityAttributes)],
        )
        _set_signature(
            self.kernel32,
            "CreateEventW",
            HANDLE,
            [LPVOID, BOOL, BOOL, LPCWSTR],
        )
        _set_signature(
            self.kernel32,
            "GetNamedPipeClientProcessId",
            BOOL,
            [HANDLE, ctypes.POINTER(DWORD)],
        )
        _set_signature(self.kernel32, "CloseHandle", BOOL, [HANDLE])
        _set_signature(self.kernel32, "LocalFree", LPVOID, [LPVOID])
        _set_signature(self.kernel32, "ResetEvent", BOOL, [HANDLE])
        _set_signature(self.kernel32, "WaitForSingleObject", DWORD, [HANDLE, DWORD])
        _set_signature(self.kernel32, "CancelIoEx", BOOL, [HANDLE, ctypes.POINTER(Overlapped)])
        _set_signature(
            self.kernel32,
            "GetOverlappedResult",
            BOOL,
            [HANDLE, ctypes.POINTER(Overlapped), ctypes.POINTER(DWORD), BOOL],
        )
        _set_signature(
            self.kernel32,
            "ConnectNamedPipe",
            BOOL,
            [HANDLE, ctypes.POINTER(Overlapped)],
        )
        _set_signature(
            self.kernel32,
            "ReadFile",
            BOOL,
            [HANDLE, LPVOID, DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(Overlapped)],
        )
        _set_signature(
            self.kernel32,
            "WriteFile",
            BOOL,
            [HANDLE, LPVOID, DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(Overlapped)],
        )
        _set_signature(self.kernel32, "DisconnectNamedPipe", BOOL, [HANDLE])
        _set_signature(self.kernel32, "CreateJobObjectW", HANDLE, [LPVOID, LPCWSTR])
        _set_signature(
            self.kernel32,
            "SetInformationJobObject",
            BOOL,
            [HANDLE, ctypes.c_int, LPVOID, DWORD],
        )
        _set_signature(
            self.kernel32,
            "AssignProcessToJobObject",
            BOOL,
            [HANDLE, HANDLE],
        )
        _set_signature(
            self.kernel32,
            "TerminateJobObject",
            BOOL,
            [HANDLE, UINT],
        )
        _set_signature(
            self.advapi32,
            "OpenProcessToken",
            BOOL,
            [HANDLE, DWORD, ctypes.POINTER(HANDLE)],
        )
        _set_signature(
            self.advapi32,
            "GetTokenInformation",
            BOOL,
            [HANDLE, ctypes.c_int, LPVOID, DWORD, ctypes.POINTER(DWORD)],
        )
        _set_signature(
            self.advapi32,
            "ConvertSidToStringSidW",
            BOOL,
            [LPVOID, ctypes.POINTER(LPWSTR)],
        )
        _set_signature(
            self.advapi32,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            BOOL,
            [LPCWSTR, DWORD, ctypes.POINTER(LPVOID), ctypes.POINTER(DWORD)],
        )


@lru_cache(maxsize=1)
def get_windows_bindings() -> Win32Bindings:
    """Load and cache the process-wide typed Win32 API set."""
    return Win32Bindings.load()


def handle_value(handle: Any) -> int:
    """Return a comparable integer handle value without pointer truncation."""
    value = getattr(handle, "value", handle)
    if value is None:
        return 0
    return int(value)


def is_invalid_handle(handle: Any) -> bool:
    return handle_value(handle) in INVALID_HANDLE_VALUES


def create_termination_job() -> Any:
    """Create a kill-on-close Job Object or raise; never return best effort."""
    api = get_windows_bindings()
    job = api.kernel32.CreateJobObjectW(None, None)
    if is_invalid_handle(job):
        raise OSError("CreateJobObjectW failed")
    info = JobObjectExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not api.kernel32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        api.kernel32.CloseHandle(job)
        raise OSError("SetInformationJobObject failed")
    return job


def assign_process_to_job(job: Any, pid: int) -> None:
    """Assign a child to the job, raising if the domain is not owned."""
    api = get_windows_bindings()
    process = api.kernel32.OpenProcess(
        PROCESS_SET_QUOTA | PROCESS_TERMINATE,
        False,
        pid,
    )
    if is_invalid_handle(process):
        raise OSError("OpenProcess for Job Object assignment failed")
    try:
        if not api.kernel32.AssignProcessToJobObject(job, process):
            raise OSError("AssignProcessToJobObject failed")
    finally:
        api.kernel32.CloseHandle(process)


def terminate_job(job: Any) -> None:
    """Terminate every process in one owned job or raise."""
    api = get_windows_bindings()
    if is_invalid_handle(job) or not api.kernel32.TerminateJobObject(job, 1):
        raise OSError("TerminateJobObject failed")


def wait_for_job_terminal(job: Any, timeout_milliseconds: int) -> bool:
    """Return whether the kernel signalled that a job has no live processes."""
    if timeout_milliseconds < 0:
        raise ValueError("job terminal wait timeout cannot be negative")
    result = get_windows_bindings().kernel32.WaitForSingleObject(
        job, timeout_milliseconds
    )
    if result == WAIT_OBJECT_0:
        return True
    if result == WAIT_TIMEOUT:
        return False
    raise OSError("WaitForSingleObject(job) failed")


def close_handle(handle: Any) -> None:
    """Close one typed handle; callers decide whether terminal proof exists."""
    if handle is None or is_invalid_handle(handle):
        return
    get_windows_bindings().kernel32.CloseHandle(handle)


__all__ = [
    "ERROR_IO_PENDING",
    "ERROR_OPERATION_ABORTED",
    "INFINITE",
    "Overlapped",
    "SecurityAttributes",
    "Win32Bindings",
    "assign_process_to_job",
    "close_handle",
    "create_termination_job",
    "get_windows_bindings",
    "handle_value",
    "is_invalid_handle",
    "terminate_job",
    "wait_for_job_terminal",
]
