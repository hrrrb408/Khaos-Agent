"""Win32 ACL checks for production trust material.

POSIX ``st_uid``/mode bits are not meaningful Windows authority evidence.
Production callers use this module before and after opening a catalog or key:
the configured trust root and owner SIDs are deployment inputs, while every
allowed ACE that grants write-like access must belong to the same explicit
trusted set.  The module deliberately has no best-effort fallback; missing
Win32 APIs or incomplete deployment configuration is an admission failure.
"""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path
from typing import Any


class WindowsTrustError(PermissionError):
    """The Windows trust-material ACL contract is unavailable or unsafe."""


_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_SECURITY_INFORMATION = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
_ACL_SIZE_INFORMATION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_FILE_WRITE_DATA = 0x0002
_FILE_APPEND_DATA = 0x0004
_FILE_WRITE_EA = 0x0010
_FILE_DELETE_CHILD = 0x0040
_DELETE = 0x00010000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_WRITE = 0x40000000
_GENERIC_ALL = 0x10000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WRITE_MASK = (
    _FILE_WRITE_DATA
    | _FILE_APPEND_DATA
    | _FILE_WRITE_EA
    | _FILE_DELETE_CHILD
    | _DELETE
    | _WRITE_DAC
    | _WRITE_OWNER
    | _GENERIC_WRITE
    | _GENERIC_ALL
)
_SYSTEM_SID = "S-1-5-18"
_BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("ace_type", ctypes.c_ubyte),
        ("ace_flags", ctypes.c_ubyte),
        ("ace_size", ctypes.c_ushort),
    ]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("ace_count", ctypes.c_uint32),
        ("acl_bytes_in_use", ctypes.c_uint32),
        ("acl_bytes_free", ctypes.c_uint32),
    ]


def _required_text(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or "\x00" in value:
        raise WindowsTrustError(f"{name} is required for Windows trust material")
    return value


def _sid_set(name: str) -> set[str]:
    raw = _required_text(name)
    values = {item.strip() for item in raw.split(",") if item.strip()}
    if not values or any(
        not value.startswith("S-1-") or len(value) > 184 for value in values
    ):
        raise WindowsTrustError(f"{name} contains an invalid SID")
    return values


def _trusted_configuration(path: Path) -> tuple[Path, set[str], set[str]]:
    """Resolve the explicit deployment ACL contract without following paths."""
    root_value = _required_text("KHAOS_WINDOWS_TRUST_ROOT")
    root = Path(root_value)
    candidate = Path(path).expanduser()
    if not root.is_absolute() or not candidate.is_absolute():
        raise WindowsTrustError("Windows trust paths and root must be absolute")
    if any(part == ".." for part in root.parts + candidate.parts):
        raise WindowsTrustError("Windows trust path contains parent traversal")
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise WindowsTrustError(
            "Windows trust material must stay under the configured trust root"
        ) from exc
    if any(part in {"", "."} for part in relative.parts):
        raise WindowsTrustError("Windows trust path is not canonical")
    owner_sids = _sid_set("KHAOS_WINDOWS_TRUSTED_OWNER_SIDS")
    allowed_write_sids = owner_sids | {
        _SYSTEM_SID,
        _BUILTIN_ADMINISTRATORS_SID,
    }
    for environment_name in (
        "KHAOS_AUTHORITYD_SERVICE_SID",
        "KHAOS_AGENT_SID",
        "KHAOS_WINDOWS_TRUSTED_ACL_SIDS",
    ):
        raw = os.environ.get(environment_name, "").strip()
        if raw:
            allowed_write_sids.update(
                item.strip() for item in raw.split(",") if item.strip()
            )
    if any(
        not value.startswith("S-1-") or len(value) > 184
        for value in allowed_write_sids
    ):
        raise WindowsTrustError("Windows trust ACL contains an invalid SID")
    return root, owner_sids, allowed_write_sids


def _windows_path_components(path: Path) -> tuple[Path, ...]:
    """Return every lexical component from the volume root to ``path``."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise WindowsTrustError("Windows trust paths must be absolute")
    current = Path(candidate.anchor)
    components = [current]
    for part in candidate.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def reject_windows_reparse_points(path: Path) -> None:
    """Reject symlinks and other reparse points in a trust-material path."""
    if os.name != "nt":
        return
    for component in _windows_path_components(path):
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise WindowsTrustError(
                f"Windows trust path is unavailable: {component}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or bool(
            getattr(metadata, "st_file_attributes", 0)
            & _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise WindowsTrustError(
                "Windows trust path contains a symlink or reparse point"
            )


def _bindings() -> tuple[Any, Any]:
    if os.name != "nt":
        raise WindowsTrustError("Win32 trust validation requires Windows")
    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        raise WindowsTrustError("Win32 trust APIs are unavailable")
    advapi32 = win_dll("advapi32", use_last_error=True)
    kernel32 = win_dll("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = ctypes.c_uint32
    advapi32.GetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAclInformation.restype = ctypes.c_int
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    advapi32.GetAce.restype = ctypes.c_int
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    return advapi32, kernel32


def _last_error(function_name: str) -> WindowsTrustError:
    error = ctypes.get_last_error()
    return WindowsTrustError(f"{function_name} failed with Win32 error {error}")


def _sid_text(advapi32: Any, kernel32: Any, sid: ctypes.c_void_p) -> str:
    if not sid or not sid.value:
        raise WindowsTrustError("Windows trust descriptor has no SID")
    text = ctypes.c_wchar_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise _last_error("ConvertSidToStringSidW")
    try:
        value = text.value or ""
    finally:
        kernel32.LocalFree(text)
    if not value:
        raise WindowsTrustError("Windows trust descriptor has an empty SID")
    return value


def _check_descriptor(
    owner: ctypes.c_void_p,
    dacl: ctypes.c_void_p,
    *,
    owner_sids: set[str],
    allowed_write_sids: set[str],
    advapi32: Any,
    kernel32: Any,
) -> None:
    owner_text = _sid_text(advapi32, kernel32, owner)
    if owner_text not in owner_sids:
        raise WindowsTrustError(
            "Windows trust material owner is not in the deployment allowlist"
        )
    if not dacl or not dacl.value:
        raise WindowsTrustError("Windows trust material has no protected DACL")
    acl_info = _AclSizeInformation()
    if not advapi32.GetAclInformation(
        dacl,
        ctypes.byref(acl_info),
        ctypes.sizeof(acl_info),
        _ACL_SIZE_INFORMATION,
    ):
        raise _last_error("GetAclInformation")
    if acl_info.ace_count > 4096 or acl_info.acl_bytes_in_use > 1024 * 1024:
        raise WindowsTrustError("Windows trust ACL exceeds its bounded size")
    for index in range(acl_info.ace_count):
        ace = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
            raise _last_error("GetAce")
        header = _AceHeader.from_address(ace.value)
        if header.ace_size < 8 or header.ace_size > acl_info.acl_bytes_in_use:
            raise WindowsTrustError("Windows trust ACL contains a malformed ACE")
        if header.ace_type == _ACCESS_DENIED_ACE_TYPE:
            continue
        # Only the fixed ACCESS_ALLOWED_ACE shape is accepted.  Object ACEs
        # and callback ACEs are rejected rather than guessed at, because an
        # unparsed callback could carry an effective write grant.
        if header.ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise WindowsTrustError("Windows trust ACL contains an unsupported ACE")
        mask = ctypes.c_uint32.from_address(ace.value + 4).value
        sid = ctypes.c_void_p(ace.value + 8)
        sid_text = _sid_text(advapi32, kernel32, sid)
        if mask & _WRITE_MASK and sid_text not in allowed_write_sids:
            raise WindowsTrustError(
                "Windows trust ACL grants write access to an untrusted SID"
            )


def _query_named(path: Path, *, advapi32: Any) -> tuple[Any, ...]:
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(security_descriptor),
    )
    if result != 0 or not security_descriptor.value:
        raise WindowsTrustError(
            f"GetNamedSecurityInfoW failed for trusted path {path}: {result}"
        )
    return security_descriptor, owner, dacl


def _query_handle(fd: int, *, advapi32: Any) -> tuple[Any, ...]:
    try:
        import msvcrt

        handle_value = msvcrt.get_osfhandle(fd)
    except (ImportError, OSError, ValueError) as exc:
        raise WindowsTrustError("Windows trust descriptor handle is unavailable") from exc
    if handle_value in {0, -1}:
        raise WindowsTrustError("Windows trust descriptor handle is invalid")
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        ctypes.c_void_p(handle_value),
        _SE_FILE_OBJECT,
        _SECURITY_INFORMATION,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(security_descriptor),
    )
    if result != 0 or not security_descriptor.value:
        raise WindowsTrustError(
            f"GetSecurityInfo failed for trusted descriptor: {result}"
        )
    return security_descriptor, owner, dacl


def _release(kernel32: Any, security_descriptor: ctypes.c_void_p) -> None:
    if security_descriptor.value and kernel32.LocalFree(security_descriptor) not in {
        None,
        0,
    }:
        raise WindowsTrustError("LocalFree failed for Windows trust descriptor")


def validate_windows_trusted_path(path: Path, *, kind: str) -> None:
    """Validate the configured Windows trust root and every path component."""
    if os.name != "nt":
        return
    if kind not in {"catalog", "key", "public-key"}:
        raise WindowsTrustError("Windows trust material kind is invalid")
    root, owner_sids, allowed_write_sids = _trusted_configuration(path)
    reject_windows_reparse_points(path)
    advapi32, kernel32 = _bindings()
    candidate = Path(path).expanduser()
    relative = candidate.relative_to(root)
    current = root
    components = (root, *(current / part for part in relative.parts))
    for item in components:
        security_descriptor, owner, dacl = _query_named(item, advapi32=advapi32)
        try:
            _check_descriptor(
                owner,
                dacl,
                owner_sids=owner_sids,
                allowed_write_sids=allowed_write_sids,
                advapi32=advapi32,
                kernel32=kernel32,
            )
        finally:
            _release(kernel32, security_descriptor)


def validate_windows_trusted_descriptor(fd: int, *, path: Path, kind: str) -> None:
    """Recheck the final opened object's ACL through its kernel handle."""
    if os.name != "nt":
        return
    _root, owner_sids, allowed_write_sids = _trusted_configuration(path)
    advapi32, kernel32 = _bindings()
    security_descriptor, owner, dacl = _query_handle(fd, advapi32=advapi32)
    try:
        _check_descriptor(
            owner,
            dacl,
            owner_sids=owner_sids,
            allowed_write_sids=allowed_write_sids,
            advapi32=advapi32,
            kernel32=kernel32,
        )
    finally:
        _release(kernel32, security_descriptor)


__all__ = [
    "WindowsTrustError",
    "reject_windows_reparse_points",
    "validate_windows_trusted_descriptor",
    "validate_windows_trusted_path",
]
