"""Exact native-launch binding used by signed execution receipts.

The approval plan and the native launch are deliberately separate objects.  A
receipt is useful at the final boundary only when it is bound to the exact
command and kernel-facing launch parameters that the launcher will consume.
This module is the Python half of the canonical binding shared with the Rust
launcher.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from khaos.coding.execution.binding import ExecutionDirectoryBinding
from khaos.coding.execution.identity import ExecutableAuthority
from khaos.coding.execution.models import ResourceBudget


def execution_binding_payload(
    command: Sequence[str],
    *,
    directory_binding: ExecutionDirectoryBinding | None,
    budget: ResourceBudget | None,
    enforce_resource_limits: bool,
    preserve_directory_fds: bool,
    environment: Mapping[str, str],
    executable_authority: ExecutableAuthority | None,
) -> dict[str, Any]:
    """Build the canonical, non-secret native launch binding.

    Paths are intentionally not used when a directory descriptor binding is
    available.  Device/inode identities are the object identity the native
    launcher verifies immediately before ``exec``.  The environment is
    represented as sorted pairs so Python and Rust produce identical bytes.
    """

    rlimits = _native_rlimits(budget, enforce_resource_limits)
    root_identity = (
        directory_binding.root_identity if directory_binding is not None else None
    )
    cwd_identity = (
        directory_binding.cwd_identity if directory_binding is not None else None
    )
    return {
        "schema_version": 1,
        "command": [str(value) for value in command],
        "root_device": root_identity[0] if root_identity is not None else None,
        "root_inode": root_identity[1] if root_identity is not None else None,
        "cwd_device": cwd_identity[0] if cwd_identity is not None else None,
        "cwd_inode": cwd_identity[1] if cwd_identity is not None else None,
        "exec_digest": (
            executable_authority.executable_digest
            if executable_authority is not None
            else None
        ),
        "interpreter_digest": (
            executable_authority.interpreter_digest
            if executable_authority is not None
            else None
        ),
        "interpreter_argv0": (
            executable_authority.interpreter_argv0
            if executable_authority is not None
            else None
        ),
        "interpreter_args": list(
            executable_authority.interpreter_args
            if executable_authority is not None
            else ()
        ),
        "rlimit_fsize": rlimits["rlimit_fsize"],
        "rlimit_nofile": rlimits["rlimit_nofile"],
        "rlimit_cpu": rlimits["rlimit_cpu"],
        "rlimit_as": rlimits["rlimit_as"],
        "environment": [
            [key, value] for key, value in sorted(environment.items())
        ],
        "new_session": True,
        "preserve_directory_fds": bool(preserve_directory_fds),
    }


def execution_binding_digest(
    command: Sequence[str],
    *,
    directory_binding: ExecutionDirectoryBinding | None,
    budget: ResourceBudget | None,
    enforce_resource_limits: bool,
    preserve_directory_fds: bool,
    environment: Mapping[str, str],
    executable_authority: ExecutableAuthority | None,
) -> str:
    """Return the SHA-256 digest of the exact native launch binding."""

    payload = json.dumps(
        execution_binding_payload(
            command,
            directory_binding=directory_binding,
            budget=budget,
            enforce_resource_limits=enforce_resource_limits,
            preserve_directory_fds=preserve_directory_fds,
            environment=environment,
            executable_authority=executable_authority,
        ),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def launcher_binding_digest(
    command: Sequence[str],
    options: Mapping[str, object],
    environment: Mapping[str, str],
) -> str:
    """Recompute a receipt binding from parsed launcher arguments.

    This is used by the explicit development launcher and mirrors the Rust
    launcher's option-level recomputation.  It intentionally consumes only
    parsed values, never a Python approval object or database row.
    """

    payload = {
        "schema_version": 1,
        "command": [str(value) for value in command],
        "root_device": _optional_int(options.get("root_device")),
        "root_inode": _optional_int(options.get("root_inode")),
        "cwd_device": _optional_int(options.get("cwd_device")),
        "cwd_inode": _optional_int(options.get("cwd_inode")),
        "exec_digest": _optional_text(options.get("exec_digest")),
        "interpreter_digest": _optional_text(options.get("interpreter_digest")),
        "interpreter_argv0": _optional_text(options.get("interpreter_argv0")),
        "interpreter_args": [
            str(value) for value in options.get("interpreter_args", ())  # type: ignore[union-attr]
        ],
        "rlimit_fsize": _optional_int(options.get("rlimit_fsize")),
        "rlimit_nofile": _optional_int(options.get("rlimit_nofile")),
        "rlimit_cpu": _optional_int(options.get("rlimit_cpu")),
        "rlimit_as": _optional_int(options.get("rlimit_as")),
        # CPython on macOS materializes ``LC_CTYPE`` and
        # ``__CF_USER_TEXT_ENCODING`` while starting the explicit Python
        # development launcher, even when ``Popen(env=...)`` did not pass
        # those keys.  They are launcher-runtime implementation details, not
        # part of the environment delivered to the native boundary (the Rust
        # launcher sees the raw mapping).  Excluding only these two
        # interpreter-injected keys keeps the Python fallback digest
        # equivalent to the Rust digest while still binding every caller
        # controlled variable.
        "environment": [
            [key, value]
            for key, value in sorted(environment.items())
            if key not in {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
        ],
        "new_session": bool(options.get("new_session")),
        "preserve_directory_fds": bool(options.get("preserve_directory_fds")),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _native_rlimits(
    budget: ResourceBudget | None, enforce_resource_limits: bool
) -> dict[str, int | None]:
    if not enforce_resource_limits or budget is None:
        return {
            "rlimit_fsize": None,
            "rlimit_nofile": None,
            "rlimit_cpu": None,
            "rlimit_as": None,
        }
    return {
        "rlimit_fsize": _positive_limit(budget.file_bytes),
        "rlimit_nofile": _positive_limit(budget.open_files),
        "rlimit_cpu": max(1, int(budget.cpu_time_seconds + 0.999999)),
        "rlimit_as": (
            _positive_limit(budget.memory_bytes)
            if sys.platform != "darwin"
            else None
        ),
    }


def _positive_limit(value: int) -> int:
    normalized = int(value)
    if normalized <= 0:
        raise ValueError("native resource limits must be positive")
    return normalized


def _optional_int(value: object) -> int | None:
    return None if value is None else int(value)


def _optional_text(value: object) -> str | None:
    return None if value is None else str(value)


__all__ = [
    "execution_binding_digest",
    "execution_binding_payload",
    "launcher_binding_digest",
]
