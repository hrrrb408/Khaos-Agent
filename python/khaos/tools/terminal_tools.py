"""Terminal and background process tools."""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.permissions.engine import split_command_segments
from khaos.security.command_guard import CommandGuard


READ_ONLY_COMMANDS = {
    "cat",
    "date",
    "echo",
    "grep",
    "head",
    "ls",
    "pwd",
    "rg",
    "tail",
    "test",
    "true",
    "wc",
    "which",
}

MUTATING_COMMANDS = {
    "chmod",
    "chown",
    "cp",
    "curl",
    "dd",
    "git",
    "kill",
    "mkdir",
    "mv",
    "npm",
    "pip",
    "python",
    "python3",
    "rm",
    "rmdir",
    "tee",
    "touch",
}

DANGEROUS_PATTERNS = {"rm -rf /", "rm -fr /", ":(){", "mkfs", "diskutil erase"}


@dataclass
class ManagedProcess:
    """Background process state."""

    id: str
    command: str
    process: asyncio.subprocess.Process
    stdout: str = ""
    stderr: str = ""
    _collector: asyncio.Task | None = field(default=None, repr=False)


_PROCESSES: dict[str, ManagedProcess] = {}
_SECURITY_ENABLED = True
_COMMAND_GUARD = CommandGuard()

# Environment-variable prefixes that are safe to pass through to spawned
# subprocesses. Everything else (API keys, tokens, etc.) is stripped so a
# command run via the terminal tool cannot exfiltrate credentials from Khaos's
# own environment. This only affects subprocesses spawned by ``terminal()`` —
# Khaos itself still sees its full environment.
SAFE_ENV_PREFIXES = (
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_",  # locale variants (LC_ALL, LC_CTYPE, …)
    "TERM",
    "SHELL",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "TEMP",
    "TMP",
)

# Explicit allowlist of non-prefixed vars that are safe to forward.
SAFE_ENV_EXACT = frozenset({"CI", "GITHUB_ACTIONS", "DOCKER_CONTAINER"})


def _build_safe_env() -> dict[str, str]:
    """构建安全的环境变量字典，移除可能包含密钥的变量。

    Only variables whose name starts with a :data:`SAFE_ENV_PREFIXES` entry or
    appears in :data:`SAFE_ENV_EXACT` are forwarded to the subprocess. This
    prevents a model-run command from reading ``OPENAI_API_KEY`` and similar
    credentials out of Khaos's own environment.
    """
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in SAFE_ENV_EXACT or any(key.startswith(prefix) for prefix in SAFE_ENV_PREFIXES):
            env[key] = value
    return env


def enable_security(enabled: bool = True) -> None:
    """启用/禁用安全检查（测试用）。"""
    global _SECURITY_ENABLED
    _SECURITY_ENABLED = enabled


async def terminal(
    command: str,
    cwd: str = ".",
    background: bool = False,
    timeout: int = 30,
    execution_service=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    """Run a terminal command via ExecutionService.

    Coding Agent reachable handler: fail closed when ExecutionService is
    missing. Direct subprocess fallback is removed — no OS-sandbox auto-fallback.
    """
    command_check = check_command_safety(command)
    if not command_check["safe"]:
        return {
            "ok": False,
            "error": f"Command blocked: {command_check['reason']}",
            "risk_level": command_check["risk_level"],
        }
    safety = evaluate_command_safety(command)
    if safety["blocked"]:
        return {
            "ok": False,
            "error": f"Command blocked: {safety['reason']}",
            "risk_level": "dangerous",
        }
    if execution_service is None:
        return {
            "ok": False,
            "error": "ExecutionService unavailable: Coding mode requires sandboxed execution; direct subprocess fallback is disabled",
            "risk_level": "blocked",
        }
    workdir = str(Path(cwd).expanduser().resolve())
    parts = shlex.split(command)
    from khaos.coding.execution import ExecutionRequest, ResourceBudget
    result = await execution_service.execute(
        ExecutionRequest(tuple(parts), Path(workdir), budget=ResourceBudget(timeout_seconds=timeout), task_id=task_id, workspace_id=workspace_id, access_mode="read-only" if safety["read_only"] else "workspace-write")
    )
    return {"command": command, "returncode": result.return_code, "stdout": result.stdout, "stderr": result.stderr, "status": result.status, "safety": safety}


def check_command_safety(command: str) -> dict[str, Any]:
    """检查命令安全性。在 terminal() 执行前调用。"""
    if not _SECURITY_ENABLED:
        return {"safe": True, "risk_level": "safe", "reason": "security disabled"}
    result = _COMMAND_GUARD.check(command)
    return {
        "safe": result.safe,
        "risk_level": result.risk_level,
        "reason": result.reason,
        "matched_pattern": result.matched_pattern,
    }


async def process(action: str, id: str, timeout: int = 30) -> dict[str, Any]:
    """Poll, wait, kill, or read logs for a background process."""
    managed = _PROCESSES.get(id)
    if managed is None:
        raise KeyError(f"unknown process: {id}")
    if action == "poll":
        return {
            "id": id,
            "running": managed.process.returncode is None,
            "returncode": managed.process.returncode,
        }
    if action == "wait":
        try:
            await asyncio.wait_for(managed.process.wait(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"process wait timed out after {timeout}s") from exc
        if managed._collector is not None:
            await managed._collector
        return {
            "id": id,
            "running": False,
            "returncode": managed.process.returncode,
            "stdout": managed.stdout,
            "stderr": managed.stderr,
        }
    if action == "kill":
        if managed.process.returncode is None:
            managed.process.send_signal(signal.SIGTERM)
            await managed.process.wait()
        if managed._collector is not None:
            await managed._collector
        return {"id": id, "running": False, "returncode": managed.process.returncode}
    if action == "log":
        return {
            "id": id,
            "stdout": managed.stdout,
            "stderr": managed.stderr,
            "running": managed.process.returncode is None,
        }
    raise ValueError(f"unsupported process action: {action}")


def evaluate_command_safety(command: str) -> dict[str, Any]:
    """Evaluate shell segments for read-only, mutating, and blocked commands."""
    lowered = command.strip().lower()
    for pattern in DANGEROUS_PATTERNS:
        if pattern in lowered:
            return {
                "segments": split_command_segments(command),
                "read_only": False,
                "requires_confirmation": True,
                "blocked": True,
                "reason": pattern,
            }

    segments = split_command_segments(command)
    bases: list[str] = []
    read_only = True
    for segment in segments:
        try:
            parts = shlex.split(segment)
        except ValueError:
            read_only = False
            bases.append(segment)
            continue
        if not parts:
            continue
        base = Path(parts[0]).name
        bases.append(base)
        if base in MUTATING_COMMANDS or base not in READ_ONLY_COMMANDS:
            read_only = False
        if _segment_has_redirection(segment):
            read_only = False

    return {
        "segments": segments,
        "base_commands": bases,
        "read_only": read_only,
        "requires_confirmation": not read_only,
        "blocked": False,
        "reason": "read-only" if read_only else "mutating or unknown command",
    }


def is_read_only_command(command: str) -> bool:
    """Return true when every command segment is read-only."""
    safety = evaluate_command_safety(command)
    return bool(safety["read_only"] and not safety["blocked"])


async def _collect_output(managed: ManagedProcess) -> None:
    stdout, stderr = await managed.process.communicate()
    managed.stdout = stdout.decode("utf-8", errors="replace")
    managed.stderr = stderr.decode("utf-8", errors="replace")


def _segment_has_redirection(segment: str) -> bool:
    in_single = False
    in_double = False
    for char in segment:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char in {"<", ">"} and not in_single and not in_double:
            return True
    return False
