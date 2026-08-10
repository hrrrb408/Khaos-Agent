"""Terminal and background process tools."""

from __future__ import annotations

import asyncio
import os
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.execution.environment import scrub_spawn_environment
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
    return scrub_spawn_environment(env)


async def terminal(
    command: str,
    cwd: str = ".",
    background: bool = False,
    timeout: int = 30,
    execution_service=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    sandbox_decision=None,
    executable_identity: str | None = None,
    spawn_plan=None,
    execution_authority=None,
) -> dict[str, Any]:
    """Compatibility wrapper for explicit shell execution.

    Production registration exposes :func:`terminal_argv` and
    :func:`terminal_shell`; it never exposes this ambiguous string contract.
    """
    return await terminal_shell(
        shell="/bin/sh",
        script=command,
        cwd=cwd,
        background=background,
        timeout_seconds=timeout,
        execution_service=execution_service,
        task_id=task_id,
        workspace_id=workspace_id,
        sandbox_decision=sandbox_decision,
        executable_identity=executable_identity,
        spawn_plan=spawn_plan,
        execution_authority=execution_authority,
    )


async def terminal_argv(
    argv: list[str],
    cwd: str = ".",
    timeout_seconds: int = 60,
    background: bool = False,
    *,
    execution_service=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    workspace_manager=None,
    process_authority=None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    _safety_command: str | None = None,
    sandbox_decision=None,
    executable_identity: str | None = None,
    spawn_plan=None,
    execution_authority=None,
) -> dict[str, Any]:
    """Execute an argv vector without shell parsing or expansion."""
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must contain non-empty strings")
    command = shlex.join(argv)
    safety_command = _safety_command or command
    command_check = check_command_safety(safety_command)
    if not command_check["safe"]:
        return {
            "ok": False,
            "error": f"Command blocked: {command_check['reason']}",
            "risk_level": command_check["risk_level"],
        }
    safety = evaluate_command_safety(safety_command)
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
    workdir = _workspace_cwd(cwd, workspace_manager, workspace_id, task_id)
    from khaos.coding.execution import ExecutionRequest, ResourceBudget
    request = ExecutionRequest(
        tuple(argv),
        workdir,
        budget=ResourceBudget(timeout_seconds=timeout_seconds),
        task_id=task_id,
        workspace_id=workspace_id,
        access_mode="read-only" if safety["read_only"] else "workspace-write",
        sandbox_decision=sandbox_decision,
        executable_identity=executable_identity or "",
        spawn_plan=spawn_plan,
        execution_authority=execution_authority,
    )
    if background:
        if process_authority is None:
            raise PermissionError("background execution requires ProcessAuthority")
        process_id = await process_authority.start(
            execution_service,
            request,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        return {"id": process_id, "status": "running", "argv": list(argv)}
    result = await execution_service.execute(request)
    return {
        "command": command,
        "returncode": result.return_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": result.status,
        "diagnostics": result.diagnostics,
        "safety": safety,
    }


async def terminal_shell(
    shell: str,
    script: str,
    cwd: str = ".",
    timeout_seconds: int = 60,
    background: bool = False,
    *,
    execution_service=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
    workspace_manager=None,
    process_authority=None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    sandbox_decision=None,
    executable_identity: str | None = None,
    spawn_plan=None,
    execution_authority=None,
) -> dict[str, Any]:
    """Execute a script only through an explicitly selected absolute shell."""
    shell_path = Path(shell)
    if str(shell_path) not in {"/bin/sh", "/bin/bash", "/bin/zsh"}:
        raise PermissionError("shell must be an approved absolute shell path")
    if not script.strip():
        raise ValueError("script must not be empty")
    return await terminal_argv(
        [str(shell_path), "-c", script],
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        background=background,
        execution_service=execution_service,
        task_id=task_id,
        workspace_id=workspace_id,
        workspace_manager=workspace_manager,
        process_authority=process_authority,
        principal_id=principal_id,
        project_id=project_id,
        runtime_id=runtime_id,
        _safety_command=script,
        sandbox_decision=sandbox_decision,
        executable_identity=executable_identity,
        spawn_plan=spawn_plan,
        execution_authority=execution_authority,
    )


def check_command_safety(command: str) -> dict[str, Any]:
    """检查命令安全性。在 terminal() 执行前调用。"""
    result = _COMMAND_GUARD.check(command)
    return {
        "safe": result.safe,
        "risk_level": result.risk_level,
        "reason": result.reason,
        "matched_pattern": result.matched_pattern,
    }


async def process(
    action: str,
    id: str,
    timeout_seconds: int = 30,
    *,
    process_authority=None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    task_id: str | None = None,
    workspace_id: str | None = None,
    **_injected: Any,
) -> dict[str, Any]:
    """Poll, wait, kill, or read logs for a background process."""
    if process_authority is None:
        raise PermissionError("process operation requires ProcessAuthority")
    return await process_authority.control(
        action,
        id,
        timeout_seconds,
        principal_id=principal_id,
        project_id=project_id,
        runtime_id=runtime_id,
        task_id=task_id or "",
        workspace_id=workspace_id or "",
    )


@dataclass
class _BackgroundRecord:
    handle: Any
    stdout_task: asyncio.Task[str]
    principal_id: str
    project_id: str
    runtime_id: str
    task_id: str
    workspace_id: str


class BackgroundProcessAuthority:
    """Runtime-owned handles whose processes are held by ProcessSupervisor."""

    def __init__(
        self,
        *,
        max_background_processes: int = 4,
        max_processes_per_workspace: int = 2,
        output_limit: int = 65536,
    ) -> None:
        self.max_background_processes = max_background_processes
        self.max_processes_per_workspace = max_processes_per_workspace
        self.output_limit = output_limit
        self._records: dict[str, _BackgroundRecord] = {}
        self._workspace_ids: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def start(
        self,
        execution_service: Any,
        request: Any,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
    ) -> str:
        workspace_id = str(request.workspace_id or "")
        async with self._lock:
            self._prune_finished_locked()
            if len(self._records) >= self.max_background_processes:
                raise RuntimeError("background process budget exhausted")
            workspace_count = sum(
                value == workspace_id for value in self._workspace_ids.values()
            )
            if workspace_count >= self.max_processes_per_workspace:
                raise RuntimeError("workspace process budget exhausted")
            process_id = request.correlation_id or uuid.uuid4().hex[:12]
            handle = await execution_service.start_managed_process(request)
            stdout_task = asyncio.create_task(
                _collect_bounded_stdout(handle.stdout, self.output_limit)
            )
            self._records[process_id] = _BackgroundRecord(
                handle=handle,
                stdout_task=stdout_task,
                principal_id=principal_id,
                project_id=project_id,
                runtime_id=runtime_id,
                task_id=str(request.task_id or ""),
                workspace_id=workspace_id,
            )
            self._workspace_ids[process_id] = workspace_id
            return process_id

    async def control(
        self,
        action: str,
        process_id: str,
        timeout: int,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
    ) -> dict[str, Any]:
        async with self._lock:
            record = self._records.get(process_id)
        if record is None:
            raise KeyError(f"unknown process: {process_id}")
        if (
            record.principal_id,
            record.project_id,
            record.runtime_id,
            record.task_id,
            record.workspace_id,
        ) != (principal_id, project_id, runtime_id, task_id, workspace_id):
            raise PermissionError("background process belongs to a different runtime authority")
        handle = record.handle
        if action == "poll":
            return {"id": process_id, "running": handle.returncode is None, "returncode": handle.returncode}
        if action == "wait":
            try:
                code = await asyncio.wait_for(handle.wait(), timeout=timeout)
            except TimeoutError as exc:
                raise TimeoutError(f"process wait timed out after {timeout}s") from exc
            stdout = await record.stdout_task
            return await self._finished(process_id, code, stdout, handle)
        if action == "kill":
            await handle.aclose()
            stdout = await record.stdout_task
            return await self._finished(process_id, handle.returncode, stdout, handle)
        if action == "log":
            stdout = record.stdout_task.result() if record.stdout_task.done() else ""
            return {"id": process_id, "stdout": stdout, "stderr": handle.stderr_text, "running": handle.returncode is None}
        raise ValueError(f"unsupported process action: {action}")

    async def shutdown(self) -> None:
        async with self._lock:
            records = list(self._records.values())
        await asyncio.gather(*(record.handle.aclose() for record in records))
        async with self._lock:
            self._records.clear()
            self._workspace_ids.clear()

    async def _finished(self, process_id: str, code: int | None, stdout: str, handle: Any) -> dict[str, Any]:
        async with self._lock:
            self._records.pop(process_id, None)
            self._workspace_ids.pop(process_id, None)
        return {"id": process_id, "running": False, "returncode": code, "stdout": stdout, "stderr": handle.stderr_text}

    def _prune_finished_locked(self) -> None:
        for process_id, record in list(self._records.items()):
            if record.handle.returncode is not None and record.stdout_task.done():
                self._records.pop(process_id, None)
                self._workspace_ids.pop(process_id, None)


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


async def _collect_bounded_stdout(stream: Any, limit: int) -> str:
    retained = bytearray()
    if stream is None:
        return ""
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return retained.decode("utf-8", errors="replace")


def _workspace_cwd(cwd: str, manager: Any, workspace_id: str | None, task_id: str | None) -> Path:
    if manager is None or not workspace_id or not task_id:
        return Path(cwd).expanduser().resolve()
    workspace = manager.get(workspace_id)
    if workspace is None or workspace.task_id != task_id:
        raise PermissionError("task/workspace binding is invalid")
    root = workspace.worktree_path.resolve(strict=True)
    candidate = Path(cwd)
    resolved = candidate.resolve(strict=False) if candidate.is_absolute() else (root / candidate).resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise PermissionError("terminal cwd escapes active TaskWorkspace")
    return resolved


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
