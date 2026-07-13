"""Production Docker backend for planned trusted verification.

This module is deliberately independent from Agent ExecutionService and its
terminal/test_run backends.  It accepts only an already canonical, server-owned
command and a disposable verification workspace.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

from khaos.coding.planning.trusted_verification import (
    DisposableVerificationWorkspace, SandboxProfile,
)
from khaos.coding.planning.verification_execution_models import TrustedVerificationCommand


@dataclass(frozen=True)
class SandboxStepResult:
    sandbox_instance_id: str
    image_digest: str
    exit_code: int | None
    signal: int | None
    duration_ms: int
    stdout: bytes
    stderr: bytes
    stdout_digest: str
    stderr_digest: str
    output_truncated: bool
    timed_out: bool = False
    cancelled: bool = False


class VerificationSandboxBackend(Protocol):
    profile: SandboxProfile

    async def execute(
        self,
        command: TrustedVerificationCommand,
        workspace: DisposableVerificationWorkspace,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> SandboxStepResult: ...


class DockerVerificationSandboxBackend:
    """Hardened production backend using one digest-pinned disposable container."""

    def __init__(
        self,
        *,
        profile: SandboxProfile,
        docker_executable: Path = Path("/usr/local/bin/docker"),
        secret_values: Iterable[str] = (),
        host_paths: Iterable[Path] = (),
        kill_grace_seconds: float = 1.0,
    ) -> None:
        if not profile.image_digest.startswith("sha256:"):
            raise ValueError("production sandbox image must be digest pinned")
        if profile.network_enabled or not profile.read_only_root:
            raise ValueError("production verification profile must be offline/read-only")
        self.profile = profile
        self._docker = docker_executable.resolve(strict=True)
        self._secrets = tuple(value for value in secret_values if value)
        self._host_paths = tuple(str(path.resolve()) for path in host_paths)
        self._grace = kill_grace_seconds

    async def probe(self) -> None:
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "image", "inspect", self.profile.image_digest,
            "--format", "{{.Id}}", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"production sandbox image unavailable: {self._redact(stderr)!r}")
        if stdout.decode("utf-8", "replace").strip() != self.profile.image_digest:
            raise RuntimeError("sandbox image identity mismatch")

    async def execute(
        self,
        command: TrustedVerificationCommand,
        workspace: DisposableVerificationWorkspace,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> SandboxStepResult:
        normalized = command.normalized()
        if normalized.command_digest != command.command_digest:
            raise PermissionError("trusted command digest mismatch")
        if command.sandbox_profile_id != self.profile.profile_id:
            raise PermissionError("sandbox profile mismatch")
        cwd = self._safe_cwd(command.cwd)
        name = f"khaos-verify-{secrets.token_hex(12)}"
        environment = (
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/tmp/home", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "TZ=UTC", "SOURCE_DATE_EPOCH=0", "PYTHONHASHSEED=0",
        )
        args = [
            str(self._docker), "run", "--rm", "--name", name,
            "--network", "none", "--read-only", "--user", self.profile.run_as_user,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.profile.pids_limit),
            "--memory", str(self.profile.memory_bytes), "--cpus", str(self.profile.cpu_count),
            "--ulimit", f"nofile={self.profile.open_files}:{self.profile.open_files}",
            "--ulimit", f"fsize={self.profile.file_size_bytes}:{self.profile.file_size_bytes}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
            "--mount", f"type=bind,src={workspace.root},dst=/workspace",
            "--workdir", f"/workspace/{cwd}" if cwd != "." else "/workspace",
        ]
        for value in environment:
            args.extend(("--env", value))
        args.extend((self.profile.image_digest, *command.argv))
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout_task = asyncio.create_task(self._read_bounded(process.stdout, command.output_limit_bytes))
        stderr_task = asyncio.create_task(self._read_bounded(process.stderr, command.output_limit_bytes))
        wait_task = asyncio.create_task(process.wait())
        cancel_task = asyncio.create_task(cancellation.wait()) if cancellation else None
        timed_out = False
        cancelled = False
        try:
            wait_set = {wait_task}
            if cancel_task:
                wait_set.add(cancel_task)
            done, _ = await asyncio.wait(
                wait_set, timeout=command.timeout_ms / 1000,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if wait_task not in done:
                timed_out = cancel_task not in done
                cancelled = cancel_task in done
                await self._terminate_container(name, process)
            await wait_task
        finally:
            if cancel_task:
                cancel_task.cancel()
        stdout, stdout_truncated = await stdout_task
        stderr, stderr_truncated = await stderr_task
        stdout = self._redact(stdout)
        stderr = self._redact(stderr)
        code = process.returncode
        return SandboxStepResult(
            name, self.profile.image_digest,
            None if code is not None and code < 0 else code,
            -code if code is not None and code < 0 else None,
            int((time.monotonic() - started) * 1000), stdout, stderr,
            hashlib.sha256(stdout).hexdigest(), hashlib.sha256(stderr).hexdigest(),
            stdout_truncated or stderr_truncated, timed_out, cancelled,
        )

    async def _terminate_container(self, name: str, process: asyncio.subprocess.Process) -> None:
        killer = await asyncio.create_subprocess_exec(
            str(self._docker), "kill", "--signal", "TERM", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
        try:
            await asyncio.wait_for(process.wait(), timeout=self._grace)
        except asyncio.TimeoutError:
            killer = await asyncio.create_subprocess_exec(
                str(self._docker), "kill", "--signal", "KILL", name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    async def _read_bounded(
        self, stream: asyncio.StreamReader | None, limit: int,
    ) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        size = 0
        truncated = False
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                break
            remaining = max(0, limit - size)
            if remaining:
                chunks.append(chunk[:remaining])
                size += min(remaining, len(chunk))
            if len(chunk) > remaining:
                truncated = True
        return b"".join(chunks), truncated

    def _redact(self, value: bytes) -> bytes:
        text = value.decode("utf-8", "replace")
        for secret in self._secrets:
            text = text.replace(secret, "<redacted-secret>")
        for path in sorted(self._host_paths, key=len, reverse=True):
            text = text.replace(path, "<host-path>")
        text = re.sub(r"/(?:Users|home)/[^\s:'\"]+", "<host-path>", text)
        return text.encode("utf-8")

    @staticmethod
    def _safe_cwd(value: str) -> str:
        candidate = value.replace("\\", "/")
        parts = candidate.split("/")
        if (not value or value.startswith("/") or re.match(r"^[A-Za-z]:", candidate)
                or candidate.startswith("//")
                or any(part in {"", ".."} for part in parts)):
            if value == ".":
                return "."
            raise PermissionError("verification cwd must be repository relative")
        return candidate
