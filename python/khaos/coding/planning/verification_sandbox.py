"""Production Docker backend for planned trusted verification.

This module is deliberately independent from Agent ExecutionService and its
terminal/test_run backends.  It accepts only an already canonical, server-owned
command and a disposable verification workspace.

Batch 3.1.1 §1: refactored to a durable instance lifecycle API:
``prepare_instance`` → ``launch_instance`` → ``terminate_instance`` →
``inspect_instance`` / ``reconcile_instances``.  Every container carries
high-entropy Khaos labels that bind it to a persisted
``VerificationSandboxInstance`` row.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol

from khaos.coding.planning.trusted_verification import (
    DisposableVerificationWorkspace, SandboxProfile,
)
from khaos.coding.planning.verification_execution_models import TrustedVerificationCommand
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)


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
    """Hardened production backend using one digest-pinned disposable container.

    Batch 3.1.1 §1: refactored to durable instance lifecycle.
    """

    BACKEND_ID = "docker-verification-v1"

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

    # ------------------------------------------------------------------
    # §1: Durable instance lifecycle API
    # ------------------------------------------------------------------

    def generate_instance_name(self) -> str:
        """Generate a high-entropy container name."""
        return f"khaos-verify-{secrets.token_hex(12)}"

    def build_labels(
        self, *, run_id: str, step_id: str, instance_id: str,
        boot_id: str, manifest_digest: str,
    ) -> dict[str, str]:
        """Build unforgeable Khaos labels for the container."""
        return {
            "khaos.run-id": run_id,
            "khaos.step-id": step_id,
            "khaos.sandbox-instance-id": instance_id,
            "khaos.boot-id": boot_id,
            "khaos.manifest-digest": manifest_digest[:63],
        }

    async def prepare_instance(
        self, *, sandbox_instance_id: str, instance_name: str,
        image_digest: str, labels: dict[str, str],
    ) -> str:
        """Prepare the container (no-op for Docker — name is the handle).

        Returns the instance_name which serves as the container name.
        """
        return instance_name

    async def launch_instance(
        self, *, instance_name: str, image_digest: str,
        command: TrustedVerificationCommand,
        workspace_root: Path, labels: dict[str, str],
    ) -> asyncio.subprocess.Process:
        """Launch the Docker container with ``--pull=never`` and Khaos labels.

        Batch 3.1.1 §7: uses ``--pull=never`` to prevent automatic image
        pulling.  The image must already exist locally and match the
        digest pinned in the profile.
        """
        cwd = self._safe_cwd(command.cwd)
        environment = (
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/tmp/home", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "TZ=UTC", "SOURCE_DATE_EPOCH=0", "PYTHONHASHSEED=0",
        )
        args = [
            str(self._docker), "run", "--pull=never", "--rm", "--name", instance_name,
            "--network", "none", "--read-only", "--user", self.profile.run_as_user,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.profile.pids_limit),
            "--memory", str(self.profile.memory_bytes), "--cpus", str(self.profile.cpu_count),
            "--ulimit", f"nofile={self.profile.open_files}:{self.profile.open_files}",
            "--ulimit", f"fsize={self.profile.file_size_bytes}:{self.profile.file_size_bytes}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
            "--mount", f"type=bind,src={workspace_root},dst=/workspace",
            "--workdir", f"/workspace/{cwd}" if cwd != "." else "/workspace",
        ]
        for key, value in labels.items():
            args.extend(("--label", f"{key}={value}"))
        for value in environment:
            args.extend(("--env", value))
        args.extend((image_digest, *command.argv))
        return await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

    async def inspect_instance(self, instance_name: str) -> dict[str, Any] | None:
        """Inspect a container by name. Returns None if not found."""
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "inspect", instance_name,
            "--format", "{{json .}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            return None
        try:
            return json.loads(stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return None

    async def inspect_image(self, image_digest: str) -> str | None:
        """Inspect a local image. Returns the actual image ID or None."""
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "image", "inspect", image_digest,
            "--format", "{{.Id}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            return None
        return stdout.decode("utf-8", "replace").strip() or None

    async def terminate_instance(self, instance_name: str) -> bool:
        """Terminate a container by name. Returns True if terminated."""
        for sig in ("TERM", "KILL"):
            killer = await asyncio.create_subprocess_exec(
                str(self._docker), "kill", "--signal", sig, instance_name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
            # Brief wait for container to exit.
            await asyncio.sleep(0.1)
            info = await self.inspect_instance(instance_name)
            if info is None:
                return True
        # Force remove if still present.
        remover = await asyncio.create_subprocess_exec(
            str(self._docker), "rm", "-f", instance_name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await remover.wait()
        return self.inspect_instance(instance_name) is None

    async def reconcile_instances(
        self, *, expected_labels: dict[str, str],
    ) -> dict[str, Any]:
        """Find and optionally terminate containers matching Khaos labels.

        Batch 3.1.1 §2: used during Runtime initialization to discover
        and clean up residual containers from a crashed worker.

        Returns a report dict with:
        - ``found``: list of container names matching labels.
        - ``terminated``: list of container names that were terminated.
        - ``unknown``: list of containers with partial label matches (NOT terminated).
        """
        # List all containers with the khaos.run-id label.
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "ps", "-a",
            "--filter", "label=khaos.run-id",
            "--format", "{{.Names}}\t{{.Labels}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        found: list[str] = []
        terminated: list[str] = []
        unknown: list[str] = []
        for line in stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            label_str = parts[1].strip()
            # Parse comma-separated key=value labels.
            container_labels: dict[str, str] = {}
            for pair in label_str.split(","):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    container_labels[k.strip()] = v.strip()
            # Check if ALL expected labels match.
            matches = all(
                container_labels.get(k) == v
                for k, v in expected_labels.items()
            )
            if matches:
                found.append(name)
                ok = await self.terminate_instance(name)
                if ok:
                    terminated.append(name)
            elif any(k.startswith("khaos.") for k in container_labels):
                # Partial Khaos label match — label tampering suspected.
                unknown.append(name)
        return {"found": found, "terminated": terminated, "unknown": unknown}

    # ------------------------------------------------------------------
    # §7: Production image attestation
    # ------------------------------------------------------------------

    async def probe(self) -> str:
        """Probe the local image and return the actual image ID.

        Batch 3.1.1 §7: uses ``image inspect`` (not ``pull``).  The actual
        image ID must equal the profile's ``image_digest``.
        """
        actual = await self.inspect_image(self.profile.image_digest)
        if actual is None:
            raise RuntimeError(
                f"production sandbox image unavailable (not pulled): "
                f"{self.profile.image_digest}"
            )
        if actual != self.profile.image_digest:
            raise RuntimeError(
                f"sandbox image identity mismatch: expected "
                f"{self.profile.image_digest}, got {actual}"
            )
        return actual

    async def verify_container_image(self, instance_name: str) -> str:
        """Re-inspect the running container's image ID after start.

        Batch 3.1.1 §7: the container's actual image ID must match
        the profile's pinned digest.
        """
        info = await self.inspect_instance(instance_name)
        if info is None:
            raise RuntimeError(f"container {instance_name} not found after launch")
        # Docker inspect returns the image ID in .Image.
        actual = info.get("Image", "")
        if actual and actual != self.profile.image_digest:
            raise RuntimeError(
                f"container image mismatch after launch: expected "
                f"{self.profile.image_digest}, got {actual}"
            )
        return actual

    # ------------------------------------------------------------------
    # Original execute() API (now wraps the durable lifecycle)
    # ------------------------------------------------------------------

    async def execute(
        self,
        command: TrustedVerificationCommand,
        workspace: DisposableVerificationWorkspace,
        *,
        cancellation: asyncio.Event | None = None,
        sandbox_instance_id: str = "",
        verification_run_id: str = "",
        step_run_id: str = "",
        boot_id: str = "",
    ) -> SandboxStepResult:
        """Execute one command in a disposable Docker container.

        Batch 3.1.1 §1: now accepts sandbox_instance_id / run_id / step_id /
        boot_id for durable instance tracking.  When these are provided,
        the container is labeled with unforgeable Khaos labels.
        """
        normalized = command.normalized()
        if normalized.command_digest != command.command_digest:
            raise PermissionError("trusted command digest mismatch")
        if command.sandbox_profile_id != self.profile.profile_id:
            raise PermissionError("sandbox profile mismatch")
        name = self.generate_instance_name()
        labels = self.build_labels(
            run_id=verification_run_id, step_id=step_run_id,
            instance_id=sandbox_instance_id or name, boot_id=boot_id,
            manifest_digest=getattr(workspace, "manifest_digest", ""),
        )
        started = time.monotonic()
        process = await self.launch_instance(
            instance_name=name, image_digest=self.profile.image_digest,
            command=command, workspace_root=workspace.root, labels=labels,
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
