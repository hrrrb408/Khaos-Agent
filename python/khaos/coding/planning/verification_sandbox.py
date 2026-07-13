"""Production Docker backend for planned trusted verification.

This module is deliberately independent from Agent ExecutionService and its
terminal/test_run backends.  It accepts only an already canonical, server-owned
command and a disposable verification workspace.

Batch 3.1.2 §1: refactored to an explicit container lifecycle:
``prepare_instance`` → ``create_instance`` → ``inspect_and_attest_instance``
→ ``start_instance`` → ``wait_instance`` → ``terminate_instance`` →
``remove_instance``.  The container ID is persisted BEFORE project code
executes, using ``docker create --pull=never`` instead of ``docker run --rm``.
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
    DisposableVerificationWorkspace, SandboxProfile, TrustedToolchain,
)
from khaos.coding.planning.verification_execution_models import TrustedVerificationCommand
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)


@dataclass(frozen=True)
class ContainerAttestation:
    """Batch 3.1.2 §4: image identity attestation for a created container."""
    container_id: str
    container_image_id: str          # from docker inspect .Image
    local_image_id: str              # from docker image inspect .Id
    expected_image_digest: str       # from profile (manifest digest)
    labels: dict[str, str]
    manifest_digest: str
    attestation_digest: str


@dataclass(frozen=True)
class ToolchainAttestation:
    """Batch 3.1.2 §5: real toolchain attestation from an attestation container.

    Built inside a trusted, no-Workspace-mount attestation container by:
    opening the absolute executable path, confirming it is a regular file,
    computing its SHA-256, running the fixed version argv, parsing the
    output, and verifying the parsed version matches the approved version.

    The ``attestation_digest`` binds the toolchain identity to the actual
    image attestation and is re-verified before each verification launch.
    """
    toolchain_id: str                # "{language}:{executable_id}"
    executable_path: str             # absolute path inside the container
    binary_digest: str               # sha256:<hex> of the executable file
    version_output_digest: str       # sha256:<hex> of the raw version output
    parsed_version: str              # parsed version string
    actual_image_attestation: str    # profile.image_digest used for attestation
    attested_at: float               # time.time() at attestation
    attestation_digest: str          # canonical digest binding all fields above


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
    container_id: str = ""
    attestation_digest: str = ""


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

    Batch 3.1.2 §1: explicit create/start/wait/terminate/remove lifecycle.
    Container identity is persisted BEFORE project code executes.
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
    # §1: Explicit container lifecycle API
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

    def _build_create_args(
        self, *, instance_name: str, image_digest: str,
        command: TrustedVerificationCommand,
        workspace_root: Path, labels: dict[str, str],
    ) -> list[str]:
        """Build the ``docker create`` argument list (no --rm, no --pull)."""
        cwd = self._safe_cwd(command.cwd)
        environment = (
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/tmp/home", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "TZ=UTC", "SOURCE_DATE_EPOCH=0", "PYTHONHASHSEED=0",
        )
        args = [
            str(self._docker), "create", "--pull=never", "--name", instance_name,
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
        return args

    async def create_instance(
        self, *, instance_name: str, image_digest: str,
        command: TrustedVerificationCommand,
        workspace_root: Path, labels: dict[str, str],
    ) -> str:
        """Batch 3.1.2 §1: ``docker create --pull=never`` — no project code runs.

        Returns the container ID printed by ``docker create`` on stdout.
        """
        args = self._build_create_args(
            instance_name=instance_name, image_digest=image_digest,
            command=command, workspace_root=workspace_root, labels=labels,
        )
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                f"docker create failed (exit {process.returncode}): "
                f"{stderr.decode('utf-8', 'replace')}"
            )
        container_id = stdout.decode("utf-8", "replace").strip()
        if not container_id:
            raise RuntimeError("docker create produced no container ID")
        return container_id

    async def inspect_and_attest_instance(
        self, *, container_id_or_name: str, expected_labels: dict[str, str],
        expected_image_digest: str, expected_manifest_digest: str,
    ) -> ContainerAttestation:
        """Batch 3.1.2 §4: inspect the created container and verify identity.

        Verifies:
        - All expected Khaos labels are present and match.
        - The container's Image ID matches the local image inspect ID.
        - The local image ID matches the profile's expected digest.
        - The workspace manifest digest label matches.

        Returns a ``ContainerAttestation`` with all identity fields.
        """
        info = await self.inspect_instance(container_id_or_name)
        if info is None:
            raise RuntimeError(
                f"container {container_id_or_name} not found after create"
            )
        container_id = info.get("Id", "")
        container_image_id = info.get("Image", "")
        # Verify labels.
        container_labels: dict[str, str] = {}
        for key, value in info.get("Config", {}).get("Labels", {}).items():
            container_labels[key] = value
        for key, expected_value in expected_labels.items():
            actual_value = container_labels.get(key)
            if actual_value != expected_value:
                raise RuntimeError(
                    f"container label mismatch: {key} expected={expected_value} "
                    f"actual={actual_value}"
                )
        # Verify image identity.
        local_image_id = await self.inspect_image(expected_image_digest)
        if local_image_id is None:
            raise RuntimeError(
                f"local image not found: {expected_image_digest}"
            )
        if local_image_id != expected_image_digest:
            raise RuntimeError(
                f"local image ID mismatch: expected={expected_image_digest} "
                f"actual={local_image_id}"
            )
        if container_image_id and container_image_id != local_image_id:
            raise RuntimeError(
                f"container image ID mismatch: container={container_image_id} "
                f"local={local_image_id}"
            )
        # Verify manifest digest label.
        actual_manifest = container_labels.get("khaos.manifest-digest", "")
        if expected_manifest_digest and actual_manifest:
            if actual_manifest != expected_manifest_digest[:63]:
                raise RuntimeError(
                    f"manifest digest label mismatch: expected="
                    f"{expected_manifest_digest[:63]} actual={actual_manifest}"
                )
        attestation_digest = hashlib.sha256(json.dumps({
            "container_id": container_id,
            "container_image_id": container_image_id,
            "local_image_id": local_image_id,
            "expected_image_digest": expected_image_digest,
            "labels": expected_labels,
            "manifest_digest": expected_manifest_digest,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return ContainerAttestation(
            container_id=container_id,
            container_image_id=container_image_id,
            local_image_id=local_image_id,
            expected_image_digest=expected_image_digest,
            labels=dict(expected_labels),
            manifest_digest=expected_manifest_digest,
            attestation_digest=attestation_digest,
        )

    async def start_instance(self, container_id_or_name: str) -> None:
        """Batch 3.1.2 §1: ``docker start`` the created container."""
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "start", container_id_or_name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                f"docker start failed (exit {process.returncode}): "
                f"{stderr.decode('utf-8', 'replace')}"
            )

    async def attach_instance(
        self, container_id_or_name: str,
    ) -> tuple[asyncio.subprocess.Process, Any, Any]:
        """Batch 3.1.2 §1: ``docker attach`` to capture stdout/stderr.

        Returns (process, stdout_reader, stderr_reader).  The process
        completes when the container exits and the streams are drained.
        """
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "attach", "--no-stdin",
            container_id_or_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        return process, process.stdout, process.stderr

    async def wait_instance(self, container_id_or_name: str) -> int:
        """Batch 3.1.2 §1: ``docker wait`` — returns the exit code."""
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "wait", container_id_or_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"docker wait failed for {container_id_or_name}")
        try:
            return int(stdout.decode("utf-8", "replace").strip())
        except ValueError:
            raise RuntimeError(f"docker wait returned non-integer: {stdout!r}")

    async def inspect_instance(self, container_id_or_name: str) -> dict[str, Any] | None:
        """Inspect a container by name or ID. Returns None if not found."""
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "inspect", container_id_or_name,
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

    async def terminate_instance(self, container_id_or_name: str) -> bool:
        """Terminate a container by name or ID. Returns True if terminated."""
        for sig in ("TERM", "KILL"):
            killer = await asyncio.create_subprocess_exec(
                str(self._docker), "kill", "--signal", sig, container_id_or_name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
            await asyncio.sleep(0.1)
            info = await self.inspect_instance(container_id_or_name)
            if info is None:
                return True
            # Check if container is in exited state.
            state = info.get("State", {})
            if state.get("Status") == "exited" or state.get("Running") is False:
                return True
        return False

    async def remove_instance(self, container_id_or_name: str) -> bool:
        """Remove a stopped container. Returns True if removed."""
        remover = await asyncio.create_subprocess_exec(
            str(self._docker), "rm", "-f", container_id_or_name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await remover.wait()
        return await self.inspect_instance(container_id_or_name) is None

    async def terminate_and_remove_instance(
        self, container_id_or_name: str,
    ) -> tuple[bool, bool]:
        """Batch 3.1.3 §2: terminate, remove, and verify container is gone.

        Returns ``(terminated_ok, removed_ok)``:
        - ``terminated_ok``: True if terminate_instance succeeded.
        - ``removed_ok``: True if inspect confirms container is gone.

        Only when ``removed_ok is True`` may the caller persist TERMINATED.
        """
        terminated_ok = await self.terminate_instance(container_id_or_name)
        removed_ok = await self.remove_instance(container_id_or_name)
        # Double-check: inspect must return None.
        final_check = await self.inspect_instance(container_id_or_name)
        return terminated_ok, removed_ok and final_check is None

    async def confirm_instance_gone(
        self, container_id_or_name: str,
    ) -> bool:
        """Batch 3.1.3 §2: confirm a container does not exist.

        Returns True only if inspect returns None.  Never raises — the
        caller must check the return value before marking TERMINATED.
        """
        return await self.inspect_instance(container_id_or_name) is None

    async def reconcile_instances(
        self, *, expected_labels: dict[str, str],
    ) -> dict[str, Any]:
        """Batch 3.1.2 §2: find and terminate containers matching Khaos labels.

        Returns a report dict with:
        - ``found``: list of container names matching ALL expected labels.
        - ``terminated``: list of container names that were terminated+removed.
        - ``unknown``: list of containers with partial Khaos label matches (NOT terminated).
        - ``mismatches``: list of (name, mismatch_reason) for label/image mismatches.
        """
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
        mismatches: list[tuple[str, str]] = []
        for line in stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            label_str = parts[1].strip()
            container_labels: dict[str, str] = {}
            for pair in label_str.split(","):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    container_labels[k.strip()] = v.strip()
            matches = all(
                container_labels.get(k) == v
                for k, v in expected_labels.items()
            )
            if matches:
                found.append(name)
                ok = await self.terminate_instance(name)
                if ok:
                    removed = await self.remove_instance(name)
                    if removed:
                        terminated.append(name)
                    else:
                        mismatches.append((name, "terminate-ok-remove-failed"))
                else:
                    mismatches.append((name, "terminate-failed"))
            elif any(k.startswith("khaos.") for k in container_labels):
                unknown.append(name)
        return {
            "found": found, "terminated": terminated,
            "unknown": unknown, "mismatches": mismatches,
        }

    async def reconcile_instance_by_record(
        self, *, container_id: str, instance_name: str,
        expected_labels: dict[str, str],
        expected_image_digest: str, expected_manifest_digest: str,
    ) -> dict[str, Any]:
        """Batch 3.1.2 §2: reconcile one specific instance by DB record.

        Uses the persisted container_id (or instance_name as fallback) to
        inspect and verify the container.  Returns a report dict:
        - ``status``: "missing" | "terminated" | "mismatch" | "cleanup-failed"
        - ``container_id``: the container ID inspected (or "").
        - ``reason``: mismatch reason if status is "mismatch".
        """
        target = container_id or instance_name
        if not target:
            return {"status": "missing", "container_id": "", "reason": "no-container-id"}
        info = await self.inspect_instance(target)
        if info is None:
            # Try by name if we used container_id.
            if container_id and instance_name and container_id != instance_name:
                info = await self.inspect_instance(instance_name)
            if info is None:
                return {"status": "missing", "container_id": "", "reason": "container-not-found"}
        actual_id = info.get("Id", "")
        # Verify labels.
        container_labels: dict[str, str] = {}
        for key, value in info.get("Config", {}).get("Labels", {}).items():
            container_labels[key] = value
        for key, expected_value in expected_labels.items():
            actual_value = container_labels.get(key)
            if actual_value != expected_value:
                ok = await self.terminate_instance(actual_id or target)
                if ok:
                    await self.remove_instance(actual_id or target)
                return {
                    "status": "mismatch", "container_id": actual_id,
                    "reason": f"label-mismatch:{key}",
                }
        # Verify image.
        container_image = info.get("Image", "")
        if container_image and expected_image_digest and container_image != expected_image_digest:
            ok = await self.terminate_instance(actual_id or target)
            if ok:
                await self.remove_instance(actual_id or target)
            return {
                "status": "mismatch", "container_id": actual_id,
                "reason": f"image-mismatch:{container_image}!={expected_image_digest}",
            }
        # Full match — terminate and remove.
        ok = await self.terminate_instance(actual_id or target)
        if not ok:
            return {
                "status": "cleanup-failed", "container_id": actual_id,
                "reason": "terminate-failed",
            }
        removed = await self.remove_instance(actual_id or target)
        if not removed:
            return {
                "status": "cleanup-failed", "container_id": actual_id,
                "reason": "remove-failed",
            }
        return {"status": "terminated", "container_id": actual_id, "reason": ""}

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

    # ------------------------------------------------------------------
    # §5: Real toolchain attestation
    # ------------------------------------------------------------------

    # Fixed version argv per executable_id — never trust catalog argv for
    # attestation.  The argv and output format are part of the trusted
    # toolchain contract, not the verification catalog.
    _VERSION_ARGV: dict[str, tuple[str, ...]] = {
        "python": ("--version",),
        "npm": ("--version",),
        "go": ("version",),
        "cargo": ("--version",),
    }

    @classmethod
    def _parse_version(cls, executable_id: str, output: str) -> str:
        """Parse the version output using a fixed format per executable_id.

        Falls back to the first whitespace-separated token if no parser is
        registered.  Never raises — an empty/unparseable result will fail
        the caller's version-match check.
        """
        text = output.strip()
        if executable_id == "python":
            # "Python 3.13.0" → "3.13.0"
            parts = text.split()
            return parts[-1] if parts else ""
        if executable_id == "npm":
            # "11.0.0" → "11.0.0"
            return text.split()[0] if text.split() else ""
        if executable_id == "go":
            # "go version go1.25.0 darwin/amd64" → "1.25.0"
            match = re.search(r"go(\d+\.\d+(?:\.\d+)?)", text)
            return match.group(1) if match else ""
        if executable_id == "cargo":
            # "cargo 1.90.0" → "1.90.0"
            parts = text.split()
            return parts[1] if len(parts) >= 2 else ""
        parts = text.split()
        return parts[-1] if parts else ""

    async def _run_attestation_command(
        self, *, image_digest: str, argv: tuple[str, ...],
        timeout_seconds: float = 30.0,
    ) -> tuple[int, bytes, bytes]:
        """Run a no-Workspace-mount attestation container and capture output.

        Uses ``docker run --rm --pull=never --network none --read-only``
        with the pinned image digest.  No workspace is mounted — the
        container can only read the image's own filesystem.
        """
        args = [
            str(self._docker), "run", "--rm", "--pull=never",
            "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.profile.pids_limit),
            "--memory", str(self.profile.memory_bytes),
            "--cpus", str(self.profile.cpu_count),
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
            image_digest, *argv,
        ]
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            raise RuntimeError(
                f"attestation container timed out: argv={argv}"
            )
        return process.returncode, stdout, stderr

    async def attest_toolchain(
        self, *, toolchain: TrustedToolchain, image_digest: str,
    ) -> ToolchainAttestation:
        """Batch 3.1.2 §5: attest one toolchain inside an attestation container.

        Runs a no-Workspace-mount container with the pinned image, opens
        the absolute executable path, confirms it is a regular file,
        computes its SHA-256, runs the fixed version argv, parses the
        output, and returns a :class:`ToolchainAttestation`.

        Does NOT trust the workspace executable — only the image's own
        filesystem is visible to the attestation container.
        """
        version_argv = self._VERSION_ARGV.get(toolchain.executable_id)
        if version_argv is None:
            raise RuntimeError(
                f"toolchain {toolchain.executable_id} has no fixed version argv"
            )
        # 1. Compute binary SHA-256 using sha256sum inside the container.
        #    sha256sum is part of coreutils and present in most images;
        #    if absent, attestation fails closed.
        digest_rc, digest_out, digest_err = await self._run_attestation_command(
            image_digest=image_digest,
            argv=("sha256sum", toolchain.absolute_path),
        )
        if digest_rc != 0:
            raise RuntimeError(
                f"toolchain binary digest failed for "
                f"{toolchain.absolute_path}: exit={digest_rc} "
                f"stderr={digest_err.decode('utf-8', 'replace')}"
            )
        digest_line = digest_out.decode("utf-8", "replace").strip()
        # sha256sum output: "<hex>  <path>"
        digest_parts = digest_line.split(None, 1)
        if len(digest_parts) < 1 or not re.fullmatch(r"[0-9a-f]{64}", digest_parts[0]):
            raise RuntimeError(
                f"toolchain binary digest unparseable for "
                f"{toolchain.absolute_path}: {digest_line!r}"
            )
        binary_digest = f"sha256:{digest_parts[0]}"
        # 2. Confirm the path is a regular file using test -f inside the
        #    container.  This is defense-in-depth — sha256sum would also
        #    fail on a non-regular file, but we want an explicit check.
        test_rc, _, _ = await self._run_attestation_command(
            image_digest=image_digest,
            argv=("test", "-f", toolchain.absolute_path),
        )
        if test_rc != 0:
            raise RuntimeError(
                f"toolchain executable is not a regular file: "
                f"{toolchain.absolute_path}"
            )
        # 3. Run the fixed version argv and capture output.
        version_rc, version_out, version_err = await self._run_attestation_command(
            image_digest=image_digest,
            argv=(toolchain.absolute_path, *version_argv),
        )
        if version_rc != 0:
            raise RuntimeError(
                f"toolchain version command failed for "
                f"{toolchain.executable_id}: exit={version_rc} "
                f"stderr={version_err.decode('utf-8', 'replace')}"
            )
        version_output = version_out.decode("utf-8", "replace")
        parsed_version = self._parse_version(toolchain.executable_id, version_output)
        if not parsed_version:
            raise RuntimeError(
                f"toolchain version output unparseable for "
                f"{toolchain.executable_id}: {version_output!r}"
            )
        version_output_digest = f"sha256:{hashlib.sha256(version_out).hexdigest()}"
        attested_at = time.time()
        toolchain_id = f"{toolchain.language}:{toolchain.executable_id}"
        attestation_digest = hashlib.sha256(json.dumps({
            "toolchain_id": toolchain_id,
            "executable_path": toolchain.absolute_path,
            "binary_digest": binary_digest,
            "version_output_digest": version_output_digest,
            "parsed_version": parsed_version,
            "actual_image_attestation": image_digest,
            "attested_at": attested_at,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return ToolchainAttestation(
            toolchain_id=toolchain_id,
            executable_path=toolchain.absolute_path,
            binary_digest=binary_digest,
            version_output_digest=version_output_digest,
            parsed_version=parsed_version,
            actual_image_attestation=image_digest,
            attested_at=attested_at,
            attestation_digest=attestation_digest,
        )

    async def attest_toolchains(
        self, *, toolchains: tuple[TrustedToolchain, ...],
        image_digest: str,
    ) -> tuple[ToolchainAttestation, ...]:
        """Batch 3.1.2 §5: attest all toolchains for the pinned image.

        Returns a tuple of :class:`ToolchainAttestation` in the same order
        as the input toolchains.  Any failure raises and the caller must
        NOT install the verifier (fail-closed).
        """
        attestations: list[ToolchainAttestation] = []
        for toolchain in toolchains:
            if toolchain.image_digest != image_digest:
                raise RuntimeError(
                    f"toolchain {toolchain.language}:{toolchain.executable_id} "
                    f"image mismatch: {toolchain.image_digest} != {image_digest}"
                )
            attestation = await self.attest_toolchain(
                toolchain=toolchain, image_digest=image_digest,
            )
            # Verify parsed version matches the approved version.
            if attestation.parsed_version != toolchain.version:
                raise RuntimeError(
                    f"toolchain {toolchain.executable_id} version mismatch: "
                    f"approved={toolchain.version} "
                    f"actual={attestation.parsed_version}"
                )
            # If the toolchain declared a binary_digest, verify it matches.
            if toolchain.binary_digest and attestation.binary_digest != toolchain.binary_digest:
                raise RuntimeError(
                    f"toolchain {toolchain.executable_id} binary digest mismatch: "
                    f"declared={toolchain.binary_digest} "
                    f"actual={attestation.binary_digest}"
                )
            attestations.append(attestation)
        return tuple(attestations)

    # ------------------------------------------------------------------
    # §1: Explicit launch + collect API (production path)
    # ------------------------------------------------------------------

    def validate_command(self, command: TrustedVerificationCommand) -> None:
        """Batch 3.1.3 §1: pre-launch command validation (extracted from launch_instance).

        Verifies command digest and sandbox profile binding before any
        docker operation.  Raises PermissionError on mismatch.
        """
        normalized = command.normalized()
        if normalized.command_digest != command.command_digest:
            raise PermissionError("trusted command digest mismatch")
        if command.sandbox_profile_id != self.profile.profile_id:
            raise PermissionError("sandbox profile mismatch")

    async def launch_instance(
        self, *, instance_name: str, image_digest: str,
        command: TrustedVerificationCommand,
        workspace_root: Path, labels: dict[str, str],
        expected_manifest_digest: str,
    ) -> tuple[str, ContainerAttestation, asyncio.subprocess.Process, Any, Any]:
        """Batch 3.1.2 §1: create + inspect_and_attest + start + attach.

        Returns ``(container_id, attestation, attach_proc, stdout_stream,
        stderr_stream)``.  The caller MUST persist ``container_id`` and
        ``attestation`` BEFORE calling :meth:`collect_result`, so that a
        crash between launch and collect leaves a durable trail.

        No project code runs during ``docker create``.  ``docker start``
        begins the entrypoint, but the caller persists RUNNING before
        awaiting output via :meth:`collect_result`.
        """
        normalized = command.normalized()
        if normalized.command_digest != command.command_digest:
            raise PermissionError("trusted command digest mismatch")
        if command.sandbox_profile_id != self.profile.profile_id:
            raise PermissionError("sandbox profile mismatch")
        # 1. docker create --pull=never (no project code runs)
        container_id = await self.create_instance(
            instance_name=instance_name, image_digest=image_digest,
            command=command, workspace_root=workspace_root, labels=labels,
        )
        # 2. inspect and attest (before start — no project code has run)
        attestation = await self.inspect_and_attest_instance(
            container_id_or_name=container_id, expected_labels=labels,
            expected_image_digest=image_digest,
            expected_manifest_digest=expected_manifest_digest,
        )
        # 3. docker start
        await self.start_instance(container_id)
        # 4. docker attach to capture output
        attach_proc, stdout_stream, stderr_stream = await self.attach_instance(container_id)
        return container_id, attestation, attach_proc, stdout_stream, stderr_stream

    async def collect_result(
        self, *, container_id: str,
        attach_proc: asyncio.subprocess.Process,
        stdout_stream: Any, stderr_stream: Any,
        command: TrustedVerificationCommand,
        cancellation: asyncio.Event | None,
        started: float, sandbox_instance_id: str,
        attestation_digest: str,
        remove: bool = True,
    ) -> SandboxStepResult:
        """Batch 3.1.3 §1: wait for completion, read streams, optionally remove.

        Called AFTER the caller has persisted ``container_id`` and
        ``attestation_digest``.  Handles timeout, cancellation, stream
        reading.  When ``remove=True`` (default, backward compat), also
        terminates and removes the container.  When ``remove=False``, the
        caller is responsible for calling ``terminate_and_remove_instance``
        and confirming the container is gone before persisting TERMINATED.
        """
        stdout_task = asyncio.create_task(
            self._read_bounded(stdout_stream, command.output_limit_bytes),
        )
        stderr_task = asyncio.create_task(
            self._read_bounded(stderr_stream, command.output_limit_bytes),
        )
        wait_task = asyncio.create_task(self.wait_instance(container_id))
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
                await self.terminate_instance(container_id)
            exit_code = await wait_task
        finally:
            if cancel_task:
                cancel_task.cancel()
            try:
                attach_proc.kill()
            except ProcessLookupError:
                pass
        stdout, stdout_truncated = await stdout_task
        stderr, stderr_truncated = await stderr_task
        stdout = self._redact(stdout)
        stderr = self._redact(stderr)
        if remove:
            await self.remove_instance(container_id)
        return SandboxStepResult(
            sandbox_instance_id, self.profile.image_digest,
            None if exit_code is not None and exit_code < 0 else exit_code,
            -exit_code if exit_code is not None and exit_code < 0 else None,
            int((time.monotonic() - started) * 1000), stdout, stderr,
            hashlib.sha256(stdout).hexdigest(), hashlib.sha256(stderr).hexdigest(),
            stdout_truncated or stderr_truncated, timed_out, cancelled,
            container_id, attestation_digest,
        )

    # ------------------------------------------------------------------
    # Legacy execute() API — wraps launch_instance + collect_result for
    # backward compatibility with tests.  Production code uses the
    # explicit API so container_id is persisted before project code runs.
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
        instance_name: str = "",
    ) -> SandboxStepResult:
        """Backward-compatible wrapper: launch_instance + collect_result."""
        name = instance_name or self.generate_instance_name()
        labels = self.build_labels(
            run_id=verification_run_id, step_id=step_run_id,
            instance_id=sandbox_instance_id or name, boot_id=boot_id,
            manifest_digest=getattr(workspace, "manifest_digest", ""),
        )
        started = time.monotonic()
        container_id, attestation, attach_proc, stdout_stream, stderr_stream = (
            await self.launch_instance(
                instance_name=name, image_digest=self.profile.image_digest,
                command=command, workspace_root=workspace.root, labels=labels,
                expected_manifest_digest=getattr(workspace, "manifest_digest", ""),
            )
        )
        return await self.collect_result(
            container_id=container_id, attach_proc=attach_proc,
            stdout_stream=stdout_stream, stderr_stream=stderr_stream,
            command=command, cancellation=cancellation,
            started=started, sandbox_instance_id=sandbox_instance_id or name,
            attestation_digest=attestation.attestation_digest,
        )

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
