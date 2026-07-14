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
class ImageAttestation:
    """Batch 3.1.3 §4 / Batch 3.1.5 §1: explicit image identity attestation model.

    Captures the full image identity proof with separately verifiable
    fields.  The image reference must be ``repository@sha256:digest``
    format.  ``docker create`` uses the full reference with
    ``--pull=never`` — no auto-pull is ever allowed.

    RepoDigests, local image/config ID, and container .Image are verified
    separately.  The registry manifest digest is NOT required to equal
    the local config image ID (they are different concepts).

    Batch 3.1.5 §1: ``content_digest`` is the canonical content digest
    excluding ``attested_at`` — it is stable across re-probes and enters
    the approved verification plan snapshot.  ``attestation_digest`` is
    retained as an alias for backward compatibility.
    """
    requested_image_reference: str       # repository@sha256:digest
    approved_repository_digest: str      # sha256:... (the approved digest)
    platform: str                        # e.g. "linux/amd64"
    platform_manifest_digest: str        # sha256:... (registry manifest)
    local_config_image_id: str           # from docker image inspect .Id
    container_image_id: str              # from docker inspect .Image
    repo_digests: tuple[str, ...]        # from docker image inspect .RepoDigests
    no_pull_proof: str                   # "--pull=never" confirmation
    attested_at: float                   # time.time() at attestation
    attestation_digest: str              # canonical digest binding all above
    # Batch 3.1.5 §1: explicit content digest (same value as attestation_digest,
    # which excludes attested_at).  This is the field that enters the approved
    # verification plan snapshot and the approval binding.
    content_digest: str = ""

    def __post_init__(self) -> None:
        # content_digest defaults to attestation_digest when not explicitly set.
        if not self.content_digest and self.attestation_digest:
            object.__setattr__(self, "content_digest", self.attestation_digest)


@dataclass(frozen=True)
class ContainerAttestation:
    """Batch 3.1.2 §4: image identity attestation for a created container.

    Batch 3.1.3 §4: now carries an explicit ``image_attestation_digest``
    binding to the ``ImageAttestation`` that was verified before
    ``docker create``.
    """
    container_id: str
    container_image_id: str          # from docker inspect .Image
    local_image_id: str              # from docker image inspect .Id
    expected_image_digest: str       # from profile (manifest digest)
    labels: dict[str, str]
    manifest_digest: str
    attestation_digest: str
    image_attestation_digest: str = ""  # Batch 3.1.3 §4: binds ImageAttestation


@dataclass(frozen=True)
class ToolchainAttestation:
    """Batch 3.1.2 §5: real toolchain attestation from an attestation container.

    Built inside a trusted, no-Workspace-mount attestation container by:
    opening the absolute executable path, confirming it is a regular file,
    computing its SHA-256, running the fixed version argv, parsing the
    output, and verifying the parsed version matches the approved version.

    The ``attestation_digest`` binds the toolchain identity to the actual
    image attestation and is re-verified before each verification launch.

    Batch 3.1.3 §5: ``image_attestation_digest`` explicitly binds the
    ``ImageAttestation`` that was in effect when the toolchain was
    attested.  This enters the Approval verification binding.
    """
    toolchain_id: str                # "{language}:{executable_id}"
    executable_path: str             # absolute path inside the container
    binary_digest: str               # sha256:<hex> of the executable file
    version_output_digest: str       # sha256:<hex> of the raw version output
    parsed_version: str              # parsed version string
    actual_image_attestation: str    # profile.image_digest used for attestation
    attested_at: float               # time.time() at attestation
    attestation_digest: str          # canonical digest binding all fields above
    image_attestation_digest: str = ""  # Batch 3.1.3 §5: binds ImageAttestation


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


@dataclass(frozen=True)
class ProductionVerificationConfig:
    """Batch 3.1.4 §2: typed configuration for production verification.

    Callers cannot pass backend instances to ``configure_trusted_verification``.
    The runtime constructs the exact ``DockerVerificationSandboxBackend``
    internally via a private factory using this config.

    The config carries only identity fields — the runtime already has
    access to the ``SandboxProfile``, artifact root, and workspace factory
    through the other ``configure_trusted_verification`` parameters.
    """
    artifact_storage_capability_id: str # ArtifactRootCapability identity
    snapshot_storage_capability_id: str # snapshot storage identity


class ProductionVerificationAuthority:
    """Batch 3.1.4 §2: authority that signs production backends.

    Batch 3.1.4 §2: now requires a runtime-issued factory marker to sign.
    The marker is an opaque object that only ``ApprovalRuntime``'s private
    factory possesses.  Ordinary objects cannot impersonate a production
    backend by setting ``_production_authority`` — they must also carry
    the correct ``_runtime_factory_marker``.

    The sign method verifies:
    - ``type(backend) is DockerVerificationSandboxBackend`` (exact type,
      not a subclass or duck-typed impersonator)
    - ``backend._runtime_factory_marker`` matches the factory marker

    Test backends do not pass through this authority and are rejected
    by the production runner.
    """

    def __init__(
        self, *, factory_marker: Any = None,
        authority_id: str = "khaos-production-v1",
    ) -> None:
        self._authority_id = authority_id
        self._factory_marker = factory_marker

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def sign(self, backend: Any) -> Any:
        """Attach the production authority marker to a backend.

        Batch 3.1.4 §2: verifies exact type and factory marker before
        signing.  Malicious objects that implement ``create_instance``
        / ``start_instance`` but are not exact
        ``DockerVerificationSandboxBackend`` instances are rejected.
        """
        if type(backend) is not DockerVerificationSandboxBackend:
            raise TypeError(
                "ProductionVerificationAuthority can only sign exact "
                "DockerVerificationSandboxBackend instances — subclasses "
                "and duck-typed impersonators are rejected"
            )
        if self._factory_marker is None:
            raise PermissionError(
                "ProductionVerificationAuthority requires a runtime-issued "
                "factory marker to sign backends"
            )
        actual_marker = getattr(backend, "_runtime_factory_marker", None)
        if actual_marker is not self._factory_marker:
            raise PermissionError(
                "backend was not constructed by the runtime's private factory"
            )
        object.__setattr__(backend, "_production_authority", self._authority_id)
        return backend

    @staticmethod
    def is_production_backend(backend: Any) -> bool:
        """Check whether a backend was signed by a ProductionVerificationAuthority."""
        return bool(getattr(backend, "_production_authority", None))

    @staticmethod
    def is_runtime_factory_backend(backend: Any) -> bool:
        """Batch 3.1.4 §2: check exact type + runtime factory marker."""
        if type(backend) is not DockerVerificationSandboxBackend:
            return False
        return bool(getattr(backend, "_runtime_factory_marker", None))


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
        # Batch 3.1.4 §4 / Batch 3.1.5 §1: accept both bare config ID
        # (sha256:...) and full repository@sha256:digest reference.  The
        # full reference is required for production probe_image_attestation;
        # the bare config ID is accepted for backward compatibility with
        # existing tests.  When ``requested_image_reference`` is set on
        # the profile, it takes precedence.
        effective_ref = profile.effective_image_reference
        if not (effective_ref.startswith("sha256:") or
                "@sha256:" in effective_ref):
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

    def build_toolchain_attestation_labels(
        self, *, instance_id: str, boot_id: str,
        image_attestation_digest: str, toolchain_id: str,
        probe_ordinal: int,
    ) -> dict[str, str]:
        """Batch 3.1.5 §3: build the full label set for a toolchain-attestation
        container.

        Every label is required so cross-boot reconciliation can attribute the
        container to a specific probe of a specific toolchain under a specific
        image attestation.  Missing any label is an ownership mismatch.
        """
        return {
            "khaos.kind": "toolchain-attestation",
            "khaos.sandbox-instance-id": instance_id,
            "khaos.boot-id": boot_id,
            "khaos.image-attestation-digest": image_attestation_digest[:63],
            "khaos.toolchain-id": toolchain_id[:63],
            "khaos.probe-ordinal": str(probe_ordinal),
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
        image_attestation: ImageAttestation | None = None,
    ) -> ContainerAttestation:
        """Batch 3.1.2 §4 / Batch 3.1.4 §4: inspect the created container and verify identity.

        Verifies:
        - All expected Khaos labels are present and match.
        - The container's ``.Image`` matches the approved
          ``local_config_image_id`` from the ``ImageAttestation``.
        - The workspace manifest digest label matches.

        Batch 3.1.4 §4: the registry manifest digest is NOT compared against
        the local config image ID — they are different concepts.  The
        container's ``.Image`` field is the local config image ID and must
        equal ``image_attestation.local_config_image_id``.

        Batch 3.1.4 §4: on any mismatch, the owned (not-yet-started)
        container is safely deleted before raising.  This prevents a
        mismatched container from being started.

        Returns a ``ContainerAttestation`` with all identity fields, bound
        to the ``ImageAttestation`` content digest.
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
                # Batch 3.1.4 §4: safe-delete the owned container before raising.
                await self._safe_delete_owned_container(
                    container_id_or_name, container_id,
                    reason="label-mismatch",
                )
                raise RuntimeError(
                    f"container label mismatch: {key} expected={expected_value} "
                    f"actual={actual_value}"
                )
        # Batch 3.1.4 §4: verify image identity using the approved
        # ImageAttestation.  The container's .Image must equal the approved
        # local_config_image_id.  We do NOT compare the manifest digest
        # against the local config image ID — they are different concepts.
        local_image_id = await self.inspect_image(expected_image_digest)
        if local_image_id is None:
            await self._safe_delete_owned_container(
                container_id_or_name, container_id,
                reason="local-image-not-found",
            )
            raise RuntimeError(
                f"local image not found: {expected_image_digest}"
            )
        # Batch 3.1.4 §4: if we have an approved ImageAttestation, the
        # container's .Image must match its local_config_image_id.  This is
        # the correct comparison — both are local config image IDs.
        approved_config_id = ""
        if image_attestation is not None:
            approved_config_id = image_attestation.local_config_image_id
            if approved_config_id and container_image_id and \
                    container_image_id != approved_config_id:
                await self._safe_delete_owned_container(
                    container_id_or_name, container_id,
                    reason="container-image-id-mismatch",
                )
                raise RuntimeError(
                    f"container .Image mismatch: container={container_image_id} "
                    f"approved={approved_config_id}"
                )
            # Also verify the local image inspect ID matches the approved
            # config ID (defensive — the image should not have changed
            # between attestation and container creation).
            if approved_config_id and local_image_id != approved_config_id:
                await self._safe_delete_owned_container(
                    container_id_or_name, container_id,
                    reason="local-image-id-drift",
                )
                raise RuntimeError(
                    f"local image ID drift: current={local_image_id} "
                    f"approved={approved_config_id}"
                )
        else:
            # No ImageAttestation (test backends) — fall back to verifying
            # container .Image matches the local image inspect ID.  This is
            # a same-concept comparison (both are config IDs).
            if container_image_id and container_image_id != local_image_id:
                await self._safe_delete_owned_container(
                    container_id_or_name, container_id,
                    reason="container-local-image-mismatch",
                )
                raise RuntimeError(
                    f"container image ID mismatch: container={container_image_id} "
                    f"local={local_image_id}"
                )
        # Verify manifest digest label.
        actual_manifest = container_labels.get("khaos.manifest-digest", "")
        if expected_manifest_digest and actual_manifest:
            if actual_manifest != expected_manifest_digest[:63]:
                await self._safe_delete_owned_container(
                    container_id_or_name, container_id,
                    reason="manifest-label-mismatch",
                )
                raise RuntimeError(
                    f"manifest digest label mismatch: expected="
                    f"{expected_manifest_digest[:63]} actual={actual_manifest}"
                )
        # Batch 3.1.4 §4: bind the ContainerAttestation to the approved
        # ImageAttestation content digest.  This enters the Approval binding.
        image_attestation_digest = ""
        if image_attestation is not None:
            image_attestation_digest = image_attestation.attestation_digest
        attestation_digest = hashlib.sha256(json.dumps({
            "container_id": container_id,
            "container_image_id": container_image_id,
            "local_image_id": local_image_id,
            "expected_image_digest": expected_image_digest,
            "labels": expected_labels,
            "manifest_digest": expected_manifest_digest,
            "image_attestation_digest": image_attestation_digest,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return ContainerAttestation(
            container_id=container_id,
            container_image_id=container_image_id,
            local_image_id=local_image_id,
            expected_image_digest=expected_image_digest,
            labels=dict(expected_labels),
            manifest_digest=expected_manifest_digest,
            attestation_digest=attestation_digest,
            image_attestation_digest=image_attestation_digest,
        )

    async def _safe_delete_owned_container(
        self, container_id_or_name: str, container_id: str, *,
        reason: str,
    ) -> None:
        """Batch 3.1.4 §4: safe-delete an owned, not-yet-started container.

        Called when a pre-launch mismatch is detected.  The container has
        been created but NOT started — no project code has run.  We
        terminate and remove it so it doesn't linger as an orphan.

        Failures are logged but do not mask the original mismatch error.
        """
        try:
            await self.terminate_and_remove_instance(
                container_id or container_id_or_name,
            )
        except Exception:
            # Best-effort cleanup — the mismatch error is the real signal.
            pass

    async def start_instance(self, container_id_or_name: str) -> None:
        """Batch 3.1.2 §1: ``docker start`` the created container.

        Batch 3.1.4 §1: this method is NOT used in the production
        start-and-capture path — it starts the container without
        capturing output, creating a race where fast-exiting containers
        lose their stdout/stderr before ``attach_instance`` connects.
        Use :meth:`start_and_attach_instance` instead.
        """
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

        Batch 3.1.4 §1: this method is NOT used in the production path
        because it races with container exit.  Use
        :meth:`start_and_attach_instance` instead.

        Returns (process, stdout_reader, stderr_reader).  The process
        completes when the container exits and the streams are drained.
        """
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "attach", "--no-stdin",
            container_id_or_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        return process, process.stdout, process.stderr

    async def start_and_attach_instance(
        self, container_id_or_name: str,
    ) -> tuple[asyncio.subprocess.Process, Any, Any]:
        """Batch 3.1.4 §1: atomically start and attach to capture output.

        Uses ``docker start --attach`` to establish the output pipe BEFORE
        PID 1 executes, eliminating the start→attach race where
        fast-exiting containers lose their output.

        The ``--attach`` flag ensures stdout/stderr are connected in the
        same operation that starts the container, so no byte is lost even
        if PID 1 exits in the first millisecond.

        ``stdin`` is connected to ``DEVNULL`` (equivalent to
        ``--no-stdin``) to prevent the container from blocking on stdin.

        Returns ``(process, stdout_reader, stderr_reader)``.  The process
        completes when the container exits and the streams are drained.
        """
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "start", "--attach",
            container_id_or_name,
            stdin=asyncio.subprocess.DEVNULL,
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
        """Batch 3.1.3 §3: non-destructive reconciliation.

        Only containers matching ALL expected labels are terminated+removed.
        Partial matches (khaos.* labels but not all expected) are reported
        as ``unknown`` and NEVER terminated.  Empty expected_labels is
        explicitly rejected — two different Khaos Runtimes must not delete
        each other's containers.
        """
        if not expected_labels:
            raise ValueError("reconcile_instances requires non-empty expected_labels")
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

    async def list_unknown_khaos_containers(self) -> list[dict[str, Any]]:
        """Batch 3.1.3 §3: list containers with khaos.* labels.

        This API ONLY lists — it never terminates or removes.  The caller
        must decide what to do with each container.  Unknown containers
        from a different Khaos Runtime must not be affected.
        """
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "ps", "-a",
            "--filter", "label=khaos.run-id",
            "--format", "{{.Names}}\t{{.Labels}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        results: list[dict[str, Any]] = []
        for line in stdout.decode("utf-8", "replace").splitlines():
            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            label_str = parts[1].strip()
            labels: dict[str, str] = {}
            for pair in label_str.split(","):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    labels[k.strip()] = v.strip()
            results.append({"name": name, "labels": labels})
        return results

    async def reconcile_instance_by_record(
        self, *, container_id: str, instance_name: str,
        expected_labels: dict[str, str],
        expected_image_digest: str, expected_manifest_digest: str,
    ) -> dict[str, Any]:
        """Batch 3.1.3 §3: non-destructive reconciliation by DB record.

        Only when ALL ownership evidence matches (container ID/name, run
        ID, step ID, instance ID, boot ID, manifest digest, image) is the
        container terminated and removed.

        On ANY mismatch (label, image, manifest, name, or ID):
        - NEVER terminate
        - NEVER remove
        - Return ``OWNERSHIP_MISMATCH``
        - The caller must mark Runtime not-ready and record Audit/quarantine.
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
        # §3: verify ALL labels — any mismatch → OWNERSHIP_MISMATCH (no terminate).
        container_labels: dict[str, str] = {}
        for key, value in info.get("Config", {}).get("Labels", {}).items():
            container_labels[key] = value
        for key, expected_value in expected_labels.items():
            actual_value = container_labels.get(key)
            if actual_value != expected_value:
                return {
                    "status": "ownership-mismatch", "container_id": actual_id,
                    "reason": f"label-mismatch:{key}",
                }
        # §3: verify image — mismatch → OWNERSHIP_MISMATCH (no terminate).
        container_image = info.get("Image", "")
        if container_image and expected_image_digest and container_image != expected_image_digest:
            return {
                "status": "ownership-mismatch", "container_id": actual_id,
                "reason": f"image-mismatch:{container_image}!={expected_image_digest}",
            }
        # §3: verify manifest digest label.
        actual_manifest = container_labels.get("khaos.manifest-digest", "")
        if expected_manifest_digest and actual_manifest:
            expected_truncated = expected_manifest_digest[:63]
            if actual_manifest != expected_truncated:
                return {
                    "status": "ownership-mismatch", "container_id": actual_id,
                    "reason": f"manifest-mismatch:{actual_manifest}!={expected_truncated}",
                }
        # Full ownership proof — terminate and remove.
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
        """Batch 3.1.5 §1: verify the local image exists and return its config ID.

        This method NO LONGER conflates the local config image ID with the
        repository manifest digest.  It simply verifies the image exists
        locally (via ``image inspect``) and returns the local config ID
        (``.Id``).  The full identity attestation is performed by
        ``probe_image_attestation()``, which verifies RepoDigests, platform,
        and local config ID separately.

        The old comparison ``actual != self.profile.image_digest`` is
        removed — it conflated the local config ID (``sha256:...``) with
        the repository reference (``repository@sha256:...``), which are
        different concepts.
        """
        image_reference = self.profile.effective_image_reference
        actual = await self.inspect_image(image_reference)
        if actual is None:
            raise RuntimeError(
                f"production sandbox image unavailable (not pulled): "
                f"{image_reference}"
            )
        return actual

    async def probe_image_attestation(self) -> ImageAttestation:
        """Batch 3.1.3 §4 / Batch 3.1.4 §4 / Batch 3.1.5 §1: probe and attest
        the local image identity.

        Produces an ``ImageAttestation`` with all identity fields verified
        separately:
        - RepoDigests from ``docker image inspect .RepoDigests``
        - Local config image ID from ``docker image inspect .Id``
        - Platform from ``docker image inspect .Os``/``.Architecture``
        - No-pull proof: the probe uses ``image inspect`` (never ``pull``)

        Batch 3.1.4 §4: the registry manifest digest and local config image
        ID are NOT the same concept and are NOT compared against each other.
        The ``requested_image_reference`` must be in ``repository@sha256:digest``
        format.  ``approved_repository_digest`` is extracted from RepoDigests
        and verified to be present.  ``platform_manifest_digest`` is kept
        separate from ``requested_image_reference`` — for multi-arch images
        the registry manifest list digest differs from the platform-specific
        manifest digest.

        Batch 3.1.5 §1: uses ``profile.effective_image_reference`` which
        prefers ``requested_image_reference`` (production) over
        ``image_digest`` (test compatibility).  When ``approved_platform``
        is set on the profile, the probed platform must match.
        """
        image_reference = self.profile.effective_image_reference
        # Batch 3.1.4 §4: production image reference must include repository
        # and @sha256 — a bare tag or config ID is not acceptable because
        # it cannot be pinned immutably.
        if "@" not in image_reference or "sha256:" not in image_reference:
            raise RuntimeError(
                f"production image reference must be repository@sha256:digest, "
                f"got: {image_reference}"
            )
        # Extract the manifest digest from the reference (the part after @).
        reference_manifest_digest = image_reference.split("@", 1)[1]
        # Full image inspect for all fields.
        process = await asyncio.create_subprocess_exec(
            str(self._docker), "image", "inspect", image_reference,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                f"image inspect failed for {image_reference}: "
                f"{stderr.decode('utf-8', 'replace')}"
            )
        try:
            info_list = json.loads(stdout.decode("utf-8", "replace"))
            info = info_list[0] if isinstance(info_list, list) and info_list else {}
        except (json.JSONDecodeError, IndexError, TypeError):
            info = {}
        local_config_image_id = info.get("Id", "")
        os_name = info.get("Os", "linux")
        architecture = info.get("Architecture", "amd64")
        platform = f"{os_name}/{architecture}"
        repo_digests = tuple(info.get("RepoDigests", []) or [])
        # Batch 3.1.4 §4: extract the approved repository digest from
        # RepoDigests and verify it is present.  RepoDigests entries have
        # the format ``repository@sha256:digest`` — the digest part is the
        # registry manifest digest that the repository has signed.
        approved_repository_digest = ""
        for rd in repo_digests:
            if "@" not in rd:
                continue
            rd_repo, rd_digest = rd.split("@", 1)
            # Match by repository name (the part before @) — the reference
            # may use a different tag but the repository must match.
            ref_repo = image_reference.split("@", 1)[0]
            # Strip tag from ref_repo if present (it won't have one in
            # repository@sha256 format, but be defensive).
            if rd_repo == ref_repo and rd_digest == reference_manifest_digest:
                approved_repository_digest = rd_digest
                break
        if not approved_repository_digest:
            raise RuntimeError(
                f"approved repository digest not found in RepoDigests: "
                f"reference={image_reference} repo_digests={list(repo_digests)}"
            )
        # Batch 3.1.5 §1: verify local config ID is non-empty.
        if not local_config_image_id:
            raise RuntimeError(
                f"local config image ID is empty for {image_reference}"
            )
        # Batch 3.1.5 §1: when the profile specifies approved_platform,
        # the probed platform must match.
        if self.profile.approved_platform and platform != self.profile.approved_platform:
            raise RuntimeError(
                f"platform mismatch: approved={self.profile.approved_platform} "
                f"actual={platform}"
            )
        attested_at = time.time()
        # Batch 3.1.4 §4: platform_manifest_digest is the registry manifest
        # digest for the approved platform.  For single-arch images this is
        # the same as the reference digest; for multi-arch images it is the
        # platform-specific manifest digest (resolved by the runtime).  We
        # use the reference digest here — the key invariant is that it is
        # NOT compared against local_config_image_id.
        platform_manifest_digest = reference_manifest_digest
        # Batch 3.1.4 §3: attestation_digest must NOT include attested_at —
        # it's per-probe metadata that doesn't represent supply chain content.
        # The same image must produce the same digest across re-probes.
        attestation_digest = hashlib.sha256(json.dumps({
            "requested_image_reference": image_reference,
            "approved_repository_digest": approved_repository_digest,
            "platform": platform,
            "platform_manifest_digest": platform_manifest_digest,
            "local_config_image_id": local_config_image_id,
            "repo_digests": list(repo_digests),
            "no_pull_proof": "image-inspect-not-pull",
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return ImageAttestation(
            requested_image_reference=image_reference,
            approved_repository_digest=approved_repository_digest,
            platform=platform,
            platform_manifest_digest=platform_manifest_digest,
            local_config_image_id=local_config_image_id,
            container_image_id="",  # filled after container create
            repo_digests=repo_digests,
            no_pull_proof="image-inspect-not-pull",
            attested_at=attested_at,
            attestation_digest=attestation_digest,
        )

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
        toolchain_id: str = "",
        probe_ordinal: int = 0,
        image_attestation_digest: str = "",
    ) -> tuple[int, bytes, bytes]:
        """Batch 3.1.4 §5 / Batch 3.1.5 §3: run a persistent attestation
        container and capture output.

        Batch 3.1.5 §3: when ``_verification_store`` and ``_boot_context`` are
        set (production runtime), the full durable lifecycle is persisted:

            PREPARED → docker create → inspect image/labels
            → durable actual container ID → CREATED_ATTESTED
            → start --attach → RUNNING → capture
            → terminate/remove → absence proof → TERMINATED

        The container has:
        - No Workspace mount (can only read the image's own filesystem)
        - network=none
        - read-only root
        - No host credentials
        - Full toolchain-attestation label set for cross-boot attribution

        The container is always terminated and removed after output is
        captured, even on timeout.  The attestation result is only durable
        after the container absence proof (TERMINATED state persisted).
        """
        instance_name = self.generate_instance_name()
        labels = self.build_toolchain_attestation_labels(
            instance_id="",  # filled below after ID generation
            boot_id="",
            image_attestation_digest=image_attestation_digest,
            toolchain_id=toolchain_id,
            probe_ordinal=probe_ordinal,
        )
        store = getattr(self, "_verification_store", None)
        boot = getattr(self, "_boot_context", None)
        image_attestation = getattr(self, "_image_attestation", None)
        use_persistent = store is not None and boot is not None
        sandbox_instance_id = ""
        if use_persistent:
            # Batch 3.1.5 §3: persist PREPARED row BEFORE docker create.
            import secrets as _sec
            import time as _time
            from khaos.coding.planning.verification_sandbox_instance import (
                SandboxInstanceState, VerificationSandboxInstance,
            )
            sandbox_instance_id = f"vsi_{_sec.token_hex(12)}"
            labels = self.build_toolchain_attestation_labels(
                instance_id=sandbox_instance_id,
                boot_id=boot.boot_id,
                image_attestation_digest=image_attestation_digest,
                toolchain_id=toolchain_id,
                probe_ordinal=probe_ordinal,
            )
            instance = VerificationSandboxInstance(
                sandbox_instance_id=sandbox_instance_id,
                verification_run_id="",
                step_run_id="",
                backend_id=getattr(self, "BACKEND_ID", "docker-verification"),
                backend_instance_name=instance_name,
                runtime_epoch=boot.server_epoch,
                boot_id=boot.boot_id,
                image_reference=image_digest,
                expected_image_digest=image_digest,
                state=SandboxInstanceState.PREPARED,
                instance_kind="toolchain-attestation",
                toolchain_id=toolchain_id,
                probe_ordinal=probe_ordinal,
                image_attestation_digest=image_attestation_digest,
            )
            store.create_sandbox_instance(instance)
        args = [
            str(self._docker), "create", "--pull=never", "--name", instance_name,
            "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.profile.pids_limit),
            "--memory", str(self.profile.memory_bytes),
            "--cpus", str(self.profile.cpu_count),
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        ]
        for key, value in labels.items():
            args.extend(("--label", f"{key}={value}"))
        args.extend((image_digest, *argv))
        create_proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        create_stdout, create_stderr = await create_proc.communicate()
        if create_proc.returncode != 0:
            if use_persistent:
                from khaos.coding.planning.verification_sandbox_instance import (
                    SandboxInstanceState,
                )
                store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATED,
                    cleanup_status="absent",
                    failure_code="docker-create-failed",
                    terminated_at=_time.time(),
                )
            raise RuntimeError(
                f"attestation docker create failed (exit {create_proc.returncode}): "
                f"{create_stderr.decode('utf-8', 'replace')}"
            )
        container_id = create_stdout.decode("utf-8", "replace").strip()
        if not container_id:
            if use_persistent:
                from khaos.coding.planning.verification_sandbox_instance import (
                    SandboxInstanceState,
                )
                store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATED,
                    cleanup_status="absent",
                    failure_code="docker-create-no-id",
                    terminated_at=_time.time(),
                )
            raise RuntimeError("attestation docker create produced no container ID")
        if use_persistent:
            # Batch 3.1.5 §3: inspect image/labels → durable actual container
            # ID → CREATED_ATTESTED.  Verify the container's image matches the
            # approved local_config_image_id and all expected labels are present.
            from khaos.coding.planning.verification_sandbox_instance import (
                SandboxInstanceState,
            )
            import time as _t
            try:
                info = await self.inspect_instance(container_id)
                if info is None:
                    raise RuntimeError("attestation container inspect returned None")
                actual_image = info.get("Image", "")
                container_labels = info.get("Config", {}).get("Labels", {}) or {}
                for lk, lv in labels.items():
                    if container_labels.get(lk) != lv:
                        raise RuntimeError(
                            f"attestation container label mismatch: "
                            f"{lk} expected={lv!r} actual={container_labels.get(lk)!r}"
                        )
                if image_attestation is not None:
                    approved_id = getattr(image_attestation, "local_config_image_id", "")
                    if approved_id and actual_image != approved_id:
                        raise RuntimeError(
                            f"attestation container image mismatch: "
                            f"actual={actual_image!r} approved={approved_id!r}"
                        )
            except Exception:
                # Inspect failed — clean up via persistent lifecycle.
                try:
                    await self.terminate_and_remove_instance(container_id)
                except Exception:
                    pass
                store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.CLEANUP_FAILED,
                    failure_code="attestation-inspect-mismatch",
                )
                raise
            # Persist CREATED_ATTESTED with the durable container ID.
            store.persist_created_instance(
                sandbox_instance_id,
                container_id=container_id,
                attestation_digest="",
                actual_image_digest=actual_image,
                actual_container_image_id=actual_image,
            )
        # Batch 3.1.4 §1/§5: docker start --attach captures output atomically.
        attach_proc = await asyncio.create_subprocess_exec(
            str(self._docker), "start", "--attach", container_id,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        if use_persistent:
            from khaos.coding.planning.verification_sandbox_instance import (
                SandboxInstanceState,
            )
            import time as _t2
            store.update_sandbox_instance(
                sandbox_instance_id,
                state=SandboxInstanceState.RUNNING,
                started_at=_t2.time(),
            )
        try:
            stdout, stderr = await asyncio.wait_for(
                attach_proc.communicate(), timeout=timeout_seconds,
            )
            exit_code = attach_proc.returncode
        except asyncio.TimeoutError:
            try:
                attach_proc.kill()
            except ProcessLookupError:
                pass
            # Batch 3.1.4 §5: terminate and remove the container on timeout.
            _, removed_ok = await self.terminate_and_remove_instance(container_id)
            if use_persistent:
                from khaos.coding.planning.verification_sandbox_instance import (
                    SandboxInstanceState,
                )
                import time as _t3
                if removed_ok:
                    store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.TERMINATED,
                        cleanup_status="absent",
                        terminated_at=_t3.time(),
                        failure_code="attestation-timeout",
                    )
                else:
                    store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.CLEANUP_FAILED,
                        failure_code="attestation-timeout-cleanup-failed",
                    )
            raise RuntimeError(
                f"attestation container timed out: argv={argv}"
            )
        # Batch 3.1.4 §5: always terminate and remove the container after
        # output is captured.  No --rm containers — persistent lifecycle.
        _, removed_ok = await self.terminate_and_remove_instance(container_id)
        if use_persistent:
            from khaos.coding.planning.verification_sandbox_instance import (
                SandboxInstanceState,
            )
            import time as _t4
            # Batch 3.1.5 §3: absence proof — only persist TERMINATED after
            # terminate_and_remove_instance confirms the container is gone.
            if removed_ok:
                store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATED,
                    cleanup_status="absent",
                    terminated_at=_t4.time(),
                )
            else:
                # Absence proof failed — try confirm_instance_gone as fallback.
                try:
                    gone = await self.confirm_instance_gone(container_id)
                except Exception:
                    gone = False
                if gone:
                    store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.TERMINATED,
                        cleanup_status="absent",
                        terminated_at=_t4.time(),
                    )
                else:
                    store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.CLEANUP_FAILED,
                        failure_code="attestation-cleanup-failed",
                    )
        return exit_code, stdout, stderr

    async def attest_toolchain(
        self, *, toolchain: TrustedToolchain, image_digest: str,
        image_attestation_digest: str = "",
    ) -> ToolchainAttestation:
        """Batch 3.1.2 §5: attest one toolchain inside an attestation container.

        Runs a no-Workspace-mount container with the pinned image, opens
        the absolute executable path, confirms it is a regular file,
        computes its SHA-256, runs the fixed version argv, parses the
        output, and returns a :class:`ToolchainAttestation`.

        Does NOT trust the workspace executable — only the image's own
        filesystem is visible to the attestation container.

        Batch 3.1.3 §5: ``image_attestation_digest`` binds the
        ``ImageAttestation`` that was in effect when the toolchain was
        attested.  This enters the Approval verification binding.
        """
        # Batch 3.1.3 §5: use the toolchain's fixed version argv if declared,
        # otherwise fall back to the backend's _VERSION_ARGV table.
        version_argv = toolchain.version_argv or self._VERSION_ARGV.get(toolchain.executable_id)
        if version_argv is None:
            raise RuntimeError(
                f"toolchain {toolchain.executable_id} has no fixed version argv"
            )
        # Batch 3.1.5 §3: toolchain_id is needed for persistent instance labels.
        toolchain_id = f"{toolchain.language}:{toolchain.executable_id}"
        # 1. Compute binary SHA-256 using sha256sum inside the container.
        #    sha256sum is part of coreutils and present in most images;
        #    if absent, attestation fails closed.
        digest_rc, digest_out, digest_err = await self._run_attestation_command(
            image_digest=image_digest,
            argv=("sha256sum", toolchain.absolute_path),
            toolchain_id=toolchain_id,
            probe_ordinal=0,
            image_attestation_digest=image_attestation_digest,
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
            toolchain_id=toolchain_id,
            probe_ordinal=1,
            image_attestation_digest=image_attestation_digest,
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
            toolchain_id=toolchain_id,
            probe_ordinal=2,
            image_attestation_digest=image_attestation_digest,
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
        # Batch 3.1.4 §3: attestation_digest must NOT include attested_at —
        # it's per-probe metadata that doesn't represent supply chain content.
        attestation_digest = hashlib.sha256(json.dumps({
            "toolchain_id": toolchain_id,
            "executable_path": toolchain.absolute_path,
            "binary_digest": binary_digest,
            "version_output_digest": version_output_digest,
            "parsed_version": parsed_version,
            "actual_image_attestation": image_digest,
            "image_attestation_digest": image_attestation_digest,
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
            image_attestation_digest=image_attestation_digest,
        )

    async def attest_toolchains(
        self, *, toolchains: tuple[TrustedToolchain, ...],
        image_digest: str, image_attestation_digest: str = "",
    ) -> tuple[ToolchainAttestation, ...]:
        """Batch 3.1.2 §5: attest all toolchains for the pinned image.

        Returns a tuple of :class:`ToolchainAttestation` in the same order
        as the input toolchains.  Any failure raises and the caller must
        NOT install the verifier (fail-closed).

        Batch 3.1.3 §5: ``image_attestation_digest`` binds the
        ``ImageAttestation`` to each toolchain attestation.
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
                image_attestation_digest=image_attestation_digest,
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
        image_attestation: ImageAttestation | None = None,
    ) -> tuple[str, ContainerAttestation, asyncio.subprocess.Process, Any, Any]:
        """Batch 3.1.2 §1: create + inspect_and_attest + start_and_attach.

        Batch 3.1.4 §1: uses ``docker start --attach --no-stdin`` instead
        of separate ``docker start`` + ``docker attach`` to eliminate the
        output race where fast-exiting containers lose their stdout/stderr.

        Batch 3.1.4 §4: passes the approved ``ImageAttestation`` to
        ``inspect_and_attest_instance`` so the container's ``.Image`` is
        verified against the approved ``local_config_image_id`` (not the
        registry manifest digest).

        Returns ``(container_id, attestation, attach_proc, stdout_stream,
        stderr_stream)``.  The caller MUST persist ``container_id`` and
        ``attestation`` BEFORE calling :meth:`collect_result`, so that a
        crash between launch and collect leaves a durable trail.

        No project code runs during ``docker create``.  ``docker start
        --attach`` begins the entrypoint and establishes the output pipe
        atomically — no byte is lost even if PID 1 exits immediately.
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
            image_attestation=image_attestation,
        )
        # 3. docker start --attach --no-stdin (atomic start + output capture)
        attach_proc, stdout_stream, stderr_stream = (
            await self.start_and_attach_instance(container_id)
        )
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

        Batch 3.1.4 §1: two critical fixes:
        1. Uses ``attach_proc.wait()`` instead of a separate ``docker wait``
           when ``attach_proc`` is available.  ``docker start --attach``
           returns the container's exit code as its own exit code, so there
           is no need for a separate ``docker wait`` call that races with
           container startup.
        2. Streams are fully read BEFORE killing the attach process.  The
           previous code killed ``attach_proc`` in a ``finally`` block
           before awaiting the stream read tasks, causing output loss.

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
        # Batch 3.1.4 §1: use attach_proc.wait() when available — the
        # docker start --attach process's returncode IS the container's
        # exit code.  This eliminates the race where docker wait returns
        # before the container is fully started.
        if attach_proc is not None:
            wait_task = asyncio.create_task(attach_proc.wait())
        else:
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
            # Batch 3.1.4 §1: read streams BEFORE killing attach_proc.
            # The docker start --attach process holds the output pipes;
            # killing it before draining causes output loss.
            stdout, stdout_truncated = await stdout_task
            stderr, stderr_truncated = await stderr_task
        finally:
            if cancel_task:
                cancel_task.cancel()
            if attach_proc is not None:
                try:
                    attach_proc.kill()
                except ProcessLookupError:
                    pass
            # Cancel stream tasks if they haven't completed (e.g. exception).
            stdout_task.cancel()
            stderr_task.cancel()
        stdout = self._redact(stdout)
        stderr = self._redact(stderr)
        if remove:
            await self.remove_instance(container_id)
        return SandboxStepResult(
            sandbox_instance_id, self.profile.effective_image_reference,
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
                instance_name=name, image_digest=self.profile.effective_image_reference,
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
