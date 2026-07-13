"""Orchestrates approved verification without Agent tools or host execution."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from khaos.coding.planning.approval.models import compute_verification_digest
from khaos.coding.planning.execution_models import ExecutionRunStatus
from khaos.coding.planning.git_state import GitStateInspector
from khaos.coding.planning.trusted_verification import (
    ArtifactRootCapability, SandboxProfile, TrustedCommandFactory,
    VerificationWorkspaceFactory,
)
from khaos.coding.planning.verification_catalog import VerificationCatalog
from khaos.coding.planning.verification_execution_models import (
    DisposableWorkspaceRecord, DisposableWorkspaceState,
    VerificationExecutionRun, VerificationPhaseContext, VerificationResult,
    VerificationRunStatus, VerificationStepRun, VerificationStepStatus,
    verification_plan_digest,
)
from khaos.coding.planning.verification_sandbox import VerificationSandboxBackend
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)
from khaos.coding.planning.verification_store import VerificationExecutionStore


# Batch 3.1.2 §8: conservative default for files verification may generate.
# These are cache/build byproducts that don't affect verification integrity.
_DEFAULT_ALLOWED_GENERATED_OUTPUT = (
    "__pycache__/*",
    "*.pyc",
    ".pytest_cache/*",
    ".coverage",
    ".mypy_cache/*",
    ".ruff_cache/*",
    "node_modules/*",
    ".tox/*",
    "build/*",
    "dist/*",
    "*.egg-info/*",
    "target/*",
    ".next/*",
    ".nuxt/*",
)


class TrustedVerificationRunner:
    """Single production entry for planned verification execution."""

    def __init__(
        self,
        *,
        approval_store: Any,
        plan_repository: Any,
        workspace_manager: Any,
        context_provider: Any,
        backend: VerificationSandboxBackend,
        command_factory: TrustedCommandFactory,
        workspace_factory: VerificationWorkspaceFactory,
        artifact_root: Path,
        profile: SandboxProfile,
        runtime_boot: Any,
        context_registry: dict[str, VerificationPhaseContext],
        mutation_fence: Any,
        artifact_ttl_seconds: float = 24 * 3600,
        toolchain_attestations: tuple = (),
    ) -> None:
        # Batch 3.1.3 §5: production backends must be signed by an explicit
        # ProductionVerificationAuthority — not by module-name heuristics.
        from khaos.coding.planning.verification_sandbox import (
            ProductionVerificationAuthority,
        )
        if not ProductionVerificationAuthority.is_production_backend(backend):
            raise TypeError(
                "backend was not signed by a ProductionVerificationAuthority; "
                "test or unsigned backends cannot be used in the production runner"
            )
        self._store = VerificationExecutionStore(approval_store)
        self._approval_store = approval_store
        self._plans = plan_repository
        self._workspaces = workspace_manager
        self._context_provider = context_provider
        self._backend = backend
        self._commands = command_factory
        self._workspace_factory = workspace_factory
        self._artifact_root = artifact_root.resolve()
        # Batch 3.1.2 §7: open the artifact root as a capability with
        # O_DIRECTORY|O_NOFOLLOW and dir_fd-only access.  All artifact
        # writes use the no-replace protocol (temp → link → fsync).
        _forbidden: list[Path] = []
        _db_path = getattr(self._approval_store, "_db_path", None)
        if _db_path:
            _forbidden.append(Path(_db_path))
        self._artifact_capability = ArtifactRootCapability.open(
            self._artifact_root, forbidden_roots=tuple(_forbidden),
        )
        self._profile = profile
        self._boot = runtime_boot
        self._contexts = context_registry
        self._fence = mutation_fence
        self._git = GitStateInspector()
        self._artifact_ttl = artifact_ttl_seconds
        # Batch 3.1.2 §5: toolchain attestations from configure_trusted_verification.
        # Re-verified before each launch_instance to detect binary replacement
        # after configuration (re-bind attestation digest at execution time).
        self._toolchain_attestations: dict[str, Any] = {
            attestation.toolchain_id: attestation
            for attestation in toolchain_attestations
        }
        self._store.recover_interrupted()
        # Batch 3.1.2 §8: reconcile disposable workspaces from previous boots.
        self._reconcile_disposable_workspaces()
        # Batch 3.1.3 §7: reconcile artifact root orphans before runtime readiness.
        self._reconcile_artifacts()

    # ------------------------------------------------------------------
    # Batch 3.1.3 §2: Real cleanup states for sandbox instances
    # ------------------------------------------------------------------

    async def _cleanup_sandbox_instance(
        self, sandbox_instance_id: str, container_id_or_name: str,
    ) -> None:
        """Batch 3.1.3 §2: attempt cleanup after a lifecycle failure.

        Marks CLEANUP_PENDING, attempts terminate_and_remove, and only
        marks TERMINATED if the container is confirmed gone.  On failure,
        marks CLEANUP_FAILED — never guesses the container is gone.
        """
        self._store.update_sandbox_instance(
            sandbox_instance_id,
            state=SandboxInstanceState.CLEANUP_PENDING,
            failure_code="cleanup-after-lifecycle-failure",
        )
        if not container_id_or_name:
            # No container was created — nothing to clean up.
            self._store.update_sandbox_instance(
                sandbox_instance_id,
                state=SandboxInstanceState.TERMINATED,
                terminated_at=time.time(),
            )
            return
        try:
            terminated_ok, removed_ok = (
                await self._backend.terminate_and_remove_instance(container_id_or_name)
            )
        except Exception:
            removed_ok = False
        if removed_ok:
            self._store.update_sandbox_instance(
                sandbox_instance_id,
                state=SandboxInstanceState.TERMINATED,
                terminated_at=time.time(),
            )
        else:
            # Best-effort: try to confirm gone via inspect.
            try:
                gone = await self._backend.confirm_instance_gone(container_id_or_name)
            except Exception:
                gone = False
            if gone:
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATED,
                    terminated_at=time.time(),
                )
            else:
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.CLEANUP_FAILED,
                    failure_code="cleanup-failed-after-lifecycle-failure",
                )

    # ------------------------------------------------------------------
    # Batch 3.1.2 §8: Disposable workspace reconciliation
    # ------------------------------------------------------------------

    def _reconcile_disposable_workspaces(self) -> None:
        """Reconcile non-terminal disposable workspaces from previous boots.

        Batch 3.1.3 §6: handles PREPARED rows (crash during copy) by
        using the PREPARED row to locate and safely clean up the partial
        directory.  PREPARED rows have an empty manifest — the directory
        may contain partially-copied files that are not in any manifest.

        For each active workspace:
        - Reconstruct root_path from factory root + instance_id.
        - If root_path no longer exists → mark CLEANED (already gone).
        - If root_path exists:
          - PREPARED state → force-remove the partial directory (the
            PREPARED row proves we own this directory).
          - SEALED/MOUNTED state → attempt destroy with manifest.
          - Failure → mark CLEANUP_FAILED + poison workspace scope.
        """
        from khaos.coding.planning.trusted_verification import (
            DisposableVerificationWorkspace, ManifestEntry,
        )
        import shutil as _shutil
        factory_root = self._workspace_factory._root
        for record in self._store.list_active_disposable_workspaces():
            root = factory_root / record.instance_id
            if not root.exists():
                self._store.mark_disposable_workspace_cleaned(record.workspace_id)
                continue
            # Batch 3.1.3 §6: PREPARED rows have an empty manifest.
            # The directory was partially created — we own it (the row
            # proves it) and can force-remove it safely.
            if record.state == DisposableWorkspaceState.PREPARED:
                try:
                    _shutil.rmtree(root)
                    self._store.mark_disposable_workspace_cleaned(record.workspace_id)
                except Exception:
                    self._store.mark_disposable_workspace_cleanup_failed(
                        record.workspace_id, failure_code="prepared-cleanup-failed",
                    )
                    try:
                        self._approval_store.add_workspace_poison_scope(
                            record.verification_run_id,
                            owner=f"verification-cleanup:{record.workspace_id}",
                            reason="disposable-workspace-cleanup-failed",
                        )
                    except Exception:
                        pass
                continue
            # Reconstruct the workspace object from the persisted record.
            try:
                manifest_entries = tuple(
                    ManifestEntry(
                        path=entry["path"],
                        content_hash=entry["content_hash"],
                        mode=entry["mode"],
                    )
                    for entry in json.loads(record.manifest_json)
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                manifest_entries = ()
            workspace = DisposableVerificationWorkspace(
                instance_id=record.instance_id,
                root=root,
                manifest=manifest_entries,
                manifest_digest=record.manifest_digest,
                source_root="",
                allowed_generated_output=record.allowed_generated_output,
            )
            try:
                self._workspace_factory.destroy(workspace)
            except Exception:
                self._store.mark_disposable_workspace_cleanup_failed(
                    record.workspace_id, failure_code="reconcile-cleanup-failed",
                )
                try:
                    self._approval_store.add_workspace_poison_scope(
                        record.verification_run_id,
                        owner=f"verification-cleanup:{record.workspace_id}",
                        reason="disposable-workspace-cleanup-failed",
                    )
                except Exception:
                    pass
            else:
                self._store.mark_disposable_workspace_cleaned(record.workspace_id)

    # ------------------------------------------------------------------
    # Batch 3.1.3 §7: Artifact root orphan recovery
    # ------------------------------------------------------------------

    def _reconcile_artifacts(self) -> None:
        """Reconcile artifact root files against DB rows before runtime readiness.

        Batch 3.1.3 §7: the artifact root may contain orphan files,
        incomplete writes, or sealed artifacts whose final file was
        deleted or corrupted after a crash.  This method:

        1. Reads all RESERVED and SEALED rows from the DB.
        2. Calls ``ArtifactRootCapability.reconcile()`` to compare the
           expected artifacts against the actual files on disk.
        3. For each category returned by the reconcile report:
           - ``reserved_no_file`` → quarantine (incomplete reserve).
           - ``reserved_temp``    → cleanup_orphan temp + quarantine.
           - ``reserved_final``   → quarantine (cannot verify without digest).
           - ``sealed_missing``   → quarantine (file deleted after sealing).
           - ``unknown_files``    → cleanup_orphan (orphan file).
           - ``cleanup_failed``   → poison the owning verification run.
        4. For SEALED artifacts with a final file present, re-verify the
           content digest and byte length.  Any mismatch → quarantine.
        5. If any artifact could not be cleaned up, poison the owning
           verification run so it cannot reach a terminal success state.
        """
        all_rows = self._store.list_all_artifacts()
        expected = tuple(
            (row["artifact_id"], row["status"], int(row["byte_length"]))
            for row in all_rows
        )
        try:
            report = self._artifact_capability.reconcile(
                expected_artifacts=expected,
            )
        except PermissionError:
            # Non-regular file in the artifact root — fail-closed by
            # poisoning every active verification run.  The root is not
            # safe to use until an operator inspects it.
            for row in all_rows:
                try:
                    self._approval_store.add_workspace_poison_scope(
                        row["verification_run_id"],
                        owner="verification-cleanup:artifact-root",
                        reason="artifact-root-non-regular-file",
                    )
                except Exception:
                    pass
            raise
        # Index rows by artifact_id for digest verification.
        rows_by_id = {row["artifact_id"]: row for row in all_rows}
        cleanup_failures: list[str] = []
        # RESERVED artifacts with no file — incomplete reserve.
        for artifact_id in report["reserved_no_file"]:
            try:
                self._store.quarantine_artifact(
                    artifact_id, reason="reserved-no-file",
                )
            except Exception:
                cleanup_failures.append(artifact_id)
        # RESERVED artifacts with only a temp file — partial write.
        for artifact_id in report["reserved_temp"]:
            temp_name = f".{artifact_id}.tmp"
            if not self._artifact_capability.cleanup_orphan(temp_name):
                cleanup_failures.append(artifact_id)
            try:
                self._store.quarantine_artifact(
                    artifact_id, reason="reserved-temp-only",
                )
            except Exception:
                cleanup_failures.append(artifact_id)
        # RESERVED artifacts with a final file — link succeeded but seal
        # faulted.  Cannot verify without a digest, so quarantine.
        for artifact_id in report["reserved_final"]:
            try:
                self._store.quarantine_artifact(
                    artifact_id, reason="reserved-final-without-seal",
                )
            except Exception:
                cleanup_failures.append(artifact_id)
        # SEALED artifacts whose final file is missing — deleted after sealing.
        for artifact_id in report["sealed_missing"]:
            try:
                self._store.quarantine_artifact(
                    artifact_id, reason="sealed-file-missing",
                )
            except Exception:
                cleanup_failures.append(artifact_id)
        # Unknown files in the root — orphan files with no DB row.
        for name in report["unknown_files"]:
            if not self._artifact_capability.cleanup_orphan(name):
                cleanup_failures.append(name)
        # Re-verify SEALED artifacts with a final file present.
        for row in all_rows:
            if row["status"] != "sealed":
                continue
            artifact_id = row["artifact_id"]
            # Skip if the file is missing (already handled above).
            if artifact_id in report["sealed_missing"]:
                continue
            content_digest = row["content_digest"]
            byte_length = int(row["byte_length"])
            if not content_digest:
                # No digest recorded — cannot verify, quarantine.
                try:
                    self._store.quarantine_artifact(
                        artifact_id, reason="sealed-no-digest",
                    )
                except Exception:
                    cleanup_failures.append(artifact_id)
                continue
            if not self._artifact_capability.verify_sealed_artifact(
                artifact_id, expected_digest=content_digest,
                expected_size=byte_length,
            ):
                # Digest or size mismatch — corruption, quarantine.
                try:
                    self._store.quarantine_artifact(
                        artifact_id, reason="sealed-digest-mismatch",
                    )
                except Exception:
                    cleanup_failures.append(artifact_id)
        # Poison verification runs that own artifacts we could not clean up.
        if cleanup_failures:
            failed_runs: set[str] = set()
            for artifact_id in cleanup_failures:
                row = rows_by_id.get(artifact_id)
                if row is not None:
                    failed_runs.add(row["verification_run_id"])
            for verification_run_id in failed_runs:
                try:
                    self._approval_store.add_workspace_poison_scope(
                        verification_run_id,
                        owner="verification-cleanup:artifact-root",
                        reason="artifact-reconcile-cleanup-failed",
                    )
                except Exception:
                    pass

    async def run(
        self,
        context: VerificationPhaseContext,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> VerificationResult:
        self._require_context(context)
        existing = self._store.get_run_by_execution(context.execution_run_id)
        if existing is not None:
            return VerificationResult(
                existing.verification_run_id, existing.status,
                self._store.list_steps(existing.verification_run_id), True,
                existing.failure_code,
            )
        try:
            execution, plan, attestation, workspace, catalog, commands = (
                self._validate_live(context)
            )
        except Exception:
            execution = self._approval_store.get_execution_run(context.execution_run_id)
            if execution is None:
                raise
            plan = self._plans.get(execution.plan_id)
            stale_digest = hashlib.sha256(json.dumps({
                "approved_verification": (
                    compute_verification_digest(plan.verification_requirements)
                    if plan is not None else "unavailable"
                ),
                "profile": self._profile.digest,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            stale = self._new_run(
                context=context, execution=execution,
                plan_content_hash=(plan.content_hash if plan is not None
                                   else execution.plan_content_hash),
                attestation_digest=context.attestation_digest,
                plan_digest=stale_digest, catalog_fingerprint="unavailable",
            )
            run, idempotent = self._store.create_run(stale)
            if not idempotent:
                self._store.transition_run(
                    run.verification_run_id,
                    expected=(VerificationRunStatus.CREATED,),
                    target=VerificationRunStatus.VALIDATING,
                )
                self._store.transition_run(
                    run.verification_run_id,
                    expected=(VerificationRunStatus.VALIDATING,),
                    target=VerificationRunStatus.STALE,
                    failure_code="live-validation-drift",
                )
                run = self._store.get_run_by_execution(execution.execution_run_id)
            return VerificationResult(
                run.verification_run_id, run.status,
                self._store.list_steps(run.verification_run_id), idempotent,
                run.failure_code,
            )
        plan_digest = verification_plan_digest(
            commands, catalog_fingerprint=catalog.fingerprint,
            sandbox_profile_digest=self._profile.digest,
        )
        candidate = self._new_run(
            context=context, execution=execution,
            plan_content_hash=plan.content_hash,
            attestation_digest=attestation.attestation_digest,
            plan_digest=plan_digest, catalog_fingerprint=catalog.fingerprint,
        )
        run, idempotent = self._store.create_run(candidate)
        if idempotent:
            return VerificationResult(
                run.verification_run_id, run.status,
                self._store.list_steps(run.verification_run_id), True, run.failure_code,
            )
        self._store.transition_run(
            run.verification_run_id, expected=(VerificationRunStatus.CREATED,),
            target=VerificationRunStatus.VALIDATING,
        )
        disposable = None
        workspace_id = ""
        last_step: VerificationStepRun | None = None
        try:
            # Revalidate immediately before creating any process or copy.
            self._validate_live(context, expected_catalog=catalog.fingerprint,
                                expected_plan_digest=plan_digest)
            self._store.transition_run(
                run.verification_run_id, expected=(VerificationRunStatus.VALIDATING,),
                target=VerificationRunStatus.PREPARING_SANDBOX,
            )
            # Batch 3.1.3 §6: persist PREPARED row BEFORE filesystem creation.
            # The workspace_id and instance_id are generated here so the DB
            # row exists before any directory is created.  If a crash occurs
            # during mkdir/copy/seal, reconciliation can use the PREPARED row
            # to find and safely clean up the partial directory.
            workspace_id = f"dvw_{uuid.uuid4().hex}"
            instance_id = f"verify_{secrets.token_hex(16)}"
            self._store.create_disposable_workspace(DisposableWorkspaceRecord(
                workspace_id=workspace_id,
                verification_run_id=run.verification_run_id,
                step_run_id="",
                instance_id=instance_id,
                manifest_digest="",  # filled after copy
                manifest_json="[]",  # filled after copy
                allowed_generated_output=_DEFAULT_ALLOWED_GENERATED_OUTPUT,
                state=DisposableWorkspaceState.PREPARED,
                boot_id=self._boot.boot_id,
                created_at=time.time(),
            ))
            disposable = self._workspace_factory.create(
                workspace.worktree_path,
                forbidden_roots=(workspace.repository_root, workspace.worktree_path,
                                 workspace.recovery_root, self._artifact_root,
                                 Path(self._approval_store._db_path)
                                 if getattr(self._approval_store, "_db_path", None)
                                 else workspace.repository_root),
                allowed_generated_output=_DEFAULT_ALLOWED_GENERATED_OUTPUT,
                instance_id=instance_id,
            )
            # Batch 3.1.3 §6: update the PREPARED row with the sealed manifest.
            manifest_json = json.dumps(
                [entry.__dict__ for entry in disposable.manifest],
                sort_keys=True, separators=(",", ":"),
            )
            self._store.seal_disposable_workspace(
                workspace_id,
                manifest_digest=disposable.manifest_digest,
                manifest_json=manifest_json,
            )
            self._store.transition_disposable_workspace(
                workspace_id,
                expected=(DisposableWorkspaceState.SEALED,),
                target=DisposableWorkspaceState.MOUNTED,
            )
            steps = tuple(VerificationStepRun(
                step_run_id=f"pvs_{uuid.uuid4().hex}",
                verification_run_id=run.verification_run_id,
                requirement_id=command.requirement_id, command_id=command.command_id,
                command_digest=command.command_digest, ordinal=index,
                status=VerificationStepStatus.CREATED, timeout_ms=command.timeout_ms,
            ) for index, command in enumerate(commands))
            self._store.create_steps(steps)
            self._store.transition_run(
                run.verification_run_id,
                expected=(VerificationRunStatus.PREPARING_SANDBOX,),
                target=VerificationRunStatus.RUNNING,
            )
            completed: list[VerificationStepRun] = []
            terminal = VerificationRunStatus.PASSED
            failure_code = ""
            for command, step in zip(commands, steps):
                self._require_context(context)
                if cancellation is not None and cancellation.is_set():
                    terminal = VerificationRunStatus.CANCELLED
                    failure_code = "cancelled"
                    break
                self._store.mark_step_running(step.step_run_id)
                last_step = step
                started = time.time()
                # §5: re-bind toolchain attestation digest before execution.
                # If the binary was replaced after configuration, the
                # attestation_digest no longer matches the persisted record
                # and execution is rejected (fail-closed).
                #
                # Batch 3.1.3 §5: also verify the binary_digest and
                # image_attestation_digest match the persisted record.
                # If they differ, the Run goes STALE — no new proof is
                # regenerated to continue using the old approval.
                toolchain_id = command.toolchain_id
                if self._toolchain_attestations:
                    attestation = self._toolchain_attestations.get(toolchain_id)
                    if attestation is None:
                        self._store.abort_step_and_run(
                            step.step_run_id,
                            verification_run_id=run.verification_run_id,
                            failure_code="toolchain-attestation-missing",
                        )
                        raise PermissionError(
                            f"toolchain attestation not found for {toolchain_id}"
                        )
                    persisted = self._store.get_toolchain_attestation(toolchain_id)
                    if persisted is None or persisted.attestation_digest != attestation.attestation_digest:
                        self._store.abort_step_and_run(
                            step.step_run_id,
                            verification_run_id=run.verification_run_id,
                            failure_code="toolchain-attestation-stale",
                        )
                        raise PermissionError(
                            f"toolchain attestation stale or missing for {toolchain_id}"
                        )
                    # Batch 3.1.3 §5: verify binary_digest and image_attestation_digest.
                    if persisted.binary_digest != attestation.binary_digest:
                        self._store.abort_step_and_run(
                            step.step_run_id,
                            verification_run_id=run.verification_run_id,
                            failure_code="toolchain-binary-digest-mismatch",
                        )
                        raise PermissionError(
                            f"toolchain binary digest mismatch for {toolchain_id}"
                        )
                    if persisted.image_attestation_digest != attestation.image_attestation_digest:
                        self._store.abort_step_and_run(
                            step.step_run_id,
                            verification_run_id=run.verification_run_id,
                            failure_code="image-attestation-digest-mismatch",
                        )
                        raise PermissionError(
                            f"image attestation digest mismatch for {toolchain_id}"
                        )
                # §1 steps 1-2: persist PREPARED sandbox instance BEFORE
                # creating the container, so a crash leaves a durable trail.
                sandbox_instance_id = f"vsi_{secrets.token_hex(12)}"
                instance_name = self._backend.generate_instance_name()
                instance = VerificationSandboxInstance(
                    sandbox_instance_id=sandbox_instance_id,
                    verification_run_id=run.verification_run_id,
                    step_run_id=step.step_run_id,
                    backend_id=getattr(self._backend, "BACKEND_ID", "unknown"),
                    backend_instance_name=instance_name,
                    runtime_epoch=self._boot.server_epoch,
                    boot_id=self._boot.boot_id,
                    image_reference=self._profile.image_digest,
                    expected_image_digest=self._profile.image_digest,
                    workspace_manifest_digest=disposable.manifest_digest,
                    state=SandboxInstanceState.PREPARED,
                )
                self._store.create_sandbox_instance(instance)
                labels = self._backend.build_labels(
                    run_id=run.verification_run_id, step_id=step.step_run_id,
                    instance_id=sandbox_instance_id, boot_id=self._boot.boot_id,
                    manifest_digest=disposable.manifest_digest,
                )
                started_monotonic = time.monotonic()
                container_id = ""
                attestation = None
                attach_proc = None
                stdout_stream = None
                stderr_stream = None
                try:
                    # Batch 3.1.3 §1: explicit lifecycle — create, inspect,
                    # persist, start, persist, attach, collect.  Container
                    # identity is persisted BEFORE docker start, so a crash
                    # after create leaves a durable trail.
                    self._backend.validate_command(command)
                    # Step 2: docker create --pull=never (no project code)
                    container_id = await self._backend.create_instance(
                        instance_name=instance_name,
                        image_digest=self._profile.image_digest,
                        command=command, workspace_root=disposable.root,
                        labels=labels,
                    )
                    # Step 3: inspect and attest (before start)
                    attestation = await self._backend.inspect_and_attest_instance(
                        container_id_or_name=container_id,
                        expected_labels=labels,
                        expected_image_digest=self._profile.image_digest,
                        expected_manifest_digest=disposable.manifest_digest,
                    )
                    # Step 4: persist container_id + attestation + CREATED_ATTESTED
                    # in one atomic transaction BEFORE docker start.
                    self._store.persist_created_instance(
                        sandbox_instance_id,
                        container_id=container_id,
                        attestation_digest=attestation.attestation_digest,
                        actual_image_digest=attestation.local_image_id,
                        actual_container_image_id=attestation.container_image_id,
                    )
                    # Step 5: docker start (project code begins)
                    await self._backend.start_instance(container_id)
                    # Step 6: persist RUNNING
                    self._store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.RUNNING,
                        started_at=time.time(),
                    )
                    # Step 7: attach to capture output
                    attach_proc, stdout_stream, stderr_stream = (
                        await self._backend.attach_instance(container_id)
                    )
                    # Step 8: collect result (remove=False — runner controls cleanup)
                    result = await self._backend.collect_result(
                        container_id=container_id, attach_proc=attach_proc,
                        stdout_stream=stdout_stream, stderr_stream=stderr_stream,
                        command=command, cancellation=cancellation,
                        started=started_monotonic,
                        sandbox_instance_id=sandbox_instance_id,
                        attestation_digest=attestation.attestation_digest,
                        remove=False,
                    )
                except Exception:
                    # Batch 3.1.3 §2: real cleanup states.  Do NOT mark
                    # TERMINATED unless we confirm the container is gone.
                    await self._cleanup_sandbox_instance(
                        sandbox_instance_id, container_id or instance_name,
                    )
                    self._store.abort_step_and_run(
                        step.step_run_id,
                        verification_run_id=run.verification_run_id,
                        failure_code="backend-lifecycle-failed",
                    )
                    raise
                # Batch 3.1.3 §2: terminate, remove, and CONFIRM container
                # is gone before persisting TERMINATED.
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATING,
                    terminated_at=time.time(),
                )
                try:
                    terminated_ok, removed_ok = (
                        await self._backend.terminate_and_remove_instance(container_id)
                    )
                except Exception:
                    # Cleanup failed — mark CLEANUP_PENDING, attempt best-effort.
                    self._store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.CLEANUP_PENDING,
                        failure_code="terminate-remove-exception",
                    )
                    try:
                        await self._backend.terminate_and_remove_instance(container_id)
                        gone = await self._backend.confirm_instance_gone(container_id)
                    except Exception:
                        gone = False
                    if gone:
                        self._store.update_sandbox_instance(
                            sandbox_instance_id,
                            state=SandboxInstanceState.TERMINATED,
                            terminated_at=time.time(),
                        )
                    else:
                        self._store.update_sandbox_instance(
                            sandbox_instance_id,
                            state=SandboxInstanceState.CLEANUP_FAILED,
                            failure_code="cleanup-failed-after-collect",
                        )
                else:
                    if removed_ok:
                        self._store.update_sandbox_instance(
                            sandbox_instance_id,
                            state=SandboxInstanceState.TERMINATED,
                            terminated_at=time.time(),
                        )
                    else:
                        # Container still exists — cleanup failed.
                        self._store.update_sandbox_instance(
                            sandbox_instance_id,
                            state=SandboxInstanceState.CLEANUP_FAILED,
                            failure_code="remove-returned-false",
                        )
                # §3: write artifact with RESERVED→SEALED protocol.
                try:
                    artifact_id = self._write_artifact(
                        run.verification_run_id, result.stdout, result.stderr,
                    )
                except Exception:
                    # Artifact write failed — abort step+run atomically.
                    self._store.abort_step_and_run(
                        step.step_run_id,
                        verification_run_id=run.verification_run_id,
                        failure_code="artifact-write-failed",
                    )
                    raise
                if result.cancelled:
                    step_status = VerificationStepStatus.CANCELLED
                    terminal = VerificationRunStatus.CANCELLED
                    failure_code = "cancelled"
                elif result.timed_out:
                    step_status = VerificationStepStatus.TIMED_OUT
                    terminal = VerificationRunStatus.TIMED_OUT
                    failure_code = "timeout"
                elif result.exit_code in command.expected_exit_codes:
                    step_status = VerificationStepStatus.PASSED
                else:
                    step_status = VerificationStepStatus.FAILED
                    if bool(command.metadata.get("required", True)):
                        terminal = VerificationRunStatus.FAILED
                        failure_code = "required-step-failed"
                finished = replace(
                    step, status=step_status, exit_code=result.exit_code,
                    signal=result.signal, started_at=started, completed_at=time.time(),
                    duration_ms=result.duration_ms, stdout_digest=result.stdout_digest,
                    stderr_digest=result.stderr_digest, output_artifact_id=artifact_id,
                    output_truncated=result.output_truncated,
                    sandbox_instance_id=sandbox_instance_id,
                    sandbox_image_digest=result.image_digest, failure_code=failure_code,
                )
                # §9: atomic step+run+execution terminal transition.
                # Cancellation uses cancel_step_and_run (not the prohibited
                # finish_step() → transition_run() split).
                if step_status == VerificationStepStatus.PASSED and terminal == VerificationRunStatus.PASSED:
                    # Non-terminal step pass — use legacy finish_step.
                    self._store.finish_step(finished)
                elif step_status == VerificationStepStatus.TIMED_OUT:
                    self._store.timeout_step_and_run(finished)
                elif step_status == VerificationStepStatus.FAILED:
                    self._store.fail_step_and_run(finished, run_failure_code=failure_code)
                else:
                    # Cancelled — atomic cancel_step_and_run with full step (§9).
                    self._store.cancel_step_and_run(
                        step.step_run_id,
                        verification_run_id=run.verification_run_id,
                        failure_code="cancelled",
                        step=finished,
                    )
                completed.append(finished)
                if terminal != VerificationRunStatus.PASSED:
                    break
            # Canonical workspace must still equal the immutable mutation proof.
            try:
                self._validate_live(context, expected_catalog=catalog.fingerprint,
                                    expected_plan_digest=plan_digest)
            except Exception as exc:
                terminal = VerificationRunStatus.POISONED
                failure_code = "canonical-workspace-drift"
                self._approval_store.add_workspace_poison_scope(
                    workspace.id, owner=f"verification:{run.verification_run_id}",
                    reason="canonical-workspace-drift",
                )
                raise RuntimeError("canonical workspace drifted during verification") from exc
            self._store.transition_run(
                run.verification_run_id, expected=(VerificationRunStatus.RUNNING,),
                target=terminal, failure_code=failure_code,
            )
            return VerificationResult(
                run.verification_run_id, terminal, tuple(completed), False, failure_code,
            )
        except Exception as exc:
            current = self._store.get_run_by_execution(execution.execution_run_id)
            if current and current.status in {
                VerificationRunStatus.VALIDATING,
                VerificationRunStatus.PREPARING_SANDBOX,
                VerificationRunStatus.RUNNING,
            }:
                target = (VerificationRunStatus.POISONED
                          if "canonical workspace" in str(exc)
                          else VerificationRunStatus.ERRORED)
                self._store.transition_run(
                    current.verification_run_id, expected=(current.status,),
                    target=target, failure_code="verification-error",
                )
            raise
        finally:
            if disposable is not None:
                # Batch 3.1.2 §8: transition to CLEANUP_PENDING before destroy.
                if workspace_id:
                    try:
                        self._store.transition_disposable_workspace(
                            workspace_id,
                            expected=(DisposableWorkspaceState.MOUNTED,
                                      DisposableWorkspaceState.SEALED,
                                      DisposableWorkspaceState.PREPARED),
                            target=DisposableWorkspaceState.CLEANUP_PENDING,
                        )
                    except Exception:
                        pass
                try:
                    self._workspace_factory.destroy(disposable)
                except Exception:
                    # §8: cleanup failed — mark workspace, poison scope,
                    # and transition run/step to ERRORED if still PASSED.
                    if workspace_id:
                        try:
                            self._store.mark_disposable_workspace_cleanup_failed(
                                workspace_id, failure_code="cleanup-failed",
                            )
                        except Exception:
                            pass
                    try:
                        self._approval_store.add_workspace_poison_scope(
                            run.verification_run_id,
                            owner=f"verification-cleanup:{workspace_id or 'unknown'}",
                            reason="disposable-workspace-cleanup-failed",
                        )
                    except Exception:
                        pass
                    # §9: atomic cleanup_fail_step_and_run if the run is
                    # still in a state that allows the transition.
                    if last_step is not None:
                        try:
                            self._store.cleanup_fail_step_and_run(
                                last_step.step_run_id,
                                verification_run_id=run.verification_run_id,
                                failure_code="disposable-workspace-cleanup-failed",
                            )
                        except Exception:
                            pass
                else:
                    # Cleanup succeeded — mark workspace CLEANED.
                    if workspace_id:
                        try:
                            self._store.mark_disposable_workspace_cleaned(workspace_id)
                        except Exception:
                            pass

    def _new_run(
        self, *, context: VerificationPhaseContext, execution: Any,
        plan_content_hash: str, attestation_digest: str, plan_digest: str,
        catalog_fingerprint: str,
    ) -> VerificationExecutionRun:
        now = time.time()
        return VerificationExecutionRun(
            verification_run_id=f"pvr_{uuid.uuid4().hex}",
            execution_run_id=execution.execution_run_id, plan_id=execution.plan_id,
            plan_content_hash=plan_content_hash,
            approval_request_id=execution.approval_request_id,
            execution_context_id=context.verification_context_id,
            task_id=execution.task_id, workspace_id=execution.workspace_id,
            repository_id=execution.repository_id,
            bundle_digest=execution.edit_bundle_digest,
            final_mutation_attestation_digest=attestation_digest,
            verification_plan_digest=plan_digest,
            trusted_catalog_fingerprint=catalog_fingerprint,
            sandbox_profile_digest=self._profile.digest,
            status=VerificationRunStatus.CREATED, started_at=now, updated_at=now,
        )

    def _validate_live(
        self,
        context: VerificationPhaseContext,
        *,
        expected_catalog: str | None = None,
        expected_plan_digest: str | None = None,
    ) -> tuple[Any, Any, Any, Any, VerificationCatalog, tuple[Any, ...]]:
        self._require_context(context)
        execution = self._approval_store.get_execution_run(context.execution_run_id)
        if execution is None or execution.status not in {
            ExecutionRunStatus.MUTATED, ExecutionRunStatus.VERIFYING,
            ExecutionRunStatus.VERIFIED, ExecutionRunStatus.VERIFICATION_FAILED,
            ExecutionRunStatus.VERIFICATION_ERROR,
        }:
            raise PermissionError("verification requires MUTATED execution run")
        if (execution.plan_id, execution.task_id, execution.workspace_id,
                execution.repository_id, execution.edit_bundle_digest,
                execution.binding_digest) != (
            context.plan_id, context.task_id, context.workspace_id,
            context.repository_id, context.bundle_digest, context.binding_digest,
        ):
            raise PermissionError("verification context scope mismatch")
        plan = self._plans.get(execution.plan_id)
        if plan is None or plan.content_hash != execution.plan_content_hash:
            raise PermissionError("persisted plan snapshot mismatch")
        request = self._approval_store.get_request(execution.approval_request_id)
        if request is None or request.binding_digest != execution.binding_digest:
            raise PermissionError("approval binding mismatch")
        if request.verification_digest != compute_verification_digest(plan.verification_requirements):
            raise PermissionError("approval verification digest mismatch")
        attestation = self._approval_store.get_final_mutation_attestation(execution.execution_run_id)
        if attestation is None or attestation.attestation_digest != context.attestation_digest:
            raise PermissionError("final mutation attestation mismatch")
        workspace = self._workspaces.get(execution.workspace_id)
        if workspace is None or workspace.task_id != execution.task_id:
            raise PermissionError("verification workspace identity mismatch")
        state = self._context_provider.current_state(
            repository_id=execution.repository_id, task_id=execution.task_id,
            workspace_id=execution.workspace_id,
        )
        if (not state.task_active or not state.workspace_active or state.task_terminal
                or state.workspace_terminal or state.head_sha != attestation.head
                or state.repository_generation != attestation.generation):
            raise PermissionError("live execution state drifted")
        git = self._git.snapshot(workspace, repository_generation=state.repository_generation)
        workspace_digest = hashlib.sha256("|".join(
            f"{item.relative_path}:{item.state_digest}"
            for item in sorted(git.file_states, key=lambda value: value.relative_path)
        ).encode()).hexdigest()
        if (git.head_commit != attestation.head or git.index_digest != attestation.index_digest
                or git.worktree_admin_identity != attestation.worktree_admin_digest
                or workspace_digest != attestation.workspace_state_digest):
            raise PermissionError("canonical workspace no longer matches final attestation")
        catalog = VerificationCatalog(workspace.worktree_path, repository_id=execution.repository_id)
        for requirement in plan.verification_requirements:
            if requirement.command is None:
                continue
            matches = tuple(entry for entry in catalog.entries if (
                entry.verification_type == requirement.verification_type
                and entry.language == requirement.scope
                and entry.argv == requirement.command
            ))
            expected_configs = {
                (evidence.path or "", str(evidence.metadata.get("config_hash", "")))
                for evidence in requirement.evidence
                if evidence.metadata.get("config_hash")
            }
            if len(matches) != 1 or not expected_configs or (
                matches[0].config_path, matches[0].config_hash
            ) not in expected_configs:
                raise PermissionError("trusted verification config evidence drifted")
        commands = self._commands.build(
            plan.verification_requirements, catalog.entries,
            profile_id=self._profile.profile_id,
        )
        digest = verification_plan_digest(
            commands, catalog_fingerprint=catalog.fingerprint,
            sandbox_profile_digest=self._profile.digest,
        )
        if expected_catalog is not None and catalog.fingerprint != expected_catalog:
            raise PermissionError("verification catalog fingerprint drifted")
        if expected_plan_digest is not None and digest != expected_plan_digest:
            raise PermissionError("verification plan digest drifted")
        return execution, plan, attestation, workspace, catalog, commands

    def _require_context(self, context: VerificationPhaseContext) -> None:
        if self._contexts.get(getattr(context, "verification_context_id", "")) is not context:
            raise PermissionError("verification context was not issued by runtime")
        self._fence.assert_owner(
            context.workspace_id, f"verification-lease:{context.phase_lease_id}",
        )
        row = self._store.require_phase_lease(context.phase_lease_id)
        if (
            row["execution_run_id"], row["owner_execution_id"], row["task_id"],
            row["workspace_id"], row["repository_id"], row["plan_id"],
            row["bundle_digest"], row["attestation_digest"],
            row["binding_digest"],
        ) != (
            context.execution_run_id, context.owner_execution_id, context.task_id,
            context.workspace_id, context.repository_id, context.plan_id,
            context.bundle_digest, context.attestation_digest,
            context.binding_digest,
        ):
            raise PermissionError("verification phase lease binding mismatch")
        persisted_epoch, persisted_boot = self._approval_store.get_current_epoch()
        if (int(row["server_epoch"]) != context.server_epoch
                or row["boot_id"] != context.boot_id
                or persisted_epoch != context.server_epoch
                or persisted_boot != context.boot_id
                or context.server_epoch != self._boot.server_epoch
                or context.boot_id != self._boot.boot_id):
            raise PermissionError("verification runtime boot is stale")

    def _write_artifact(self, run_id: str, stdout: bytes, stderr: bytes) -> str:
        """Batch 3.1.2 §7: RESERVED → temp → final no-replace → fsync → SEALED.

        Uses :class:`ArtifactRootCapability` for all file operations:
        dir_fd-only access, no Path re-parsing, no ``os.rename`` to
        overwrite existing final files.  The protocol is:
        1. Insert a RESERVED artifact row (BEFORE writing the file).
        2. Write temp file (O_CREAT|O_EXCL|O_NOFOLLOW) + fsync.
        3. Link temp → final (no-replace, fails if final exists).
        4. fsync the artifact root directory.
        5. Unlink the temp file.
        6. Atomically transition RESERVED → SEALED in the DB.
        """
        artifact_id = f"pvo_{secrets.token_hex(20)}"
        relative = f"{artifact_id}.log"
        expires_at = time.time() + self._artifact_ttl
        # Step 1: RESERVED row BEFORE writing the file.
        self._store.reserve_artifact(
            artifact_id=artifact_id, verification_run_id=run_id,
            relative_name=relative, expires_at=expires_at,
        )
        payload = b"stdout:\n" + stdout + b"\nstderr:\n" + stderr
        # Steps 2-5: write via capability (temp + fsync + link + root fsync + unlink temp).
        try:
            content_digest, byte_length = self._artifact_capability.write_artifact(
                artifact_id, payload,
            )
        except Exception:
            # Cleanup: if the temp file was created but link failed, the
            # capability already cleaned it up.  Mark the artifact row
            # as quarantined so reconciliation can handle it.
            self._store.quarantine_artifact(artifact_id, reason="write-failed")
            raise
        # Step 6: SEALED.
        self._store.seal_artifact(
            artifact_id=artifact_id,
            content_digest=content_digest, byte_length=byte_length,
        )
        return artifact_id
