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
    SandboxProfile, TrustedCommandFactory, VerificationWorkspaceFactory,
)
from khaos.coding.planning.verification_catalog import VerificationCatalog
from khaos.coding.planning.verification_execution_models import (
    VerificationExecutionRun, VerificationPhaseContext, VerificationResult,
    VerificationRunStatus, VerificationStepRun, VerificationStepStatus,
    verification_plan_digest,
)
from khaos.coding.planning.verification_sandbox import VerificationSandboxBackend
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)
from khaos.coding.planning.verification_store import VerificationExecutionStore


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
        if backend.__class__.__module__.endswith("tests"):
            raise TypeError("test sandbox backend cannot be used in production runner")
        self._store = VerificationExecutionStore(approval_store)
        self._approval_store = approval_store
        self._plans = plan_repository
        self._workspaces = workspace_manager
        self._context_provider = context_provider
        self._backend = backend
        self._commands = command_factory
        self._workspace_factory = workspace_factory
        self._artifact_root = artifact_root.resolve()
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
        try:
            # Revalidate immediately before creating any process or copy.
            self._validate_live(context, expected_catalog=catalog.fingerprint,
                                expected_plan_digest=plan_digest)
            self._store.transition_run(
                run.verification_run_id, expected=(VerificationRunStatus.VALIDATING,),
                target=VerificationRunStatus.PREPARING_SANDBOX,
            )
            disposable = self._workspace_factory.create(
                workspace.worktree_path,
                forbidden_roots=(workspace.repository_root, workspace.worktree_path,
                                 workspace.recovery_root, self._artifact_root,
                                 Path(self._approval_store._db_path)
                                 if getattr(self._approval_store, "_db_path", None)
                                 else workspace.repository_root),
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
                started = time.time()
                # §5: re-bind toolchain attestation digest before execution.
                # If the binary was replaced after configuration, the
                # attestation_digest no longer matches the persisted record
                # and execution is rejected (fail-closed).
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
                # §1 steps 3-5: docker create + inspect_and_attest + start + attach.
                # No project code runs during create.  Start begins the
                # entrypoint; we persist RUNNING before awaiting output.
                labels = self._backend.build_labels(
                    run_id=run.verification_run_id, step_id=step.step_run_id,
                    instance_id=sandbox_instance_id, boot_id=self._boot.boot_id,
                    manifest_digest=disposable.manifest_digest,
                )
                started_monotonic = time.monotonic()
                try:
                    container_id, attestation, attach_proc, stdout_stream, stderr_stream = (
                        await self._backend.launch_instance(
                            instance_name=instance_name,
                            image_digest=self._profile.image_digest,
                            command=command, workspace_root=disposable.root,
                            labels=labels,
                            expected_manifest_digest=disposable.manifest_digest,
                        )
                    )
                except Exception:
                    # Backend launch failed — abort step+run atomically.
                    self._store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.TERMINATED,
                        terminated_at=time.time(),
                        failure_code="backend-launch-failed",
                    )
                    self._store.abort_step_and_run(
                        step.step_run_id,
                        verification_run_id=run.verification_run_id,
                        failure_code="backend-launch-failed",
                    )
                    raise
                # §1 step 6: persist container_id, actual image, STARTING
                # BEFORE project code output is collected.  This is the
                # critical durability point: container identity is durable
                # before any project code runs.
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.STARTING,
                    container_id=container_id,
                    actual_container_image_id=attestation.container_image_id,
                    actual_image_digest=attestation.local_image_id,
                )
                # §1 steps 7-8: docker start already done in launch_instance;
                # immediately persist RUNNING.
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.RUNNING,
                    started_at=time.time(),
                )
                # §1 steps 9-11: wait for output or cancellation, then
                # terminate and remove.
                try:
                    result = await self._backend.collect_result(
                        container_id=container_id, attach_proc=attach_proc,
                        stdout_stream=stdout_stream, stderr_stream=stderr_stream,
                        command=command, cancellation=cancellation,
                        started=started_monotonic,
                        sandbox_instance_id=sandbox_instance_id,
                        attestation_digest=attestation.attestation_digest,
                    )
                except Exception:
                    self._store.update_sandbox_instance(
                        sandbox_instance_id,
                        state=SandboxInstanceState.TERMINATED,
                        terminated_at=time.time(),
                        failure_code="backend-collect-failed",
                    )
                    self._store.abort_step_and_run(
                        step.step_run_id,
                        verification_run_id=run.verification_run_id,
                        failure_code="backend-collect-failed",
                    )
                    raise
                # §1 step 12: confirm container removed, persist TERMINATED.
                self._store.update_sandbox_instance(
                    sandbox_instance_id,
                    state=SandboxInstanceState.TERMINATED,
                    terminated_at=time.time(),
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
                self._workspace_factory.destroy(disposable)

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
        """Batch 3.1.1 §3: RESERVED → write file → fsync → SEALED protocol.

        1. Insert a RESERVED artifact row (BEFORE writing the file).
        2. Write the artifact file to a temporary path.
        3. fsync the file.
        4. Atomically install (rename) to the final path.
        5. fsync the artifact root directory.
        6. Atomically transition RESERVED → SEALED in the DB.
        """
        self._artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        artifact_id = f"pvo_{secrets.token_hex(20)}"
        relative = f"{artifact_id}.log"
        expires_at = time.time() + self._artifact_ttl
        # Step 1: RESERVED row BEFORE writing the file.
        self._store.reserve_artifact(
            artifact_id=artifact_id, verification_run_id=run_id,
            relative_name=relative, expires_at=expires_at,
        )
        payload = b"stdout:\n" + stdout + b"\nstderr:\n" + stderr
        digest = hashlib.sha256(payload).hexdigest()
        # Step 2-3: write to temporary path + fsync.
        tmp_relative = f".{artifact_id}.tmp"
        tmp_path = self._artifact_root / tmp_relative
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            # Step 4: atomic install (no-replace).
            final_path = self._artifact_root / relative
            os.rename(str(tmp_path), str(final_path))
            # Step 5: fsync the artifact root directory.
            dir_fd = os.open(str(self._artifact_root), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            # Step 6: SEALED.
            self._store.seal_artifact(
                artifact_id=artifact_id,
                content_digest=digest, byte_length=len(payload),
            )
        except Exception:
            # Cleanup temp file if it exists.
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise
        return artifact_id
