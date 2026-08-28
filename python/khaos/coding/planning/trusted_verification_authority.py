"""Deterministic M7.4 trusted-verification authority boundary.

This module consumes only typed, bounded verification descriptors.  It never
starts a command, reads a repository path, calls a model, changes a task, or
grants a permission.  The default evidence validator is fail-closed.  A
runtime that has the existing M4 boot-scoped verification read handle may
compose the explicit adapter in this module; arbitrary callers cannot turn a
positive status or stdout claim into a trusted assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast
from uuid import uuid4

from khaos.coding.planning.execution_models import (
    FinalMutationAttestation,
    PlanExecutionRun,
)
from khaos.coding.planning.verification_assessment import (
    TRUSTED_VERIFICATION_INPUT_SCHEMA_VERSION,
    TrustedVerificationInput,
    VerificationAssessment,
    VerificationAssessmentDisposition,
    VerificationCheckAssessment,
    VerificationEvidenceKind,
    VerificationEvidenceRef,
    VerificationExecutionEvidence,
    VerificationExecutionStatus,
    VerificationRequirement,
    VerificationTermination,
)
from khaos.coding.planning.verification_execution_models import (
    VerificationRunBinding,
    VerificationStepRun,
)
from khaos.security.protocol_boundary import canonical_digest

_MAX_DIAGNOSTIC_LENGTH = 512


class VerificationAuthorityError(RuntimeError):
    """Base error for the trusted-verification authority boundary."""


class VerificationAuthorityInputError(VerificationAuthorityError):
    """The verifier input is malformed or internally inconsistent."""


class VerificationEvidenceValidationStatus(str, Enum):
    """Closed validator results without a caller-controlled authority flag."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class VerificationEvidenceValidation:
    """Result returned by an evidence owner/validator.

    ``status`` is a result of the validator, not a positive boolean that a
    model or arbitrary fact provider can mint.  ``reason`` is bounded and
    explanatory only.
    """

    evidence_id: str
    status: VerificationEvidenceValidationStatus
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.evidence_id) is not str or not self.evidence_id:
            raise VerificationAuthorityInputError("evidence_id is invalid")
        if type(self.status) is not VerificationEvidenceValidationStatus:
            raise VerificationAuthorityInputError("evidence validation status is invalid")
        if type(self.reason) is not str or len(self.reason) > _MAX_DIAGNOSTIC_LENGTH:
            raise VerificationAuthorityInputError("evidence validation reason is invalid")


class VerificationEvidenceValidator(Protocol):
    """Port for an owner that revalidates persisted M4 evidence."""

    def validate(
        self,
        *,
        verification_input: TrustedVerificationInput,
        evidence: VerificationExecutionEvidence,
    ) -> VerificationEvidenceValidation:
        """Validate one evidence descriptor against its authoritative store."""
        raise NotImplementedError


class _M4VerificationReadHandle(Protocol):
    """Typed read-only surface required from the existing M4 authority."""

    def verification_status(self, verification_run_id: str) -> str | None:
        ...

    def verification_for_execution(self, execution_run_id: str) -> str:
        ...

    def success_binding(
        self,
        verification_run_id: str,
        *,
        execution_run_id: str | None = None,
    ) -> tuple[str, str]:
        ...

    def execution_status(self, execution_run_id: str) -> str | None:
        ...

    def verification_run_binding(
        self, verification_run_id: str,
    ) -> VerificationRunBinding | None:
        ...


class _M4ExecutionReadModel(Protocol):
    """Typed read-only surface required from the existing M4 read model."""

    def get_execution_run(
        self,
        execution_run_id: str,
        *,
        authoritative_verification_reads_required: bool = False,
    ) -> PlanExecutionRun | None:
        ...

    def get_final_mutation_attestation(
        self, execution_run_id: str,
    ) -> FinalMutationAttestation | None:
        ...

    def get_verification_step(self, step_run_id: str) -> VerificationStepRun | None:
        ...


class FailClosedVerificationEvidenceValidator:
    """Production-safe validator used until an M4 authority is composed."""

    def validate(
        self,
        *,
        verification_input: TrustedVerificationInput,
        evidence: VerificationExecutionEvidence,
    ) -> VerificationEvidenceValidation:
        del verification_input
        return VerificationEvidenceValidation(
            evidence_id=evidence.evidence_id,
            status=VerificationEvidenceValidationStatus.UNAVAILABLE,
            reason="trusted verification evidence authority is unavailable",
        )


class StructuralVerificationEvidenceValidator:
    """Explicit deterministic test adapter for contract-level composition.

    This adapter validates only the bounded structural postconditions.  It is
    intentionally not installed by the production factory: a real M4
    authority must re-read its append-only success evidence and supply the
    validator result.
    """

    def validate(
        self,
        *,
        verification_input: TrustedVerificationInput,
        evidence: VerificationExecutionEvidence,
    ) -> VerificationEvidenceValidation:
        if not _evidence_matches_input(evidence, verification_input):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="verification evidence snapshot binding mismatch",
            )
        if evidence.status is VerificationExecutionStatus.PASSED:
            if (
                evidence.exit_code != 0
                or evidence.termination is not VerificationTermination.COMPLETED
                or evidence.output_truncated
            ):
                return VerificationEvidenceValidation(
                    evidence_id=evidence.evidence_id,
                    status=VerificationEvidenceValidationStatus.REJECTED,
                    reason="passed evidence lacks complete successful termination",
                )
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.ACCEPTED,
            )
        return VerificationEvidenceValidation(
            evidence_id=evidence.evidence_id,
            status=VerificationEvidenceValidationStatus.ACCEPTED,
            reason="negative execution result is retained as a narrowing fact",
        )


class M4VerificationEvidenceValidator:
    """Adapter over the existing M4 read-only authority boundary.

    The adapter uses ``VerificationReadHandle`` and ``PlanExecutionReadModel``
    supplied by the M4 runtime.  It does not import or instantiate the legacy
    ``khaos.coding.verification.pipeline`` and it never reads host paths.
    """

    def __init__(self, *, verification_read_handle: object, execution_read_model: object) -> None:
        if not callable(getattr(verification_read_handle, "verification_status", None)):
            raise TypeError("verification_read_handle must be an M4 read handle")
        if not callable(getattr(verification_read_handle, "execution_status", None)):
            raise TypeError("verification_read_handle must expose execution_status")
        if not callable(getattr(verification_read_handle, "success_binding", None)):
            raise TypeError("verification_read_handle must expose success_binding")
        if not callable(
            getattr(verification_read_handle, "verification_for_execution", None)
        ):
            raise TypeError(
                "verification_read_handle must expose verification_for_execution"
            )
        if not callable(
            getattr(verification_read_handle, "verification_run_binding", None)
        ):
            raise TypeError(
                "verification_read_handle must expose verification_run_binding"
            )
        if not callable(getattr(execution_read_model, "get_execution_run", None)):
            raise TypeError("execution_read_model must expose get_execution_run")
        if not callable(getattr(execution_read_model, "get_final_mutation_attestation", None)):
            raise TypeError(
                "execution_read_model must expose get_final_mutation_attestation"
            )
        if not callable(getattr(execution_read_model, "get_verification_step", None)):
            raise TypeError("execution_read_model must expose get_verification_step")
        self._verification_read_handle = cast(
            _M4VerificationReadHandle,
            verification_read_handle,
        )
        self._execution_read_model = cast(_M4ExecutionReadModel, execution_read_model)

    def validate(
        self,
        *,
        verification_input: TrustedVerificationInput,
        evidence: VerificationExecutionEvidence,
    ) -> VerificationEvidenceValidation:
        if not _evidence_matches_input(evidence, verification_input):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="verification evidence snapshot binding mismatch",
            )
        try:
            verification_status = self._verification_read_handle.verification_status(
                evidence.verification_run_id
            )
            bound_verification_id = (
                self._verification_read_handle.verification_for_execution(
                    evidence.execution_run_id
                )
            )
            verification_run = self._verification_read_handle.verification_run_binding(
                evidence.verification_run_id
            )
            authority_id, authority_digest = self._verification_read_handle.success_binding(
                evidence.verification_run_id,
                execution_run_id=evidence.execution_run_id,
            )
            execution_status = self._verification_read_handle.execution_status(
                evidence.execution_run_id
            )
            execution_run = self._execution_read_model.get_execution_run(
                evidence.execution_run_id,
                authoritative_verification_reads_required=True,
            )
            attestation = self._execution_read_model.get_final_mutation_attestation(
                evidence.execution_run_id
            )
            if evidence.verification_step_id is None:
                return VerificationEvidenceValidation(
                    evidence_id=evidence.evidence_id,
                    status=VerificationEvidenceValidationStatus.UNAVAILABLE,
                    reason="M4 success lacks a verification step identity",
                )
            verification_step = self._execution_read_model.get_verification_step(
                evidence.verification_step_id
            )
        except Exception as exc:  # noqa: BLE001 - an evidence owner must fail closed
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.UNAVAILABLE,
                reason=f"M4 evidence authority rejected read: {type(exc).__name__}",
            )
        if (
            bound_verification_id != evidence.verification_run_id
            or authority_id != evidence.authority_id
            or authority_digest != evidence.authority_digest
        ):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="M4 authority identity or verification binding mismatch",
            )
        if verification_status != "passed" or execution_status != "verified":
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="M4 verification/execution status is not an authorized success",
            )
        if (
            verification_run is None
            or execution_run is None
            or attestation is None
            or verification_step is None
        ):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.UNAVAILABLE,
                reason="M4 success lacks execution, step, or mutation attestation",
            )
        if not all(
            (
                isinstance(verification_run, VerificationRunBinding),
                isinstance(execution_run, PlanExecutionRun),
                isinstance(attestation, FinalMutationAttestation),
                isinstance(verification_step, VerificationStepRun),
            )
        ):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.UNAVAILABLE,
                reason="M4 read projection has an invalid typed contract",
            )
        if not _passed_evidence_shape(evidence):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="M4 evidence lacks complete successful termination",
            )
        if not _m4_run_matches_input(
            execution_run,
            verification_run,
            attestation,
            verification_step,
            verification_input,
            evidence,
        ):
            return VerificationEvidenceValidation(
                evidence_id=evidence.evidence_id,
                status=VerificationEvidenceValidationStatus.REJECTED,
                reason="M4 execution evidence binding mismatch",
            )
        return VerificationEvidenceValidation(
            evidence_id=evidence.evidence_id,
            status=VerificationEvidenceValidationStatus.ACCEPTED,
        )


class TrustedVerificationAuthority:
    """Produce an immutable deterministic verification assessment.

    The authority is deliberately passive.  It calculates per-requirement
    dispositions from a published plan's declarative requirements and
    evidence-owner validation, then returns history for a repository to
    persist.  No returned disposition changes ``TaskStatus`` or any security
    capability.
    """

    def __init__(
        self,
        validator: VerificationEvidenceValidator | None = None,
    ) -> None:
        self._validator = (
            FailClosedVerificationEvidenceValidator()
            if validator is None
            else validator
        )

    def assess(
        self,
        verification_input: TrustedVerificationInput,
        *,
        assessment_id: str | None = None,
        created_at: str = "authority",
    ) -> VerificationAssessment:
        """Evaluate the typed snapshot without persistence or side effects."""
        if type(verification_input) is not TrustedVerificationInput:
            raise VerificationAuthorityInputError("verification_input has invalid type")
        if verification_input.schema_version != TRUSTED_VERIFICATION_INPUT_SCHEMA_VERSION:
            raise VerificationAuthorityInputError("unsupported verification input schema")
        if not created_at or type(created_at) is not str:
            raise VerificationAuthorityInputError("created_at must be a bounded string")
        if len(created_at) > _MAX_DIAGNOSTIC_LENGTH:
            raise VerificationAuthorityInputError("created_at exceeds its bound")
        assessment_identity = uuid4().hex if assessment_id is None else assessment_id
        if type(assessment_identity) is not str or not assessment_identity:
            raise VerificationAuthorityInputError("assessment_id is invalid")

        requirements = verification_input.requirements
        evidence_by_requirement: dict[str, VerificationExecutionEvidence] = {}
        for evidence in verification_input.evidence:
            if evidence.requirement_id in evidence_by_requirement:
                raise VerificationAuthorityInputError(
                    "multiple evidence records supplied for one requirement"
                )
            evidence_by_requirement[evidence.requirement_id] = evidence
        requirement_by_id = {
            item.requirement_id: item for item in requirements
        }

        checks: list[VerificationCheckAssessment] = []
        all_refs: list[VerificationEvidenceRef] = []
        diagnostics: list[str] = []
        for requirement in requirements:
            evidence = evidence_by_requirement.get(requirement.requirement_id)
            if evidence is None:
                checks.append(
                    VerificationCheckAssessment(
                        check_id=f"{requirement.requirement_id}:missing",
                        requirement_id=requirement.requirement_id,
                        status=VerificationAssessmentDisposition.UNAVAILABLE,
                        scope=requirement.scope,
                        command_digest=requirement.command_digest,
                        diagnostic="required verification evidence is unavailable",
                    )
                )
                diagnostics.append(
                    f"verification evidence unavailable: {requirement.requirement_id}"
                )
                continue

            refs = _evidence_refs(evidence)
            all_refs.extend(refs)
            requirement = requirement_by_id[evidence.requirement_id]
            if not _evidence_matches_requirement(evidence, requirement):
                status = VerificationAssessmentDisposition.STALE
                diagnostic = "verification evidence check binding is stale"
            elif not _evidence_matches_input(evidence, verification_input):
                status = VerificationAssessmentDisposition.STALE
                diagnostic = "verification evidence snapshot is stale"
            elif (
                evidence.status is VerificationExecutionStatus.FAILED
                or evidence.status is VerificationExecutionStatus.ERRORED
            ):
                # Negative execution outcomes are safe narrowing facts.  They
                # do not require a positive authority claim and can never
                # authorize completion.
                status = VerificationAssessmentDisposition.FAILED
                diagnostic = "verification execution reported failure"
            elif evidence.status in {
                VerificationExecutionStatus.TIMED_OUT,
                VerificationExecutionStatus.CANCELLED,
                VerificationExecutionStatus.ABORTED,
            }:
                status = VerificationAssessmentDisposition.INCONCLUSIVE
                diagnostic = "verification execution did not complete"
            else:
                validation = self._validator.validate(
                    verification_input=verification_input,
                    evidence=evidence,
                )
                if type(validation) is not VerificationEvidenceValidation:
                    raise VerificationAuthorityInputError(
                        "verification validator returned an invalid result"
                    )
                if validation.evidence_id != evidence.evidence_id:
                    raise VerificationAuthorityInputError(
                        "verification validator returned the wrong evidence identity"
                    )
                if validation.status == VerificationEvidenceValidationStatus.ACCEPTED:
                    status = VerificationAssessmentDisposition.SATISFIED
                    diagnostic = ""
                elif validation.status == VerificationEvidenceValidationStatus.REJECTED:
                    status = VerificationAssessmentDisposition.STALE
                    diagnostic = validation.reason or "verification evidence was rejected"
                else:
                    status = VerificationAssessmentDisposition.UNAVAILABLE
                    diagnostic = validation.reason or "verification evidence is unavailable"
            checks.append(
                VerificationCheckAssessment(
                    check_id=f"{requirement.requirement_id}:verification",
                    requirement_id=requirement.requirement_id,
                    status=status,
                    evidence=tuple(refs),
                    diagnostic=diagnostic,
                    scope=requirement.scope,
                    command_digest=requirement.command_digest,
                    execution_evidence_id=evidence.evidence_id,
                    execution_evidence_digest=evidence.evidence_digest,
                    exit_code=evidence.exit_code,
                    termination=evidence.termination,
                    result_digest=evidence.evidence_digest,
                )
            )
            if diagnostic:
                diagnostics.append(f"{requirement.requirement_id}: {diagnostic}")

        if not requirements:
            disposition = VerificationAssessmentDisposition.UNAVAILABLE
            diagnostics.append("no verification requirements were supplied")
        else:
            disposition = _aggregate_disposition(
                requirement=requirements,
                checks=tuple(checks),
            )
        if verification_input.published_plan_revision_id is None:
            disposition = VerificationAssessmentDisposition.STALE
            diagnostics.append("published plan revision binding is unavailable")
        return _build_assessment(
            verification_input=verification_input,
            assessment_id=assessment_identity,
            created_at=created_at,
            disposition=disposition,
            checks=tuple(checks),
            evidence=tuple(sorted(set(all_refs), key=_evidence_key)),
            diagnostics=tuple(diagnostics[:32]),
        )


def _build_assessment(
    *,
    verification_input: TrustedVerificationInput,
    assessment_id: str,
    created_at: str,
    disposition: VerificationAssessmentDisposition,
    checks: tuple[VerificationCheckAssessment, ...],
    evidence: tuple[VerificationEvidenceRef, ...],
    diagnostics: tuple[str, ...],
) -> VerificationAssessment:
    normalized_requirements = tuple(
        sorted(verification_input.requirements, key=lambda item: item.requirement_id)
    )
    normalized_checks = tuple(
        sorted(checks, key=lambda item: (item.requirement_id, item.check_id))
    )
    normalized_evidence = tuple(sorted(set(evidence), key=_evidence_key))
    normalized_diagnostics = tuple(sorted(diagnostics))
    semantic = {
        "schema_version": 1,
        "principal_id": verification_input.principal_id,
        "project_id": verification_input.project_id,
        "task_id": verification_input.task_id,
        "goal_spec_id": verification_input.goal_spec_id,
        "goal_spec_digest": verification_input.goal_spec_digest,
        "cognitive_state": verification_input.cognitive_state.value,
        "control_state_version": verification_input.control_state_version,
        "task_status": verification_input.task_status,
        "workspace_id": verification_input.workspace_id,
        "repository_id": verification_input.repository_id,
        "base_revision": verification_input.base_revision,
        "published_plan_revision_id": verification_input.published_plan_revision_id,
        "published_plan_revision_digest": verification_input.published_plan_revision_digest,
        "repository_generation": verification_input.repository_generation,
        "change_identity": verification_input.change_identity,
        "policy_digest": verification_input.policy_digest,
        "catalog_fingerprint": verification_input.catalog_fingerprint,
        "verification_algorithm_version": verification_input.verification_algorithm_version,
        "input_digest": verification_input.input_digest,
        "disposition": disposition.value,
        "requirements": [item.to_payload() for item in normalized_requirements],
        "checks": [item.to_payload() for item in normalized_checks],
        "evidence": [item.to_payload() for item in normalized_evidence],
        "diagnostics": list(normalized_diagnostics),
    }
    return VerificationAssessment(
        schema_version=1,
        assessment_id=assessment_id,
        task_id=verification_input.task_id,
        principal_id=verification_input.principal_id,
        project_id=verification_input.project_id,
        assessment_sequence=0,
        goal_spec_id=verification_input.goal_spec_id,
        goal_spec_digest=verification_input.goal_spec_digest,
        cognitive_state=verification_input.cognitive_state,
        control_state_version=verification_input.control_state_version,
        task_status=verification_input.task_status,
        workspace_id=verification_input.workspace_id,
        repository_id=verification_input.repository_id,
        base_revision=verification_input.base_revision,
        published_plan_revision_id=verification_input.published_plan_revision_id,
        published_plan_revision_digest=verification_input.published_plan_revision_digest,
        repository_generation=verification_input.repository_generation,
        change_identity=verification_input.change_identity,
        policy_digest=verification_input.policy_digest,
        catalog_fingerprint=verification_input.catalog_fingerprint,
        input_digest=verification_input.input_digest,
        disposition=disposition,
        requirements=normalized_requirements,
        checks=normalized_checks,
        evidence=normalized_evidence,
        diagnostics=normalized_diagnostics,
        assessment_digest=canonical_digest(semantic),
        created_at=created_at,
        verification_algorithm_version=verification_input.verification_algorithm_version,
    )


def _aggregate_disposition(
    *,
    requirement: tuple[VerificationRequirement, ...],
    checks: tuple[VerificationCheckAssessment, ...],
) -> VerificationAssessmentDisposition:
    status_by_id = {item.requirement_id: item.status for item in checks}
    required_statuses = [
        status_by_id[item.requirement_id]
        for item in requirement
        if item.required
    ]
    if not required_statuses:
        return VerificationAssessmentDisposition.SATISFIED
    for status in (
        VerificationAssessmentDisposition.STALE,
        VerificationAssessmentDisposition.UNAVAILABLE,
        VerificationAssessmentDisposition.FAILED,
        VerificationAssessmentDisposition.INCONCLUSIVE,
    ):
        if status in required_statuses:
            return status
    return VerificationAssessmentDisposition.SATISFIED


def _evidence_matches_input(
    evidence: VerificationExecutionEvidence,
    verification_input: TrustedVerificationInput,
) -> bool:
    return (
        evidence.workspace_id == verification_input.workspace_id
        and evidence.repository_id == verification_input.repository_id
        and evidence.base_revision == verification_input.base_revision
        and evidence.repository_generation == verification_input.repository_generation
        and evidence.change_identity == verification_input.change_identity
        and (
            verification_input.published_plan_revision_id is None
            or (
                bool(evidence.references)
                and any(
                    ref.kind is VerificationEvidenceKind.FINAL_MUTATION_ATTESTATION
                    for ref in evidence.references
                )
            )
        )
    )


def _evidence_matches_requirement(
    evidence: VerificationExecutionEvidence,
    requirement: VerificationRequirement,
) -> bool:
    """Bind execution evidence to the exact declared check definition.

    A verification requirement with a command digest must never be satisfied
    by a result produced for another command.  Requirements without a command
    digest are intentionally left to the configured evidence owner; the
    absence of a digest is not a caller-controlled positive authority flag.
    """
    return (
        evidence.requirement_id == requirement.requirement_id
        and (
            requirement.command_digest is None
            or evidence.command_digest == requirement.command_digest
        )
    )


def _m4_run_matches_input(
    execution_run: PlanExecutionRun,
    verification_run: VerificationRunBinding,
    attestation: FinalMutationAttestation,
    verification_step: VerificationStepRun,
    verification_input: TrustedVerificationInput,
    evidence: VerificationExecutionEvidence,
) -> bool:
    return (
        execution_run.execution_run_id
        == verification_run.execution_run_id
        == evidence.execution_run_id
        and verification_run.verification_run_id == evidence.verification_run_id
        and execution_run.task_id
        == verification_run.task_id
        == verification_input.task_id
        and execution_run.plan_id
        == verification_run.plan_id
        == verification_input.published_plan_revision_id
        and execution_run.plan_content_hash
        == verification_run.plan_content_hash
        == verification_input.published_plan_revision_digest
        and execution_run.workspace_id
        == verification_run.workspace_id
        == verification_input.workspace_id
        and execution_run.repository_id
        == verification_run.repository_id
        == verification_input.repository_id
        and execution_run.base_sha == verification_input.base_revision
        and str(execution_run.repository_generation)
        == verification_input.repository_generation
        and str(attestation.generation)
        == verification_input.repository_generation
        and attestation.execution_run_id == execution_run.execution_run_id
        and _enum_value(verification_run.status) == "passed"
        and verification_run.trusted_catalog_fingerprint
        == verification_input.catalog_fingerprint
        and verification_run.final_mutation_attestation_digest
        == attestation.attestation_digest
        and any(
            ref.kind is VerificationEvidenceKind.FINAL_MUTATION_ATTESTATION
            and ref.digest == attestation.attestation_digest
            for ref in evidence.references
        )
        and verification_step.step_run_id == evidence.verification_step_id
        and verification_step.verification_run_id == evidence.verification_run_id
        and verification_step.requirement_id == evidence.requirement_id
        and verification_step.command_digest == evidence.command_digest
        and _enum_value(verification_step.status) == "passed"
        and verification_step.exit_code == 0
        and (verification_step.stdout_digest or "")
        == (evidence.stdout_digest or "")
        and (verification_step.stderr_digest or "")
        == (evidence.stderr_digest or "")
        and bool(verification_step.output_truncated)
        == evidence.output_truncated
        and verification_step.completed_at is not None
    )


def _enum_value(value: object) -> str | None:
    candidate = getattr(value, "value", value)
    return candidate if isinstance(candidate, str) else None


def _passed_evidence_shape(evidence: VerificationExecutionEvidence) -> bool:
    """Require the explicit successful terminal postconditions from M4."""
    return (
        evidence.status is VerificationExecutionStatus.PASSED
        and evidence.exit_code == 0
        and evidence.termination is VerificationTermination.COMPLETED
        and not evidence.output_truncated
    )


def _evidence_refs(
    evidence: VerificationExecutionEvidence,
) -> tuple[VerificationEvidenceRef, ...]:
    refs = list(evidence.references)
    refs.extend(
        (
            VerificationEvidenceRef(
                kind=VerificationEvidenceKind.EXECUTION_RUN,
                ref_id=evidence.execution_run_id,
                digest=evidence.evidence_digest,
            ),
            VerificationEvidenceRef(
                kind=VerificationEvidenceKind.VERIFICATION_RUN,
                ref_id=evidence.verification_run_id,
                digest=evidence.evidence_digest,
            ),
        )
    )
    if evidence.verification_step_id is not None:
        refs.append(
            VerificationEvidenceRef(
                kind=VerificationEvidenceKind.VERIFICATION_STEP,
                ref_id=evidence.verification_step_id,
                digest=evidence.evidence_digest,
            )
        )
    return tuple(sorted(set(refs), key=_evidence_key))


def _evidence_key(value: VerificationEvidenceRef) -> tuple[str, str, str]:
    return (value.kind.value, value.ref_id, value.digest or "")


__all__ = [
    "FailClosedVerificationEvidenceValidator",
    "M4VerificationEvidenceValidator",
    "StructuralVerificationEvidenceValidator",
    "TrustedVerificationAuthority",
    "VerificationAuthorityError",
    "VerificationAuthorityInputError",
    "VerificationEvidenceValidation",
    "VerificationEvidenceValidationStatus",
    "VerificationEvidenceValidator",
]
