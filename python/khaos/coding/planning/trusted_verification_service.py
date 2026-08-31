"""M7.4 verification publication and completion-fact projection services.

The service composes the existing deterministic planning contracts, the
trusted-verification authority, and the owner-scoped assessment ledger.  It
never runs a command, calls a model, mutates a task, or grants a capability.
The completion provider is deliberately a projection: a current positive
assessment contributes typed evidence, while lifecycle completion remains
owned exclusively by ``CompletionGate``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast
from uuid import uuid4

from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionEvidenceKind,
    CompletionEvidenceRef,
    CriterionAssessment,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
    CompletionEvaluationSnapshot,
)
from khaos.agent.control.completion_flow import (
    CompletionFactBundle,
    CompletionProposal,
    VerificationCompletionFact,
    VerificationFactStatus,
)
from khaos.agent.control.goal import GoalSpec
from khaos.coding.planning.revision import (
    PlanningVerificationIntent,
    PlanRevision,
)
from khaos.coding.planning.trusted_verification_authority import (
    TrustedVerificationAuthority,
)
from khaos.coding.planning.verification_assessment import (
    TrustedVerificationInput,
    VerificationAssessment,
    VerificationAssessmentDisposition,
    VerificationEvidenceKind,
    VerificationEvidenceRef,
    VerificationExecutionEvidence,
    VerificationRequirement,
)
from khaos.coding.planning.verification_assessment_repository import (
    StoredVerificationAssessment,
    VerificationAssessmentRepository,
    VerificationTaskSnapshot,
)
from khaos.security.protocol_boundary import canonical_digest


class TrustedVerificationServiceError(RuntimeError):
    """Base service error for trusted-verification composition."""


class VerificationEventType(str, Enum):
    """Bounded observability events emitted by a verification attempt."""

    STARTED = "verification.started"
    ASSESSED = "verification.assessed"
    STALE = "verification.stale"
    UNAVAILABLE = "verification.unavailable"


@dataclass(frozen=True, slots=True)
class VerificationObservationEvent:
    """Bounded, non-authoritative verification observability record.

    The event contains identities, digests, and aggregate counters only.  It
    never carries stdout/stderr, repository content, an authority token, or a
    lifecycle instruction.  Durable event adapters may persist its payload,
    but event history is never consulted as verification authority.
    """

    event_type: VerificationEventType
    task_id: str
    assessment_id: str
    input_digest: str
    assessment_digest: str | None = None
    disposition: VerificationAssessmentDisposition | None = None
    required_check_count: int = 0
    passed_check_count: int = 0
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.event_type) is not VerificationEventType:
            raise TrustedVerificationServiceError("event_type is invalid")
        for label, value in (
            ("task_id", self.task_id),
            ("assessment_id", self.assessment_id),
            ("input_digest", self.input_digest),
        ):
            if type(value) is not str or not value or len(value) > 512:
                raise TrustedVerificationServiceError(f"{label} is invalid")
        if self.assessment_digest is not None and (
            type(self.assessment_digest) is not str
            or len(self.assessment_digest) != 64
        ):
            raise TrustedVerificationServiceError("assessment_digest is invalid")
        if self.disposition is not None and type(
            self.disposition
        ) is not VerificationAssessmentDisposition:
            raise TrustedVerificationServiceError("disposition is invalid")
        for label, value in (
            ("required_check_count", self.required_check_count),
            ("passed_check_count", self.passed_check_count),
        ):
            if type(value) is not int or value < 0 or value > 10_000:
                raise TrustedVerificationServiceError(f"{label} is invalid")
        if self.passed_check_count > self.required_check_count:
            raise TrustedVerificationServiceError(
                "passed_check_count cannot exceed required_check_count"
            )
        if self.reason_code is not None and (
            type(self.reason_code) is not str
            or not self.reason_code
            or len(self.reason_code) > 128
        ):
            raise TrustedVerificationServiceError("reason_code is invalid")

    def to_payload(self) -> dict[str, object]:
        """Return the bounded transport payload for an event sink."""
        return {
            "task_id": self.task_id,
            "assessment_id": self.assessment_id,
            "input_digest": self.input_digest,
            "assessment_digest": self.assessment_digest,
            "disposition": (
                self.disposition.value if self.disposition is not None else None
            ),
            "required_check_count": self.required_check_count,
            "passed_check_count": self.passed_check_count,
            "reason_code": self.reason_code,
        }


class VerificationEventSink(Protocol):
    """Port for bounded verification observability."""

    async def emit_verification_event(
        self, event: VerificationObservationEvent
    ) -> None:
        """Persist or forward one event without granting authority."""
        ...


class TurnVerificationEventSink:
    """Adapt typed verification events to the existing turn event ledger."""

    def __init__(self, turn: object) -> None:
        if not callable(getattr(turn, "emit", None)):
            raise TypeError("turn must expose an async emit method")
        self._turn = turn

    async def emit_verification_event(
        self, event: VerificationObservationEvent
    ) -> None:
        """Append a bounded event; the turn ledger remains passive history."""
        if type(event) is not VerificationObservationEvent:
            raise TypeError("event must be a VerificationObservationEvent")
        emit = cast(Any, self._turn).emit
        await emit(event.event_type.value, event.to_payload())


@dataclass(frozen=True, slots=True)
class TrustedVerificationPublication:
    """The immutable assessment and its owner-scoped ledger sequence."""

    assessment: VerificationAssessment
    stored: StoredVerificationAssessment


class TrustedVerificationService:
    """Compose authority assessment with append-only durable publication."""

    def __init__(
        self,
        *,
        authority: TrustedVerificationAuthority,
        repository: VerificationAssessmentRepository,
    ) -> None:
        if type(authority) is not TrustedVerificationAuthority:
            raise TypeError("authority must be a TrustedVerificationAuthority")
        self._authority = authority
        self._repository = repository

    @property
    def authority(self) -> TrustedVerificationAuthority:
        """Return the deterministic assessment authority."""
        return self._authority

    @property
    def repository(self) -> VerificationAssessmentRepository:
        """Return the owner-scoped immutable assessment repository."""
        return self._repository

    def assess(
        self,
        verification_input: TrustedVerificationInput,
        *,
        assessment_id: str | None = None,
        created_at: str = "authority",
    ) -> VerificationAssessment:
        """Compute one assessment without persistence or lifecycle effects."""
        return self._authority.assess(
            verification_input,
            assessment_id=assessment_id,
            created_at=created_at,
        )

    async def assess_and_append(
        self,
        verification_input: TrustedVerificationInput,
        *,
        principal_id: str,
        project_id: str,
        assessment_id: str | None = None,
        created_at: str | None = None,
        event_sink: VerificationEventSink | None = None,
    ) -> TrustedVerificationPublication:
        """Assess then publish, with the repository's binding fence.

        The optional event sink is observability only.  Sink failures are
        isolated from assessment publication so an event transport cannot
        become an authority or availability bypass.
        """
        if type(verification_input) is not TrustedVerificationInput:
            raise TypeError("verification_input must be a TrustedVerificationInput")
        effective_assessment_id = (
            uuid4().hex if assessment_id is None else assessment_id
        )
        await _emit_observation_event(
            event_sink,
            VerificationObservationEvent(
                event_type=VerificationEventType.STARTED,
                task_id=verification_input.task_id,
                assessment_id=effective_assessment_id,
                input_digest=verification_input.input_digest,
                required_check_count=sum(
                    1 for item in verification_input.requirements if item.required
                ),
                reason_code="assessment_started",
            ),
        )
        assessment = self.assess(
            verification_input,
            assessment_id=effective_assessment_id,
            created_at=created_at or "authority",
        )
        await _emit_observation_event(
            event_sink,
            _assessment_event(assessment, event_type=VerificationEventType.ASSESSED),
        )
        if assessment.disposition is VerificationAssessmentDisposition.STALE:
            await _emit_observation_event(
                event_sink,
                _assessment_event(assessment, event_type=VerificationEventType.STALE),
            )
        elif assessment.disposition is VerificationAssessmentDisposition.UNAVAILABLE:
            await _emit_observation_event(
                event_sink,
                _assessment_event(
                    assessment, event_type=VerificationEventType.UNAVAILABLE
                ),
            )
        stored = await self._repository.append(
            assessment,
            principal_id=principal_id,
            project_id=project_id,
            created_at=created_at,
        )
        return TrustedVerificationPublication(assessment=assessment, stored=stored)

    async def current_assessment(
        self,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
    ) -> StoredVerificationAssessment | None:
        """Read the current owner-scoped assessment projection."""
        return await self._repository.get_current_for_task(
            task_id,
            principal_id=principal_id,
            project_id=project_id,
        )


def verification_requirements_from_plan(
    plan: PlanRevision,
) -> tuple[VerificationRequirement, ...]:
    """Convert published planning intents into stable verification IDs.

    ``PlanningVerificationIntent`` remains declarative.  The generated IDs
    are scoped to the exact durable plan revision and ordinal of its
    canonical intent ordering; they do not imply that any command has run.
    """
    if type(plan) is not PlanRevision:
        raise TypeError("plan must be a PlanRevision")
    if not plan.plan_revision_id:
        raise ValueError("verification requirements require a persisted plan revision")
    intents = tuple(
        sorted(
            plan.verification_intents,
            key=_intent_sort_key,
        )
    )
    return tuple(
        _verification_requirement(
            plan_revision_id=plan.plan_revision_id,
            ordinal=ordinal,
            intent=intent,
        )
        for ordinal, intent in enumerate(intents, start=1)
    )


def build_trusted_verification_input(
    *,
    task_snapshot: VerificationTaskSnapshot,
    goal_spec: GoalSpec,
    plan: PlanRevision | None,
    policy_digest: str,
    catalog_fingerprint: str,
    repository_generation: str | None,
    change_identity: str | None,
    evidence: tuple[VerificationExecutionEvidence, ...] = (),
) -> TrustedVerificationInput:
    """Build the exact typed input for one post-change verification attempt.

    All task/GoalSpec/plan bindings are copied from already owner-scoped
    durable objects.  This helper performs no repository or filesystem reads.
    The caller must obtain ``repository_generation``/``change_identity`` from
    an audited post-change evidence owner rather than from a host path.
    """
    if type(task_snapshot) is not VerificationTaskSnapshot:
        raise TypeError("task_snapshot must be a VerificationTaskSnapshot")
    if type(goal_spec) is not GoalSpec:
        raise TypeError("goal_spec must be a GoalSpec")
    if plan is not None and type(plan) is not PlanRevision:
        raise TypeError("plan must be a PlanRevision or None")
    if plan is not None:
        if (
            plan.task_id != task_snapshot.task_id
            or plan.principal_id != task_snapshot.principal_id
            or plan.project_id != task_snapshot.project_id
            or plan.goal_spec_id != goal_spec.goal_spec_id
            or plan.goal_spec_digest != goal_spec.semantic_digest
            or plan.workspace_id != task_snapshot.workspace_id
            or plan.repository_id != task_snapshot.repository_id
            or plan.base_revision != task_snapshot.base_revision
            or plan.plan_revision_id != task_snapshot.published_plan_revision_id
        ):
            raise TrustedVerificationServiceError(
                "published plan is not bound to the current verification snapshot"
            )
        published_plan_id = plan.plan_revision_id
        published_plan_digest = plan.plan_semantic_digest
    else:
        published_plan_id = task_snapshot.published_plan_revision_id
        published_plan_digest = None
        if published_plan_id is not None:
            raise TrustedVerificationServiceError(
                "published plan must be loaded when the task has a published identity"
            )
    typed_evidence = tuple(evidence)
    if any(type(item) is not VerificationExecutionEvidence for item in typed_evidence):
        raise TrustedVerificationServiceError(
            "verification input evidence must contain typed execution evidence"
        )
    return TrustedVerificationInput(
        schema_version=1,
        principal_id=task_snapshot.principal_id,
        project_id=task_snapshot.project_id,
        task_id=task_snapshot.task_id,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        cognitive_state=task_snapshot.cognitive_state,
        control_state_version=task_snapshot.control_state_version,
        task_status=task_snapshot.task_status,
        workspace_id=_required_snapshot_text(task_snapshot.workspace_id, "workspace_id"),
        repository_id=_required_snapshot_text(task_snapshot.repository_id, "repository_id"),
        base_revision=task_snapshot.base_revision,
        published_plan_revision_id=published_plan_id,
        published_plan_revision_digest=published_plan_digest,
        repository_generation=repository_generation,
        change_identity=change_identity,
        policy_digest=policy_digest,
        catalog_fingerprint=catalog_fingerprint,
        requirements=verification_requirements_from_plan(plan) if plan is not None else (),
        evidence=typed_evidence,
    )


class TrustedVerificationFactProvider:
    """Project only current durable assessment facts into completion flow."""

    def __init__(
        self,
        *,
        repository: VerificationAssessmentRepository,
        principal_id: str,
        project_id: str,
    ) -> None:
        if type(principal_id) is not str or not principal_id:
            raise ValueError("principal_id must be a non-empty string")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._repository = repository
        self._principal_id = principal_id
        self._project_id = project_id

    async def collect(
        self,
        *,
        proposal: CompletionProposal,
        goal_spec: GoalSpec,
        snapshot: CompletionEvaluationSnapshot,
    ) -> CompletionFactBundle:
        """Return bounded current assessment facts; never trust model prose."""
        if type(proposal) is not CompletionProposal:
            raise TypeError("proposal must be a CompletionProposal")
        if type(goal_spec) is not GoalSpec:
            raise TypeError("goal_spec must be a GoalSpec")
        if type(snapshot) is not CompletionEvaluationSnapshot:
            raise TypeError("snapshot must be a CompletionEvaluationSnapshot")
        if (
            snapshot.task_id != proposal.task_id
            or snapshot.goal_spec_id != goal_spec.goal_spec_id
            or snapshot.goal_spec_digest != goal_spec.semantic_digest
        ):
            raise TrustedVerificationServiceError(
                "completion proposal snapshot is not bound to the canonical GoalSpec"
            )
        stored = await self._repository.get_current_for_task(
            proposal.task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if stored is None:
            return CompletionFactBundle(
                constraints=(
                    CompletionConstraint(
                        code=CompletionConstraintCode.VERIFICATION_MISSING,
                        subject_id=proposal.task_id,
                    ),
                )
            )
        assessment = stored.assessment
        if (
            assessment.task_id != snapshot.task_id
            or assessment.principal_id != self._principal_id
            or assessment.project_id != self._project_id
            or assessment.goal_spec_id != snapshot.goal_spec_id
            or assessment.goal_spec_digest != snapshot.goal_spec_digest
            or assessment.cognitive_state is not snapshot.cognitive_state
            or assessment.control_state_version != snapshot.control_state_version
            or assessment.task_status != snapshot.task_status
            or assessment.workspace_id != snapshot.workspace_id
        ):
            raise TrustedVerificationServiceError(
                "current verification assessment is not bound to the proposal snapshot"
            )
        completion_evidence = _completion_evidence(assessment.evidence)
        fact_status, constraint_code = _fact_projection(assessment.disposition)
        requirement_assessments = _matching_requirement_assessments(
            assessment, goal_spec=goal_spec
        )
        criterion_assessments = _matching_criterion_assessments(
            assessment, goal_spec=goal_spec
        )
        # The provider's public contract receives the GoalSpec above, but the
        # IDs are intentionally matched only when a future caller supplies a
        # corresponding declaration.  Aggregate verification never satisfies
        # an unrelated user goal by itself.
        return CompletionFactBundle(
            requirement_assessments=requirement_assessments,
            criterion_assessments=criterion_assessments,
            evidence=completion_evidence,
            constraints=(
                ()
                if constraint_code is None
                else (
                    CompletionConstraint(
                        code=constraint_code,
                        subject_id=assessment.assessment_id,
                        evidence=completion_evidence,
                    ),
                )
            ),
            verification_facts=(
                VerificationCompletionFact(
                    assessment_id=assessment.assessment_id,
                    assessment_digest=assessment.assessment_digest,
                    status=fact_status,
                    evidence=completion_evidence,
                ),
            ),
        )


def _intent_sort_key(intent: PlanningVerificationIntent) -> tuple[Any, ...]:
    return (
        intent.verification_type,
        intent.scope,
        intent.expected_result,
        intent.required,
        intent.risk_level.value,
        intent.command or (),
        tuple(item.ref_id for item in intent.evidence),
    )


async def _emit_observation_event(
    sink: VerificationEventSink | None,
    event: VerificationObservationEvent,
) -> None:
    """Best-effort event delivery that cannot affect verification authority."""
    if sink is None:
        return
    try:
        await sink.emit_verification_event(event)
    except Exception:  # noqa: BLE001 - observability cannot affect authority
        # Observability is intentionally non-authoritative.  A broken event
        # sink must never turn an assessment into a different decision or
        # silently grant a capability.
        return


def _assessment_event(
    assessment: VerificationAssessment,
    *,
    event_type: VerificationEventType,
) -> VerificationObservationEvent:
    required_check_count = sum(
        1 for item in assessment.requirements if item.required
    )
    passed_check_count = sum(
        1
        for item in assessment.checks
        if item.status is VerificationAssessmentDisposition.SATISFIED
        and item.requirement_id in {
            requirement.requirement_id
            for requirement in assessment.requirements
            if requirement.required
        }
    )
    return VerificationObservationEvent(
        event_type=event_type,
        task_id=assessment.task_id,
        assessment_id=assessment.assessment_id,
        input_digest=assessment.input_digest,
        assessment_digest=assessment.assessment_digest,
        disposition=assessment.disposition,
        required_check_count=required_check_count,
        passed_check_count=passed_check_count,
        reason_code=assessment.disposition.value,
    )


def _verification_requirement(
    *,
    plan_revision_id: str,
    ordinal: int,
    intent: PlanningVerificationIntent,
) -> VerificationRequirement:
    definition = {
        "verification_type": intent.verification_type,
        "scope": intent.scope,
        "expected_result": intent.expected_result,
        "command": list(intent.command) if intent.command is not None else None,
        "risk_level": intent.risk_level.value,
    }
    source_intent_id = canonical_digest(
        {"plan_revision_id": plan_revision_id, "ordinal": ordinal, "intent": definition}
    )
    return VerificationRequirement(
        requirement_id=f"{plan_revision_id}:verification:{ordinal:04d}",
        verification_type=intent.verification_type,
        scope=intent.scope,
        required=intent.required,
        command_digest=canonical_digest(definition),
        source_intent_id=source_intent_id,
    )


def _required_snapshot_text(value: str | None, label: str) -> str:
    if type(value) is not str or not value:
        raise TrustedVerificationServiceError(f"{label} is unavailable")
    return value


def _completion_evidence(
    refs: tuple[VerificationEvidenceRef, ...],
) -> tuple[CompletionEvidenceRef, ...]:
    mapping = {
        VerificationEvidenceKind.EXECUTION_RUN: CompletionEvidenceKind.VERIFICATION_RUN,
        VerificationEvidenceKind.VERIFICATION_RUN: CompletionEvidenceKind.VERIFICATION_RUN,
        VerificationEvidenceKind.VERIFICATION_STEP: CompletionEvidenceKind.VERIFICATION_RUN,
        VerificationEvidenceKind.FINAL_MUTATION_ATTESTATION: CompletionEvidenceKind.CHANGESET,
        VerificationEvidenceKind.CHANGESET: CompletionEvidenceKind.CHANGESET,
    }
    result = {
        CompletionEvidenceRef(
            kind=mapping[ref.kind],
            ref_id=ref.ref_id,
            digest=ref.digest,
        )
        for ref in refs
    }
    return tuple(sorted(result, key=lambda item: (item.kind.value, item.ref_id, item.digest or "")))


def _fact_projection(
    disposition: VerificationAssessmentDisposition,
) -> tuple[VerificationFactStatus, CompletionConstraintCode | None]:
    if disposition is VerificationAssessmentDisposition.SATISFIED:
        return VerificationFactStatus.SATISFIED, None
    if disposition is VerificationAssessmentDisposition.FAILED:
        return VerificationFactStatus.UNSATISFIED, CompletionConstraintCode.VERIFICATION_FAILED
    return VerificationFactStatus.UNKNOWN, CompletionConstraintCode.VERIFICATION_MISSING


def _matching_requirement_assessments(
    assessment: VerificationAssessment,
    *,
    goal_spec: GoalSpec | None,
) -> tuple[RequirementAssessment, ...]:
    if goal_spec is None:
        return ()
    goal_ids = {item.requirement_id for item in goal_spec.requirements}
    return tuple(
        RequirementAssessment(
            requirement_id=check.requirement_id,
            status=_assessment_status(check.status),
            evidence=_completion_evidence(check.evidence),
        )
        for check in assessment.checks
        if check.requirement_id in goal_ids
    )


def _matching_criterion_assessments(
    assessment: VerificationAssessment,
    *,
    goal_spec: GoalSpec | None,
) -> tuple[CriterionAssessment, ...]:
    if goal_spec is None:
        return ()
    criterion_ids = {item.criterion_id for item in goal_spec.acceptance_criteria}
    return tuple(
        CriterionAssessment(
            criterion_id=check.requirement_id,
            status=_assessment_status(check.status),
            evidence=_completion_evidence(check.evidence),
        )
        for check in assessment.checks
        if check.requirement_id in criterion_ids
    )


def _assessment_status(value: VerificationAssessmentDisposition) -> AssessmentStatus:
    if value is VerificationAssessmentDisposition.SATISFIED:
        return AssessmentStatus.SATISFIED
    if value is VerificationAssessmentDisposition.FAILED:
        return AssessmentStatus.UNSATISFIED
    return AssessmentStatus.UNKNOWN


__all__ = [
    "TrustedVerificationFactProvider",
    "TrustedVerificationPublication",
    "TrustedVerificationService",
    "TrustedVerificationServiceError",
    "TurnVerificationEventSink",
    "VerificationEventSink",
    "VerificationEventType",
    "VerificationObservationEvent",
    "build_trusted_verification_input",
    "verification_requirements_from_plan",
]
