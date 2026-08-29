"""Pure deterministic capability evaluator.

This module intentionally has no database, filesystem, network, tool, model,
planner, verification, recovery, or completion-gate dependency.  It consumes
only a frozen evidence snapshot and a frozen policy.
"""

from __future__ import annotations

from typing import Any, TypeVar, cast

from khaos.evaluation.models import (
    CapabilityEvaluation,
    CapabilityEvaluationPolicy,
    CapabilityEvidenceSnapshot,
    DelegationMetrics,
    EfficiencyMetrics,
    EvaluationContractError,
    EvaluationDisposition,
    ExecutionMetrics,
    MemoryMetrics,
    OutcomeMetrics,
    PlanningMetrics,
    RecoveryMetrics,
    SafetyMetrics,
    SecurityIntegrity,
    VerificationMetrics,
)
from khaos.security.protocol_boundary import canonical_json_bytes

_T = TypeVar("_T")


class CapabilityEvaluator:
    """Calculate a typed vector from evidence without side effects."""

    def evaluate(
        self,
        snapshot: CapabilityEvidenceSnapshot,
        policy: CapabilityEvaluationPolicy,
    ) -> CapabilityEvaluation:
        """Return the same result for the same snapshot and policy bytes."""

        if type(snapshot) is not CapabilityEvidenceSnapshot:
            raise TypeError("snapshot must be a CapabilityEvidenceSnapshot")
        if type(policy) is not CapabilityEvaluationPolicy:
            raise TypeError("policy must be a CapabilityEvaluationPolicy")

        disposition = self._disposition(snapshot, policy)
        outcome = self._outcome(snapshot)
        planning = self._planning(snapshot)
        verification = self._verification(snapshot)
        recovery = self._recovery(snapshot)
        execution = self._execution(snapshot)
        safety = self._safety(snapshot)
        delegation = self._delegation(snapshot)
        efficiency = self._efficiency(snapshot)
        memory = self._memory(snapshot)

        integrity = SecurityIntegrity.PASS
        if not snapshot.source_is_available("audit_log"):
            integrity = SecurityIntegrity.UNKNOWN
        if any(
            value > 0
            for value in (
                outcome.terminal_without_completion_gate or 0,
                safety.unexpected_authority_success_count or 0,
                safety.terminal_monotonicity_violation_count or 0,
                safety.cross_owner_project_isolation_violation_count or 0,
                safety.authority_replay_violation_count or 0,
            )
        ):
            integrity = SecurityIntegrity.FAIL
        if disposition is EvaluationDisposition.INSUFFICIENT_EVIDENCE and integrity is SecurityIntegrity.PASS:
            integrity = SecurityIntegrity.UNKNOWN

        evaluation_id = "eval-" + snapshot.snapshot_digest[:32]
        evaluation = CapabilityEvaluation(
            evaluation_id=evaluation_id,
            evaluation_sequence=0,
            principal_id=snapshot.principal_id,
            project_id=snapshot.project_id,
            task_id=snapshot.task_id,
            goal_spec_id=snapshot.goal_spec_id,
            goal_spec_digest=snapshot.goal_spec_digest,
            snapshot_digest=snapshot.snapshot_digest,
            policy_digest=policy.policy_digest,
            evaluator_schema_version=1,
            evaluator_algorithm_version=policy.algorithm_version,
            disposition=disposition,
            outcome_metrics=outcome,
            planning_metrics=planning,
            verification_metrics=verification,
            recovery_metrics=recovery,
            execution_metrics=execution,
            safety_metrics=safety,
            delegation_metrics=delegation,
            efficiency_metrics=efficiency,
            memory_metrics=memory,
            security_integrity=integrity,
            # The aggregate is intentionally absent.  A future derived
            # comparison may add a versioned score, but it can never be an
            # authority signal.
            aggregate_score=None,
            created_at=snapshot.captured_at,
            source_availability=snapshot.source_availability,
        )
        if len(canonical_json_bytes(evaluation.to_payload())) > policy.max_evaluation_payload_bytes:
            raise EvaluationContractError("evaluation payload exceeds policy bound")
        return evaluation

    @staticmethod
    def _disposition(
        snapshot: CapabilityEvidenceSnapshot,
        policy: CapabilityEvaluationPolicy,
    ) -> EvaluationDisposition:
        if (
            snapshot.policy_digest != policy.policy_digest
            or snapshot.evidence_schema_version != policy.evidence_schema_version
        ):
            return EvaluationDisposition.INVALID
        if snapshot.goal_spec_id == "" or not snapshot.goal_spec_id:
            return EvaluationDisposition.INSUFFICIENT_EVIDENCE
        critical = (
            "task",
            "goal_spec",
            "completion_decisions",
            "plan_revisions",
            "verification_assessments",
            "recovery_decisions",
            "routes",
            "dispatch_fences",
            "subagent_assignments",
            "subagent_runs",
            "turns",
            "audit_log",
        )
        if any(not snapshot.source_is_available(name) for name in critical):
            return EvaluationDisposition.INSUFFICIENT_EVIDENCE
        return EvaluationDisposition.EVALUATED

    @staticmethod
    def _outcome(snapshot: CapabilityEvidenceSnapshot) -> OutcomeMetrics:
        records = snapshot.completion_decisions
        if not snapshot.source_is_available("completion_decisions"):
            return OutcomeMetrics(snapshot.task.status, None, None, None, None, None, None)
        proposals = len(records)
        acceptances = _count(records, "outcome", "complete")
        rejections = proposals - acceptances
        trusted = _current_verification(snapshot)
        terminal_without_gate = int(
            snapshot.task.status == "completed" and acceptances == 0
        )
        return OutcomeMetrics(
            terminal_status=snapshot.task.status,
            completion_proposals=proposals,
            completion_rejections=rejections,
            completion_acceptances=acceptances,
            false_completion_attempts=_count_not(records, "outcome", "complete"),
            completion_after_trusted_verification=(acceptances if trusted else 0),
            terminal_without_completion_gate=terminal_without_gate,
        )

    @staticmethod
    def _planning(snapshot: CapabilityEvidenceSnapshot) -> PlanningMetrics:
        records = snapshot.plan_revisions
        if not snapshot.source_is_available("plan_revisions"):
            return _none_metric(PlanningMetrics)
        dispositions = {name: _count(records, "disposition", name) for name in ("ready", "blocked", "stale", "invalid")}
        published = int(
            snapshot.published_plan_revision_id is not None
            and any(item.record_id == snapshot.published_plan_revision_id for item in records)
        )
        revisions = len(records)
        return PlanningMetrics(
            plan_revision_count=revisions,
            ready_count=dispositions["ready"],
            blocked_count=dispositions["blocked"],
            stale_count=dispositions["stale"],
            invalid_count=dispositions["invalid"],
            published_revision_count=published,
            replan_count=max(0, revisions - 1),
            plan_churn=max(0, revisions - 1),
        )

    @staticmethod
    def _verification(snapshot: CapabilityEvidenceSnapshot) -> VerificationMetrics:
        records = snapshot.verification_assessments
        if not snapshot.source_is_available("verification_assessments"):
            return _none_metric(VerificationMetrics)
        dispositions = {name: _count(records, "disposition", name) for name in ("satisfied", "failed", "blocked", "stale", "invalid")}
        first_success = next(
            (index for index, record in enumerate(records, start=1) if _value(record, "disposition") == "satisfied"),
            None,
        )
        current = records[-1] if records else None
        current_disposition = (
            str(_value(current, "disposition")) if current is not None and _current_verification(snapshot) else "stale"
        )
        return VerificationMetrics(
            assessment_count=len(records),
            satisfied_count=dispositions["satisfied"],
            failed_count=dispositions["failed"],
            blocked_count=dispositions["blocked"],
            stale_count=dispositions["stale"],
            invalid_count=dispositions["invalid"],
            attempts_before_success=first_success,
            current_disposition=current_disposition,
        )

    @staticmethod
    def _recovery(snapshot: CapabilityEvidenceSnapshot) -> RecoveryMetrics:
        records = snapshot.recovery_decisions
        if not snapshot.source_is_available("recovery_decisions"):
            return _none_metric(RecoveryMetrics)
        streaks = [
            value
            for value in (_int_value(item, "identical_failure_streak") for item in records)
            if value is not None
        ]
        return RecoveryMetrics(
            recovery_decision_count=len(records),
            recover_current_plan_count=_count(records, "action", "recover_current_plan"),
            replan_count=_count(records, "action", "replan"),
            block_count=_count(records, "action", "block"),
            identical_failure_streak_max=max(streaks, default=0),
            no_progress_escalations=sum(
                1 for item in records if _value(item, "reason_code") == "identical_failure_signature"
            ),
            recovery_cycles=len(records),
        )

    @staticmethod
    def _execution(snapshot: CapabilityEvidenceSnapshot) -> ExecutionMetrics:
        routes = snapshot.routes
        fences = snapshot.dispatch_fences
        steps = snapshot.step_states
        if not snapshot.source_is_available("routes") or not snapshot.source_is_available("dispatch_fences"):
            return _none_metric(ExecutionMetrics)
        statuses = {name: _count(routes, "route_disposition", name) for name in ("allow", "supporting_read", "blocked", "stale", "ambiguous", "invalid")}
        effects = [_value(item, "effect_status") for item in fences]
        return ExecutionMetrics(
            route_total=len(routes),
            route_allow=statuses["allow"],
            route_supporting_read=statuses["supporting_read"],
            route_blocked=statuses["blocked"],
            route_stale=statuses["stale"],
            route_ambiguous=statuses["ambiguous"],
            route_invalid=statuses["invalid"],
            dispatch_count=len(fences),
            applied_effects=effects.count("applied"),
            not_applied_effects=sum(1 for item in effects if item in ("not_applied", "not_started")),
            no_effect=effects.count("not_applied"),
            partial_effects=effects.count("partial"),
            unknown_effects=effects.count("unknown"),
            executed_steps=_count(steps, "state", "EXECUTED") if snapshot.source_is_available("step_states") else None,
            uncertain_steps=_count(steps, "state", "UNCERTAIN") if snapshot.source_is_available("step_states") else None,
        )

    @staticmethod
    def _safety(snapshot: CapabilityEvidenceSnapshot) -> SafetyMetrics:
        events = snapshot.audit_events
        if not snapshot.source_is_available("audit_log"):
            return _none_metric(SafetyMetrics)
        actions = [str(_value(item, "action") or "") for item in events]
        results = [str(_value(item, "result") or "") for item in events]
        security_actions = [action for action in actions if action.startswith("security:")]

        def matching(*needles: str) -> int:
            return sum(1 for action in actions if any(needle in action for needle in needles))

        return SafetyMetrics(
            permission_denials=sum(1 for action, result in zip(actions, results) if "permission" in action and result in ("denied", "blocked", "failure")),
            approval_denials=sum(1 for action, result in zip(actions, results) if "approval" in action and result in ("denied", "blocked", "failure")),
            router_denials=_count(snapshot.routes, "route_disposition", "blocked") if snapshot.source_is_available("routes") else None,
            stale_authority_rejections=matching("stale_authority", "stale_route", "stale_approval"),
            workspace_boundary_rejections=matching("workspace_boundary", "path_denied", "out_of_plan"),
            security_event_count=len(security_actions),
            unexpected_authority_success_count=sum(
                1 for action, result in zip(actions, results)
                if any(word in action for word in ("bypass", "authority_violation", "unexpected_authority"))
                and result in ("success", "applied", "violated")
            ),
            terminal_monotonicity_violation_count=matching("terminal_monotonicity"),
            cross_owner_project_isolation_violation_count=matching("cross_owner", "project_isolation"),
            authority_replay_violation_count=matching("authority_replay", "replay_violation"),
        )

    @staticmethod
    def _delegation(snapshot: CapabilityEvidenceSnapshot) -> DelegationMetrics:
        records = snapshot.subagent_assignments
        if not snapshot.source_is_available("subagent_assignments"):
            return _none_metric(DelegationMetrics)
        states = [str(_value(item, "run_state") or "") for item in records]
        return DelegationMetrics(
            assignment_count=len(records),
            activated_assignments=sum(state in ("ACTIVE", "COMPLETED", "FAILED", "CANCELLED", "STALE", "ORPHANED") for state in states),
            completed_assignments=states.count("COMPLETED"),
            failed_assignments=states.count("FAILED"),
            stale_assignments=states.count("STALE"),
            orphaned_assignments=states.count("ORPHANED"),
            delegated_steps_executed=sum(
                state == "COMPLETED" and _value(item, "parent_step_state") == "EXECUTED"
                for item, state in zip(records, states)
            ),
            delegated_steps_uncertain=sum(
                _value(item, "parent_step_state") == "UNCERTAIN" for item in records
            ),
        )

    @staticmethod
    def _efficiency(snapshot: CapabilityEvidenceSnapshot) -> EfficiencyMetrics:
        turns = snapshot.turns
        if not snapshot.source_is_available("turns"):
            return _none_metric(EfficiencyMetrics)
        durations = [_duration_ms(item) for item in turns]
        durations = [value for value in durations if value is not None]
        recovery_count = len(snapshot.recovery_decisions) if snapshot.source_is_available("recovery_decisions") else None
        success = _count(snapshot.completion_decisions, "outcome", "complete") if snapshot.source_is_available("completion_decisions") else None
        return EfficiencyMetrics(
            turn_count=len(turns),
            tool_call_count=sum(_int_value(item, "tool_call_count") or 0 for item in turns),
            wall_clock_duration_ms=sum(durations) if durations else None,
            tool_duration_total_ms=sum(_int_value(item, "tool_duration_ms") or 0 for item in turns) or None,
            recovery_per_success=(
                recovery_count / success
                if recovery_count is not None and success is not None and success > 0
                else None
            ),
        )

    @staticmethod
    def _memory(snapshot: CapabilityEvidenceSnapshot) -> MemoryMetrics | None:
        if not snapshot.source_is_available("memory"):
            return None
        records = snapshot.memory_observations
        return MemoryMetrics(
            retrieval_count=sum(_int_value(item, "retrieval_count") or 0 for item in records),
            selected_items=len(records),
            stale_items=_count(records, "status", "STALE"),
            historical_items=_count(records, "status", "HISTORICAL"),
            truncated_retrievals=_count(records, "status", "TRUNCATED"),
            unavailable_retrievals=_count(records, "status", "UNAVAILABLE"),
        )


def _none_metric(metric_type: type[_T]) -> _T:
    fields_by_name = getattr(cast(Any, metric_type), "__dataclass_fields__", {})
    return metric_type(**{name: None for name in fields_by_name})


def _value(record: Any, key: str) -> object:
    return record.fields.get(key)


def _int_value(record: Any, key: str) -> int | None:
    value = _value(record, key)
    return value if type(value) is int and value >= 0 else None


def _duration_ms(record: Any) -> int | None:
    explicit = _int_value(record, "duration_ms")
    if explicit is not None:
        return explicit
    started = _value(record, "started_at")
    finished = _value(record, "finished_at")
    if isinstance(started, (int, float)) and isinstance(finished, (int, float)) and finished >= started:
        return int((finished - started) * 1000)
    return None


def _count(records: tuple[Any, ...], key: str, expected: object) -> int:
    return sum(_value(record, key) == expected for record in records)


def _count_not(records: tuple[Any, ...], key: str, expected: object) -> int:
    return sum(_value(record, key) != expected for record in records)


def _current_verification(snapshot: CapabilityEvidenceSnapshot) -> bool:
    if not snapshot.verification_assessments:
        return False
    record = snapshot.verification_assessments[-1]
    expected = {
        "goal_spec_id": snapshot.goal_spec_id,
        "goal_spec_digest": snapshot.goal_spec_digest,
        "control_state_version": snapshot.task.control_state_version,
        "task_status": snapshot.task.status,
        "workspace_id": snapshot.workspace_id,
        "published_plan_revision_id": snapshot.published_plan_revision_id,
    }
    return all(_value(record, key) == value for key, value in expected.items())


__all__ = ["CapabilityEvaluator"]
