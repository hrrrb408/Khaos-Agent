"""Durable completion continuation recovery for coding tasks.

M7.1.8 deliberately separates durable history from continuation
interpretation.  A completion decision and a gate event are immutable
records; neither is a restart capability.  This module reads those records
through owner-scoped ports and deterministically reports what a later
controller must consider next.  It never calls a model, planner, evaluator,
gate, or task-lifecycle writer.
"""

from __future__ import annotations

import json
import math
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from khaos.agent.control.completion import CompletionDecision, CompletionOutcome
from khaos.agent.control.completion_evaluator import CompletionEvaluationSnapshot
from khaos.agent.control.completion_gate import CompletionGateStatus
from khaos.agent.control.completion_repository import (
    CompletionDecisionRepositoryError,
    StoredCompletionDecision,
)
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import GoalSpecRepositoryError
from khaos.agent.control.state import AgentCognitiveState

_MAX_ID_LENGTH = 512
_MAX_REASON_LENGTH = 512
MAX_COMPLETION_GATE_PAYLOAD_BYTES = 4096
# Recovery reads only a bounded tail of the existing turn ledger.  A current
# decision's gate event is expected to be in this tail; if it is not, the
# absence of a usable matching event is conservative and requires a fresh
# evaluation rather than replaying old history.
MAX_COMPLETION_GATE_HISTORY_RECORDS = 256

_TASK_STATUSES = frozenset(
    {
        "pending",
        "running",
        "blocked",
        "waiting_test",
        "fixing",
        "completed",
        "failed",
        "cancelled",
    }
)
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})
_GATE_PAYLOAD_KEYS = frozenset(
    {
        "task_id",
        "decision_id",
        "decision_digest",
        "gate_status",
        "resulting_task_status",
        "reason",
    }
)
_GATE_REQUIRED_PAYLOAD_KEYS = frozenset(
    {
        "task_id",
        "decision_id",
        "decision_digest",
        "gate_status",
        "resulting_task_status",
    }
)


class CompletionContinuationState(str, Enum):
    """What a future control-plane controller must consider next.

    These values are neither ``TaskStatus`` nor ``AgentCognitiveState``.
    They describe a durable control-plane interpretation only.  In
    particular, none of them causes a planner, model, gate, or lifecycle
    transition to run automatically.
    """

    NO_DECISION = "no_decision"
    REPLAN_REQUIRED = "replan_required"
    REEVALUATION_REQUIRED = "reevaluation_required"
    AUTHORITY_REQUIRED = "authority_required"
    EXTERNAL_BLOCKED = "external_blocked"
    FAILURE_REVIEW_REQUIRED = "failure_review_required"
    TERMINAL_COMPLETED = "terminal_completed"
    TERMINAL_FAILED = "terminal_failed"
    TERMINAL_CANCELLED = "terminal_cancelled"
    INTEGRITY_ERROR = "integrity_error"


@dataclass(frozen=True, slots=True)
class CompletionGateHistoryRecord:
    """Owner-scoped raw record returned by the existing turn-event ledger.

    The database adapter returns the payload only when it is within the
    bounded byte budget and always reports its original byte count.  An
    over-limit row is represented without its body so recovery can reject it
    without materializing an unbounded event.  The recovery layer performs
    strict shape and binding validation before the record can influence
    continuation interpretation.
    """

    turn_id: str
    attempt_id: str
    task_id: str
    event_sequence: int
    event_type: str
    payload_json: str
    created_at: float
    turn_started_at: float
    payload_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class CompletionGateHistoryEntry:
    """Strictly decoded, bounded ``completion.gated`` event."""

    turn_id: str
    attempt_id: str
    task_id: str
    event_sequence: int
    created_at: float
    turn_started_at: float
    decision_id: str
    decision_digest: str | None
    gate_status: CompletionGateStatus
    resulting_task_status: str | None

    @classmethod
    def from_record(
        cls,
        record: CompletionGateHistoryRecord,
    ) -> CompletionGateHistoryEntry | None:
        """Decode one ledger record, rejecting malformed/non-bound events."""
        if type(record) is not CompletionGateHistoryRecord:
            return None
        if not _valid_id(record.turn_id) or not _valid_id(record.attempt_id):
            return None
        if not _valid_id(record.task_id):
            return None
        if type(record.event_sequence) is not int or record.event_sequence < 1:
            return None
        if record.event_type != "completion.gated":
            return None
        if type(record.payload_json) is not str:
            return None
        payload_bytes = (
            len(record.payload_json.encode("utf-8"))
            if record.payload_bytes is None
            else record.payload_bytes
        )
        if type(payload_bytes) is not int or payload_bytes < 0:
            return None
        if payload_bytes > MAX_COMPLETION_GATE_PAYLOAD_BYTES:
            return None
        if len(record.payload_json.encode("utf-8")) > MAX_COMPLETION_GATE_PAYLOAD_BYTES:
            return None
        if not _finite_number(record.created_at) or not _finite_number(
            record.turn_started_at
        ):
            return None
        try:
            payload = json.loads(record.payload_json)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
            return None
        if type(payload) is not dict:
            return None
        payload_keys = frozenset(payload)
        if not _GATE_REQUIRED_PAYLOAD_KEYS <= payload_keys:
            return None
        if not payload_keys <= _GATE_PAYLOAD_KEYS:
            return None

        task_id = payload.get("task_id")
        decision_id = payload.get("decision_id")
        if (
            type(task_id) is not str
            or not _valid_id(task_id)
            or type(decision_id) is not str
            or not _valid_id(decision_id)
        ):
            return None
        if task_id != record.task_id:
            return None

        decision_digest = payload.get("decision_digest")
        if decision_digest is not None and not _valid_id(decision_digest):
            return None
        resulting_task_status = payload.get("resulting_task_status")
        if resulting_task_status is not None and not _valid_id(
            resulting_task_status
        ):
            return None
        reason = payload.get("reason", "")
        if type(reason) is not str or len(reason) > _MAX_REASON_LENGTH:
            return None
        try:
            gate_status = CompletionGateStatus(payload["gate_status"])
        except (KeyError, TypeError, ValueError):
            return None

        return cls(
            turn_id=record.turn_id,
            attempt_id=record.attempt_id,
            task_id=task_id,
            event_sequence=record.event_sequence,
            created_at=record.created_at,
            turn_started_at=record.turn_started_at,
            decision_id=decision_id,
            decision_digest=decision_digest,
            gate_status=gate_status,
            resulting_task_status=resulting_task_status,
        )

    @property
    def ordering_key(self) -> tuple[float, float, str, int]:
        """Return a deterministic event ordering key."""
        return (
            self.created_at,
            self.turn_started_at,
            self.turn_id,
            self.event_sequence,
        )


@dataclass(frozen=True, slots=True)
class CompletionRecoveryState:
    """Bounded, read-only continuation interpretation for one task."""

    task_id: str
    continuation_state: CompletionContinuationState
    task_status: str | None = None
    cognitive_state: AgentCognitiveState | None = None
    control_state_version: int | None = None
    workspace_id: str | None = None
    latest_decision_id: str | None = None
    latest_decision_digest: str | None = None
    latest_decision_sequence: int | None = None
    decision_outcome: CompletionOutcome | None = None
    gate_status: CompletionGateStatus | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        _require_id(self.task_id, label="task_id")
        if type(self.continuation_state) is not CompletionContinuationState:
            raise ValueError(
                "continuation_state must be a CompletionContinuationState"
            )
        for value, label in (
            (self.task_status, "task_status"),
            (self.workspace_id, "workspace_id"),
            (self.latest_decision_id, "latest_decision_id"),
            (self.latest_decision_digest, "latest_decision_digest"),
        ):
            if value is not None:
                _require_id(value, label=label)
        if self.cognitive_state is not None and type(
            self.cognitive_state
        ) is not AgentCognitiveState:
            raise ValueError("cognitive_state must be an AgentCognitiveState")
        if self.control_state_version is not None and (
            type(self.control_state_version) is not int
            or self.control_state_version < 0
        ):
            raise ValueError("control_state_version must be non-negative")
        if self.latest_decision_sequence is not None and (
            type(self.latest_decision_sequence) is not int
            or self.latest_decision_sequence < 1
        ):
            raise ValueError("latest_decision_sequence must be positive")
        if self.decision_outcome is not None and type(
            self.decision_outcome
        ) is not CompletionOutcome:
            raise ValueError("decision_outcome must be a CompletionOutcome")
        if self.gate_status is not None and type(
            self.gate_status
        ) is not CompletionGateStatus:
            raise ValueError("gate_status must be a CompletionGateStatus")
        if type(self.reason) is not str or len(self.reason) > _MAX_REASON_LENGTH:
            raise ValueError(
                f"reason must be a string of at most {_MAX_REASON_LENGTH} characters"
            )

    def to_bounded_fact(self) -> dict[str, object | None]:
        """Return the small context projection allowed across model context."""
        return {
            "task_id": self.task_id,
            "latest_decision_id": self.latest_decision_id,
            "latest_decision_digest": self.latest_decision_digest,
            "latest_decision_sequence": self.latest_decision_sequence,
            "continuation_state": self.continuation_state.value,
            "decision_outcome": (
                self.decision_outcome.value
                if self.decision_outcome is not None
                else None
            ),
            "gate_status": (
                self.gate_status.value if self.gate_status is not None else None
            ),
        }


class CompletionRecoveryDecisionReader(Protocol):
    """Owner-scoped decision and current-snapshot read port."""

    async def read_current_task_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        goal_spec: GoalSpec,
    ) -> CompletionEvaluationSnapshot | None:
        """Read physical task state plus its durable workspace projection."""
        ...

    async def get_latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredCompletionDecision | None:
        """Read the durable history head by decision sequence."""
        ...


class CompletionRecoveryGoalSpecReader(Protocol):
    """Owner-scoped canonical GoalSpec read port."""

    async def get_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> GoalSpec | None:
        """Load the canonical GoalSpec without task-text fallback."""
        ...


class CompletionGateHistoryReader(Protocol):
    """Owner-scoped read port for existing durable turn gate events."""

    async def list_completion_gate_history(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> tuple[CompletionGateHistoryRecord, ...]:
        """Return bounded raw ``completion.gated`` event records."""
        ...


class DatabaseCompletionGateHistoryReader:
    """Adapter that keeps database method names out of recovery logic."""

    def __init__(self, database: object) -> None:
        self._database = database

    async def list_completion_gate_history(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> tuple[CompletionGateHistoryRecord, ...]:
        """Read the existing turn-event ledger through its owner-scoped API."""
        method = cast(Any, getattr(self._database, "list_completion_gate_history", None))
        if method is None or not callable(method):
            raise RuntimeError("database has no completion gate history reader")
        records = await cast(Callable[..., Awaitable[Any]], method)(
            task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if type(records) is not tuple or any(
            type(record) is not CompletionGateHistoryRecord for record in records
        ):
            raise RuntimeError("database returned an invalid gate history shape")
        return records


class CompletionRecoveryResolver:
    """Pure deterministic interpretation of durable completion history."""

    @staticmethod
    def resolve(
        *,
        current_task_snapshot: CompletionEvaluationSnapshot,
        latest_completion_decision: StoredCompletionDecision
        | CompletionDecision
        | None,
        latest_gate_attempt: CompletionGateHistoryEntry | None = None,
    ) -> CompletionRecoveryState:
        """Return continuation state without performing any side effect."""
        if type(current_task_snapshot) is not CompletionEvaluationSnapshot:
            raise TypeError(
                "current_task_snapshot must be a CompletionEvaluationSnapshot"
            )
        if latest_gate_attempt is not None and type(
            latest_gate_attempt
        ) is not CompletionGateHistoryEntry:
            raise TypeError(
                "latest_gate_attempt must be a CompletionGateHistoryEntry or None"
            )
        if current_task_snapshot.task_status not in _TASK_STATUSES:
            return _integrity_state(
                current_task_snapshot.task_id,
                "durable task status is invalid",
                snapshot=current_task_snapshot,
            )

        terminal_state = {
            "completed": CompletionContinuationState.TERMINAL_COMPLETED,
            "failed": CompletionContinuationState.TERMINAL_FAILED,
            "cancelled": CompletionContinuationState.TERMINAL_CANCELLED,
        }.get(current_task_snapshot.task_status)
        if terminal_state is not None:
            return _state(
                current_task_snapshot,
                continuation_state=terminal_state,
            )

        decision = _unwrap_decision(latest_completion_decision)
        if latest_completion_decision is not None and decision is None:
            return _integrity_state(
                current_task_snapshot.task_id,
                "latest completion decision has an invalid type",
                snapshot=current_task_snapshot,
            )
        if decision is None:
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.NO_DECISION,
            )
        if decision.task_id != current_task_snapshot.task_id:
            return _integrity_state(
                current_task_snapshot.task_id,
                "latest completion decision task binding is invalid",
                snapshot=current_task_snapshot,
            )
        if (
            decision.goal_spec_id != current_task_snapshot.goal_spec_id
            or decision.goal_spec_digest
            != current_task_snapshot.goal_spec_digest
        ):
            return _integrity_state(
                current_task_snapshot.task_id,
                "latest completion decision GoalSpec binding is invalid",
                snapshot=current_task_snapshot,
                decision=decision,
            )

        if decision.outcome is CompletionOutcome.REPLAN:
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.REPLAN_REQUIRED,
                decision=decision,
                decision_sequence=_decision_sequence(latest_completion_decision),
            )
        if decision.outcome is CompletionOutcome.BLOCKED:
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.EXTERNAL_BLOCKED,
                decision=decision,
                decision_sequence=_decision_sequence(latest_completion_decision),
            )
        if decision.outcome is CompletionOutcome.FAILED:
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.FAILURE_REVIEW_REQUIRED,
                decision=decision,
                decision_sequence=_decision_sequence(latest_completion_decision),
            )
        if decision.outcome is not CompletionOutcome.COMPLETE:
            return _integrity_state(
                current_task_snapshot.task_id,
                "latest completion decision outcome is invalid",
                snapshot=current_task_snapshot,
                decision=decision,
                decision_sequence=_decision_sequence(latest_completion_decision),
            )

        if not _decision_matches_snapshot(decision, current_task_snapshot):
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.REEVALUATION_REQUIRED,
                decision=decision,
                gate_attempt=latest_gate_attempt,
                decision_sequence=_decision_sequence(latest_completion_decision),
                reason="completion decision snapshot is stale",
            )
        if latest_gate_attempt is None or not _gate_matches_decision(
            latest_gate_attempt,
            decision,
        ):
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.REEVALUATION_REQUIRED,
                decision=decision,
                decision_sequence=_decision_sequence(latest_completion_decision),
                reason="no current gate result is bound to the decision",
            )
        if (
            latest_gate_attempt.gate_status
            is CompletionGateStatus.AUTHORITY_INSUFFICIENT
        ):
            return _state(
                current_task_snapshot,
                continuation_state=CompletionContinuationState.AUTHORITY_REQUIRED,
                decision=decision,
                gate_attempt=latest_gate_attempt,
                decision_sequence=_decision_sequence(latest_completion_decision),
            )
        return _state(
            current_task_snapshot,
            continuation_state=CompletionContinuationState.REEVALUATION_REQUIRED,
            decision=decision,
            gate_attempt=latest_gate_attempt,
            decision_sequence=_decision_sequence(latest_completion_decision),
            reason="completion decision has no replayable continuation authority",
        )


class CompletionRecoveryService:
    """Read durable completion history and expose a restart-safe state."""

    def __init__(
        self,
        *,
        decision_repository: CompletionRecoveryDecisionReader,
        goal_spec_repository: CompletionRecoveryGoalSpecReader,
        gate_history_reader: CompletionGateHistoryReader,
        principal_id: str,
        project_id: str,
    ) -> None:
        _require_id(principal_id, label="principal_id")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._decision_repository = decision_repository
        self._goal_spec_repository = goal_spec_repository
        self._gate_history_reader = gate_history_reader
        self._principal_id = principal_id
        self._project_id = project_id

    async def recover(self, task_id: str) -> CompletionRecoveryState | None:
        """Recover one task's continuation interpretation from durable data.

        ``None`` means the task is unavailable in this owner scope.  An
        existing task with malformed durable control history returns an
        explicit ``INTEGRITY_ERROR`` state and never falls back to an older
        permissive record.
        """
        _require_id(task_id, label="task_id")
        try:
            goal_spec = await self._goal_spec_repository.get_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except GoalSpecRepositoryError:
            return _integrity_state(task_id, "canonical GoalSpec read failed")
        except Exception:  # noqa: BLE001 - recovery fails closed at the port boundary
            return _integrity_state(task_id, "canonical GoalSpec read failed")
        if goal_spec is None:
            return None
        if type(goal_spec) is not GoalSpec:
            return _integrity_state(task_id, "canonical GoalSpec has invalid type")

        try:
            snapshot = await self._decision_repository.read_current_task_snapshot(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                goal_spec=goal_spec,
            )
        except CompletionDecisionRepositoryError:
            return _integrity_state(task_id, "current task snapshot failed integrity")
        except Exception:  # noqa: BLE001 - recovery fails closed at the port boundary
            return _integrity_state(task_id, "current task snapshot read failed")
        if snapshot is None:
            return None
        if type(snapshot) is not CompletionEvaluationSnapshot:
            return _integrity_state(task_id, "current task snapshot has invalid type")

        # Terminal lifecycle state has precedence over historical decisions.
        # We intentionally do not read or expose a possibly malformed latest
        # decision here: a terminal task cannot be resurrected by history.
        if snapshot.task_status in _TERMINAL_TASK_STATUSES:
            return CompletionRecoveryResolver.resolve(
                current_task_snapshot=snapshot,
                latest_completion_decision=None,
            )

        try:
            latest = await self._decision_repository.get_latest_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except CompletionDecisionRepositoryError:
            return _integrity_state(task_id, "latest completion decision failed integrity")
        except Exception:  # noqa: BLE001 - recovery fails closed at the port boundary
            return _integrity_state(task_id, "latest completion decision read failed")

        try:
            records = await self._gate_history_reader.list_completion_gate_history(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except Exception:  # noqa: BLE001 - recovery fails closed at the port boundary
            return _integrity_state(task_id, "completion gate history read failed")
        if type(records) is not tuple:
            return _integrity_state(task_id, "completion gate history has invalid type")

        decoded_entries: list[CompletionGateHistoryEntry] = []
        malformed_history = False
        for record in records:
            entry = CompletionGateHistoryEntry.from_record(record)
            if entry is None:
                # Never discard a malformed newer event and fall back to an
                # older usable gate result.  The event ledger is history, not
                # a bearer capability; ambiguous history requires a fresh
                # evaluation.
                malformed_history = True
                continue
            decoded_entries.append(entry)
        latest_gate = (
            None
            if malformed_history
            else _latest_gate_for_decision(tuple(decoded_entries), latest)
        )
        return CompletionRecoveryResolver.resolve(
            current_task_snapshot=snapshot,
            latest_completion_decision=latest,
            latest_gate_attempt=latest_gate,
        )


def _latest_gate_for_decision(
    entries: Sequence[CompletionGateHistoryEntry],
    stored: StoredCompletionDecision | None,
) -> CompletionGateHistoryEntry | None:
    """Return only the event bound to the exact current decision identity."""
    if stored is None:
        return None
    matching = tuple(
        entry
        for entry in entries
        if entry.task_id == stored.task_id
        and entry.decision_id == stored.decision_id
        and entry.decision_digest == stored.decision_digest
    )
    if not matching:
        return None
    return max(matching, key=lambda entry: entry.ordering_key)


def _unwrap_decision(
    value: StoredCompletionDecision | CompletionDecision | None,
) -> CompletionDecision | None:
    if value is None:
        return None
    if type(value) is CompletionDecision:
        return value
    if type(value) is StoredCompletionDecision:
        return value.decision
    return None


def _decision_matches_snapshot(
    decision: CompletionDecision,
    snapshot: CompletionEvaluationSnapshot,
) -> bool:
    return (
        decision.task_id == snapshot.task_id
        and decision.goal_spec_id == snapshot.goal_spec_id
        and decision.goal_spec_digest == snapshot.goal_spec_digest
        and decision.cognitive_state is snapshot.cognitive_state
        and decision.control_state_version == snapshot.control_state_version
        and decision.task_status_at_evaluation == snapshot.task_status
        and decision.workspace_id == snapshot.workspace_id
    )


def _gate_matches_decision(
    gate_attempt: CompletionGateHistoryEntry,
    decision: CompletionDecision,
) -> bool:
    return (
        gate_attempt.task_id == decision.task_id
        and gate_attempt.decision_id == decision.decision_id
        and gate_attempt.decision_digest == decision.decision_digest
    )


def _state(
    snapshot: CompletionEvaluationSnapshot,
    *,
    continuation_state: CompletionContinuationState,
    decision: CompletionDecision | None = None,
    gate_attempt: CompletionGateHistoryEntry | None = None,
    decision_sequence: int | None = None,
    reason: str = "",
) -> CompletionRecoveryState:
    return CompletionRecoveryState(
        task_id=snapshot.task_id,
        continuation_state=continuation_state,
        task_status=snapshot.task_status,
        cognitive_state=snapshot.cognitive_state,
        control_state_version=snapshot.control_state_version,
        workspace_id=snapshot.workspace_id,
        latest_decision_id=(decision.decision_id if decision is not None else None),
        latest_decision_digest=(
            decision.decision_digest if decision is not None else None
        ),
        latest_decision_sequence=decision_sequence,
        decision_outcome=(decision.outcome if decision is not None else None),
        gate_status=(
            gate_attempt.gate_status if gate_attempt is not None else None
        ),
        reason=reason,
    )


def _decision_sequence(
    value: StoredCompletionDecision | CompletionDecision | None,
) -> int | None:
    if type(value) is StoredCompletionDecision:
        return value.decision_sequence
    return None


def _integrity_state(
    task_id: str,
    reason: str,
    *,
    snapshot: CompletionEvaluationSnapshot | None = None,
    decision: CompletionDecision | None = None,
    decision_sequence: int | None = None,
) -> CompletionRecoveryState:
    return CompletionRecoveryState(
        task_id=task_id,
        continuation_state=CompletionContinuationState.INTEGRITY_ERROR,
        task_status=snapshot.task_status if snapshot is not None else None,
        cognitive_state=(
            snapshot.cognitive_state if snapshot is not None else None
        ),
        control_state_version=(
            snapshot.control_state_version if snapshot is not None else None
        ),
        workspace_id=snapshot.workspace_id if snapshot is not None else None,
        latest_decision_id=(decision.decision_id if decision is not None else None),
        latest_decision_digest=(
            decision.decision_digest if decision is not None else None
        ),
        latest_decision_sequence=decision_sequence,
        decision_outcome=decision.outcome if decision is not None else None,
        reason=reason,
    )


def _require_id(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > _MAX_ID_LENGTH:
        raise ValueError(f"{label} exceeds {_MAX_ID_LENGTH} characters")
    return value


def _valid_id(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= _MAX_ID_LENGTH


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


__all__ = [
    "MAX_COMPLETION_GATE_HISTORY_RECORDS",
    "MAX_COMPLETION_GATE_PAYLOAD_BYTES",
    "CompletionContinuationState",
    "CompletionGateHistoryEntry",
    "CompletionGateHistoryReader",
    "CompletionGateHistoryRecord",
    "CompletionRecoveryDecisionReader",
    "CompletionRecoveryGoalSpecReader",
    "CompletionRecoveryResolver",
    "CompletionRecoveryService",
    "CompletionRecoveryState",
    "DatabaseCompletionGateHistoryReader",
]
