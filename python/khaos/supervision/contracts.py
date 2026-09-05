"""Typed, bounded contracts for Coding supervision.

The objects in this module are the user-visible projection boundary.  They
carry progress and lifecycle facts, but never carry permission grants,
approval tokens, source contents, tool output, or completion authority.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.time_utils import utc_now_naive

MAX_EVENT_PAYLOAD_BYTES = 64 * 1024
MAX_STATE_BYTES = 128 * 1024
MAX_TEXT_BYTES = 4096
MAX_PATHS = 512
MAX_CHECKPOINT_REFS = 128
MAX_SUBAGENTS = 128


class SupervisionContractError(ValueError):
    """A typed supervision value is malformed or exceeds its bound."""


class SupervisionStatus(StrEnum):
    """Small user-facing state vocabulary for one Coding task."""

    PLANNING = "PLANNING"
    INVESTIGATING = "INVESTIGATING"
    EDITING = "EDITING"
    VERIFYING = "VERIFYING"
    REPAIRING = "REPAIRING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    RUNNING_SUBAGENTS = "RUNNING_SUBAGENTS"
    INTEGRATING = "INTEGRATING"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    READY = "READY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    QUARANTINED = "QUARANTINED"
    PAUSING = "PAUSING"


class SupervisionEventType(StrEnum):
    """Canonical semantic events emitted by runtime owners."""

    TASK_STARTED = "task.started"
    PLAN_CREATED = "plan.created"
    PLAN_REVISED = "plan.revised"
    STEP_STARTED = "step.started"
    CONTEXT_PREPARED = "context.prepared"
    REPO_INVESTIGATED = "repo.investigated"
    EDIT_PROPOSED = "edit.proposed"
    EDIT_APPLIED = "edit.applied"
    VERIFICATION_STARTED = "verification.started"
    VERIFICATION_PROGRESS = "verification.progress"
    VERIFICATION_FAILED = "verification.failed"
    VERIFICATION_PASSED = "verification.passed"
    REPAIR_STARTED = "repair.started"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"
    SUBAGENT_STARTED = "subagent.started"
    SUBAGENT_PROGRESS = "subagent.progress"
    SUBAGENT_FINISHED = "subagent.finished"
    MERGE_PLANNED = "merge.planned"
    MERGE_PUBLISHED = "merge.published"
    CHECKPOINT_CREATED = "checkpoint.created"
    CHECKPOINT_RESTORED = "checkpoint.restored"
    TASK_PAUSED = "task.paused"
    TASK_RESUMED = "task.resumed"
    COMPLETION_REJECTED = "completion.rejected"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_CANCELLED = "task.cancelled"
    CONTROL_REQUESTED = "control.requested"
    WORKSPACE_OBSERVED = "workspace.observed"


class SupervisionActor(StrEnum):
    """Trusted origin of a supervision event."""

    RUNTIME = "runtime"
    USER = "user"
    SYSTEM = "system"
    RECOVERY = "recovery"


class SupervisionSeverity(StrEnum):
    """Display severity; it is not an authorization decision."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ControlState(StrEnum):
    """Durable cooperative control state."""

    RUNNING = "RUNNING"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"


class SupervisionCommandStatus(StrEnum):
    """Result vocabulary shared by API, CLI, and TUI control adapters."""

    APPLIED = "APPLIED"
    NOOP = "NOOP"
    REJECTED_STALE = "REJECTED_STALE"
    BLOCKED = "BLOCKED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    FAILED = "FAILED"


def _bounded_text(value: object, label: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise SupervisionContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise SupervisionContractError(f"{label} exceeds its bound")
    return value


def _optional_text(value: object, label: str, maximum: int = MAX_TEXT_BYTES) -> str | None:
    if value is None:
        return None
    if type(value) is not str or "\x00" in value:
        raise SupervisionContractError(f"{label} must be text or null")
    if len(value.encode("utf-8")) > maximum:
        raise SupervisionContractError(f"{label} exceeds its bound")
    return value


def _paths(value: object, label: str = "paths") -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise SupervisionContractError(f"{label} must be a sequence")
    if len(value) > MAX_PATHS:
        raise SupervisionContractError(f"{label} exceeds its bound")
    result: list[str] = []
    for item in value:
        if type(item) is not str or not item or "\x00" in item:
            raise SupervisionContractError(f"{label} contains an invalid path")
        if item.startswith("/") or "\\" in item or ".." in item.split("/"):
            raise SupervisionContractError(f"{label} contains a non-relative path")
        if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in item.split("/")):
            raise SupervisionContractError(f"{label} reaches protected metadata")
        if item not in result:
            result.append(item)
    return tuple(result)


def _enum(value: object, cls: type[StrEnum], label: str) -> StrEnum:
    if isinstance(value, cls):
        return value
    try:
        return cls(str(value))
    except ValueError as exc:
        raise SupervisionContractError(f"{label} is invalid") from exc


_FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "content",
        "source",
        "diff",
        "patch",
        "stdout",
        "stderr",
        "output",
        "transcript",
        "prompt",
        "model_output",
        "terminal_output",
        "text",
    }
)


def _validate_projection_payload(value: object, *, path: str = "payload") -> None:
    """Reject source/output-shaped fields from durable event payloads."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise SupervisionContractError(f"{path} contains a non-text key")
            if key.casefold() in _FORBIDDEN_PAYLOAD_KEYS:
                raise SupervisionContractError(
                    f"{path} contains forbidden source/output field {key!r}"
                )
            _validate_projection_payload(child, path=f"{path}.{key}")
    elif isinstance(value, (tuple, list)):
        for index, child in enumerate(value):
            _validate_projection_payload(child, path=f"{path}[{index}]")
    elif isinstance(value, (str, int, float, bool)) or value is None:
        return
    else:
        raise SupervisionContractError(f"{path} is not JSON-compatible")


@dataclass(frozen=True, slots=True)
class CurrentActivity:
    """Typed description of what the runtime is doing now."""

    operation: str
    kind: str
    stage: str
    description: str = ""
    scope: tuple[str, ...] = ()
    current: int | None = None
    total: int | None = None
    status: str = "active"

    def __post_init__(self) -> None:
        _bounded_text(self.operation, "activity.operation", 128)
        _bounded_text(self.kind, "activity.kind", 128)
        _bounded_text(self.stage, "activity.stage", 128)
        _optional_text(self.description, "activity.description", 1024)
        object.__setattr__(self, "scope", _paths(self.scope, "activity.scope"))
        if self.current is not None and (
            type(self.current) is not int or self.current < 0
        ):
            raise SupervisionContractError("activity.current is invalid")
        if self.total is not None and (type(self.total) is not int or self.total < 0):
            raise SupervisionContractError("activity.total is invalid")
        if self.current is not None and self.total is not None and self.current > self.total:
            raise SupervisionContractError("activity.current exceeds activity.total")
        _bounded_text(self.status, "activity.status", 64)

    def to_payload(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "kind": self.kind,
            "stage": self.stage,
            "description": self.description,
            "scope": list(self.scope),
            "current": self.current,
            "total": self.total,
            "status": self.status,
        }

    @classmethod
    def from_payload(cls, value: object) -> CurrentActivity | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise SupervisionContractError("activity must be an object")
        return cls(
            operation=value.get("operation", "unknown"),
            kind=value.get("kind", "unknown"),
            stage=value.get("stage", "unknown"),
            description=value.get("description", ""),
            scope=tuple(value.get("scope", ())),
            current=value.get("current"),
            total=value.get("total"),
            status=value.get("status", "active"),
        )


@dataclass(frozen=True, slots=True)
class PlanProjection:
    """Bounded display projection of the durable plan revision."""

    revision_id: str
    digest: str
    current_step: int = 0
    total_steps: int = 0
    summary: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.revision_id, "plan.revision_id", 256)
        _bounded_text(self.digest, "plan.digest", 128)
        if type(self.current_step) is not int or self.current_step < 0:
            raise SupervisionContractError("plan.current_step is invalid")
        if type(self.total_steps) is not int or self.total_steps < 0:
            raise SupervisionContractError("plan.total_steps is invalid")
        if self.current_step > self.total_steps:
            raise SupervisionContractError("plan.current_step exceeds total_steps")
        _optional_text(self.summary, "plan.summary", 1024)

    def to_payload(self) -> dict[str, object]:
        return {
            "revision_id": self.revision_id,
            "digest": self.digest,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "summary": self.summary,
        }

    @classmethod
    def from_payload(cls, value: object) -> PlanProjection | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise SupervisionContractError("plan projection must be an object")
        return cls(
            revision_id=value.get("revision_id", "unknown"),
            digest=value.get("digest", "unknown"),
            current_step=value.get("current_step", 0),
            total_steps=value.get("total_steps", 0),
            summary=value.get("summary", ""),
        )


@dataclass(frozen=True, slots=True)
class SupervisionEvent:
    """One immutable canonical event before repository sequence assignment."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    task_id: str = ""
    workspace_id: str = ""
    event_type: SupervisionEventType | str = SupervisionEventType.CONTEXT_PREPARED
    sequence: int = 0
    repository_generation: int | None = None
    plan_revision: int | None = None
    actor: SupervisionActor | str = SupervisionActor.RUNTIME
    severity: SupervisionSeverity | str = SupervisionSeverity.INFO
    payload: Mapping[str, object] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: utc_now_naive().isoformat())
    event_digest: str = ""
    principal_id: str = ""
    project_id: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.event_id, "event_id", 128)
        _bounded_text(self.task_id, "task_id", 128)
        _bounded_text(self.workspace_id, "workspace_id", 128)
        object.__setattr__(self, "event_type", _enum(self.event_type, SupervisionEventType, "event_type"))
        if type(self.sequence) is not int or self.sequence < 0:
            raise SupervisionContractError("event.sequence must be non-negative")
        if self.repository_generation is not None and (
            type(self.repository_generation) is not int or self.repository_generation <= 0
        ):
            raise SupervisionContractError("event.repository_generation is invalid")
        if self.plan_revision is not None and (
            type(self.plan_revision) is not int or self.plan_revision < 0
        ):
            raise SupervisionContractError("event.plan_revision is invalid")
        object.__setattr__(self, "actor", _enum(self.actor, SupervisionActor, "actor"))
        object.__setattr__(self, "severity", _enum(self.severity, SupervisionSeverity, "severity"))
        if not isinstance(self.payload, Mapping):
            raise SupervisionContractError("event.payload must be an object")
        payload = dict(self.payload)
        _validate_projection_payload(payload)
        if len(canonical_json_bytes(payload)) > MAX_EVENT_PAYLOAD_BYTES:
            raise SupervisionContractError("event.payload exceeds its bound")
        object.__setattr__(self, "payload", payload)
        _bounded_text(self.created_at, "event.created_at", 128)
        if self.principal_id:
            _bounded_text(self.principal_id, "event.principal_id", 256)
        if self.project_id:
            _bounded_text(self.project_id, "event.project_id", 256)
        expected = canonical_digest(self._digest_payload())
        if self.event_digest and self.event_digest != expected:
            raise SupervisionContractError("event digest does not match payload")
        object.__setattr__(self, "event_digest", expected)

    def _digest_payload(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "event_type": self.event_type.value,
            "sequence": self.sequence,
            "repository_generation": self.repository_generation,
            "plan_revision": self.plan_revision,
            "actor": self.actor.value,
            "severity": self.severity.value,
            "payload": dict(self.payload),
            "created_at": self.created_at,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
        }

    def with_sequence(self, sequence: int) -> SupervisionEvent:
        if type(sequence) is not int or sequence <= 0:
            raise SupervisionContractError("persisted event sequence must be positive")
        return replace(self, sequence=sequence, event_digest="")

    def to_payload(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "repository_generation": self.repository_generation,
            "plan_revision": self.plan_revision,
            "actor": self.actor.value,
            "severity": self.severity.value,
            "payload": dict(self.payload),
            "created_at": self.created_at,
            "event_digest": self.event_digest,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
        }

    @classmethod
    def from_payload(cls, value: Mapping[str, object]) -> SupervisionEvent:
        return cls(
            event_id=value.get("event_id", ""),
            task_id=value.get("task_id", ""),
            workspace_id=value.get("workspace_id", ""),
            sequence=value.get("sequence", 0),
            event_type=value.get("event_type", ""),
            repository_generation=value.get("repository_generation"),
            plan_revision=value.get("plan_revision"),
            actor=value.get("actor", SupervisionActor.RUNTIME.value),
            severity=value.get("severity", SupervisionSeverity.INFO.value),
            payload=value.get("payload", {}),
            created_at=value.get("created_at") or utc_now_naive().isoformat(),
            event_digest=value.get("event_digest", ""),
            principal_id=value.get("principal_id", ""),
            project_id=value.get("project_id", ""),
        )


@dataclass(frozen=True, slots=True)
class TaskSupervisionState:
    """Bounded restart-safe projection derived from canonical events."""

    task_id: str
    principal_id: str
    project_id: str
    workspace_id: str
    goal: str = ""
    status: SupervisionStatus | str = SupervisionStatus.READY
    repository_generation: int = 1
    current_plan: PlanProjection | None = None
    current_step: str | None = None
    activity: CurrentActivity | None = None
    changed_paths: tuple[str, ...] = ()
    verification_state: str = "unknown"
    approval_state: str = "none"
    active_subagents: tuple[str, ...] = ()
    merge_state: str = "none"
    checkpoint_ids: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    completion_eligibility: str = "unknown"
    known_file_digests: Mapping[str, str] = field(default_factory=dict)
    revision: int = 0
    sequence: int = 0
    updated_at: str = field(default_factory=lambda: utc_now_naive().isoformat())
    state_digest: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.task_id, "state.task_id", 128)
        _bounded_text(self.principal_id, "state.principal_id", 256)
        _bounded_text(self.project_id, "state.project_id", 256)
        _bounded_text(self.workspace_id, "state.workspace_id", 128)
        _optional_text(self.goal, "state.goal", 8192)
        object.__setattr__(self, "status", _enum(self.status, SupervisionStatus, "state.status"))
        if type(self.repository_generation) is not int or self.repository_generation <= 0:
            raise SupervisionContractError("state.repository_generation is invalid")
        if self.current_step is not None:
            _optional_text(self.current_step, "state.current_step", 256)
        for label, value in (
            ("verification_state", self.verification_state),
            ("approval_state", self.approval_state),
            ("merge_state", self.merge_state),
            ("completion_eligibility", self.completion_eligibility),
        ):
            _bounded_text(value, f"state.{label}", 128)
        object.__setattr__(self, "changed_paths", _paths(self.changed_paths, "state.changed_paths"))
        object.__setattr__(self, "active_subagents", _paths(self.active_subagents, "state.active_subagents"))
        if len(self.active_subagents) > MAX_SUBAGENTS:
            raise SupervisionContractError("state.active_subagents exceeds its bound")
        object.__setattr__(self, "checkpoint_ids", _paths(self.checkpoint_ids, "state.checkpoint_ids"))
        if len(self.checkpoint_ids) > MAX_CHECKPOINT_REFS:
            raise SupervisionContractError("state.checkpoint_ids exceeds its bound")
        object.__setattr__(self, "blockers", _paths(self.blockers, "state.blockers"))
        if type(self.revision) is not int or self.revision < 0:
            raise SupervisionContractError("state.revision is invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise SupervisionContractError("state.sequence is invalid")
        _bounded_text(self.updated_at, "state.updated_at", 128)
        known = dict(self.known_file_digests)
        if len(known) > MAX_PATHS:
            raise SupervisionContractError("state.known_file_digests exceeds its bound")
        for path, digest in known.items():
            _paths((path,), "state.known_file_digests")
            if type(digest) is not str or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise SupervisionContractError("state.known_file_digests has invalid digest")
        object.__setattr__(self, "known_file_digests", known)
        expected = canonical_digest(self._digest_payload())
        if self.state_digest and self.state_digest != expected:
            raise SupervisionContractError("state digest does not match projection")
        object.__setattr__(self, "state_digest", expected)
        if len(canonical_json_bytes(self.to_payload())) > MAX_STATE_BYTES:
            raise SupervisionContractError("state projection exceeds its bound")

    def _digest_payload(self) -> dict[str, object]:
        payload = self.to_payload()
        payload.pop("state_digest", None)
        return payload

    def to_payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "goal": self.goal,
            "status": self.status.value,
            "repository_generation": self.repository_generation,
            "current_plan": self.current_plan.to_payload() if self.current_plan else None,
            "current_step": self.current_step,
            "activity": self.activity.to_payload() if self.activity else None,
            "changed_paths": list(self.changed_paths),
            "verification_state": self.verification_state,
            "approval_state": self.approval_state,
            "active_subagents": list(self.active_subagents),
            "merge_state": self.merge_state,
            "checkpoint_ids": list(self.checkpoint_ids),
            "blockers": list(self.blockers),
            "completion_eligibility": self.completion_eligibility,
            "known_file_digests": dict(self.known_file_digests),
            "revision": self.revision,
            "sequence": self.sequence,
            "updated_at": self.updated_at,
            "state_digest": self.state_digest,
        }

    @classmethod
    def from_payload(cls, value: Mapping[str, object]) -> TaskSupervisionState:
        return cls(
            task_id=value.get("task_id", ""),
            principal_id=value.get("principal_id", ""),
            project_id=value.get("project_id", ""),
            workspace_id=value.get("workspace_id", ""),
            goal=value.get("goal", ""),
            status=value.get("status", SupervisionStatus.READY.value),
            repository_generation=value.get("repository_generation", 1),
            current_plan=PlanProjection.from_payload(value.get("current_plan")),
            current_step=value.get("current_step"),
            activity=CurrentActivity.from_payload(value.get("activity")),
            changed_paths=tuple(value.get("changed_paths", ())),
            verification_state=value.get("verification_state", "unknown"),
            approval_state=value.get("approval_state", "none"),
            active_subagents=tuple(value.get("active_subagents", ())),
            merge_state=value.get("merge_state", "none"),
            checkpoint_ids=tuple(value.get("checkpoint_ids", ())),
            blockers=tuple(value.get("blockers", ())),
            completion_eligibility=value.get("completion_eligibility", "unknown"),
            known_file_digests=value.get("known_file_digests", {}),
            revision=value.get("revision", 0),
            sequence=value.get("sequence", 0),
            updated_at=value.get("updated_at") or utc_now_naive().isoformat(),
            state_digest=value.get("state_digest", ""),
        )


@dataclass(frozen=True, slots=True)
class ControlCommandResult:
    """Idempotent result of a typed pause/resume/cancel command."""

    command_id: str
    task_id: str
    status: SupervisionCommandStatus | str
    control_state: ControlState | str
    revision: int
    reason: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.command_id, "command.command_id", 128)
        _bounded_text(self.task_id, "command.task_id", 128)
        object.__setattr__(self, "status", _enum(self.status, SupervisionCommandStatus, "command.status"))
        object.__setattr__(self, "control_state", _enum(self.control_state, ControlState, "command.control_state"))
        if type(self.revision) is not int or self.revision < 0:
            raise SupervisionContractError("command.revision is invalid")
        _optional_text(self.reason, "command.reason", 2048)

    def to_payload(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "control_state": self.control_state.value,
            "revision": self.revision,
            "reason": self.reason,
        }
