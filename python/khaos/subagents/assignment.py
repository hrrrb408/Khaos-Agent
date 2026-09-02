"""M7.8 plan-bound sub-agent authority contracts and persistence.

The objects in this module are deliberately separate from ``SubAgentTask``.
The latter is a legacy operational projection used by the generic office
sub-agent API; these contracts are the trusted control-plane binding for one
delegated coding step.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from khaos.coding.planning.revision import PlanningStep, PlanOperation
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.time_utils import utc_now_naive

ASSIGNMENT_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 16 * 1024
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


class AssignmentDisposition(str, Enum):
    """Typed result of a delegation request."""

    CREATED = "created"
    BLOCKED = "blocked"
    STALE = "stale"
    INVALID = "invalid"
    TERMINAL = "terminal"
    CONFLICT = "conflict"


class AssignmentRunState(str, Enum):
    """Durable operational state of one assignment run."""

    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    STALE = "STALE"
    ORPHANED = "ORPHANED"


def _required(value: object, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be positive")
    return value


@dataclass(frozen=True, slots=True)
class SubAgentPolicy:
    """Immutable, conservative delegation policy compiled by trusted code."""

    max_active_children: int = 1
    max_delegations_per_turn: int = 1
    max_depth: int = 1
    max_child_turns: int = 30
    max_child_token_budget: int = 100_000
    max_child_timeout: int = 300
    allow_low_risk: bool = True
    allow_medium_risk: bool = True
    allow_high_risk: bool = False
    allow_critical_risk: bool = False
    allow_mutation: bool = True
    allow_verification: bool = True
    allow_supporting_reads: bool = True
    max_result_bytes: int = MAX_REPORT_BYTES
    policy_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "max_active_children", "max_delegations_per_turn", "max_depth",
            "max_child_turns", "max_child_token_budget", "max_child_timeout",
            "max_result_bytes",
        ):
            _positive(getattr(self, name), name)
        if self.max_depth != 1:
            raise ValueError("M7.8 policy max_depth must be exactly 1")
        for name in (
            "allow_low_risk", "allow_medium_risk", "allow_high_risk",
            "allow_critical_risk", "allow_mutation", "allow_verification",
            "allow_supporting_reads",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be bool")
        digest = canonical_digest(self._payload(include_digest=False))
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("policy_digest does not match policy")
        object.__setattr__(self, "policy_digest", digest)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload = {
            "max_active_children": self.max_active_children,
            "max_delegations_per_turn": self.max_delegations_per_turn,
            "max_depth": self.max_depth,
            "max_child_turns": self.max_child_turns,
            "max_child_token_budget": self.max_child_token_budget,
            "max_child_timeout": self.max_child_timeout,
            "allow_low_risk": self.allow_low_risk,
            "allow_medium_risk": self.allow_medium_risk,
            "allow_high_risk": self.allow_high_risk,
            "allow_critical_risk": self.allow_critical_risk,
            "allow_mutation": self.allow_mutation,
            "allow_verification": self.allow_verification,
            "allow_supporting_reads": self.allow_supporting_reads,
            "max_result_bytes": self.max_result_bytes,
        }
        if include_digest:
            payload["policy_digest"] = self.policy_digest
        return payload


@dataclass(frozen=True, slots=True)
class SubAgentAssignment:
    """Immutable binding of one child to one current published plan step."""

    schema_version: int
    assignment_id: str
    assignment_sequence: int
    task_owner_principal_id: str
    project_id: str
    parent_task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    parent_task_status: str
    parent_cognitive_state: str
    parent_control_state_version: int
    workspace_id: str
    repository_id: str
    base_revision: str | None
    workspace_generation: int
    published_plan_revision_id: str
    published_plan_revision_digest: str
    execution_epoch_digest: str
    plan_step_id: str
    plan_step_digest: str
    plan_operation: str
    allowed_tools: tuple[str, ...]
    child_execution_principal_id: str
    child_session_id: str
    child_runtime_id: str
    depth: int
    policy_digest: str
    created_at: str
    expires_at: str | None = None
    assignment_digest: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != ASSIGNMENT_SCHEMA_VERSION:
            raise ValueError("unsupported assignment schema version")
        for name in (
            "assignment_id", "task_owner_principal_id", "project_id", "parent_task_id",
            "goal_spec_id", "goal_spec_digest", "parent_task_status",
            "parent_cognitive_state", "workspace_id", "repository_id",
            "published_plan_revision_id", "published_plan_revision_digest",
            "execution_epoch_digest", "plan_step_id", "plan_step_digest",
            "plan_operation", "child_execution_principal_id", "child_session_id",
            "child_runtime_id", "policy_digest", "created_at",
        ):
            _required(getattr(self, name), name)
        if self.base_revision is not None:
            _required(self.base_revision, "base_revision")
        _positive(self.assignment_sequence, "assignment_sequence")
        _positive(self.workspace_generation, "workspace_generation")
        if self.depth != 1:
            raise ValueError("M7.8 assignments must have depth 1")
        if not self.child_execution_principal_id.startswith(
            f"subagent:{self.task_owner_principal_id}:"
        ):
            raise ValueError("child execution principal is not bound to parent owner")
        tools = tuple(sorted(set(self.allowed_tools)))
        if any(type(tool) is not str or not tool for tool in tools):
            raise ValueError("allowed_tools contains an invalid tool")
        object.__setattr__(self, "allowed_tools", tools)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.assignment_digest and self.assignment_digest != expected:
            raise ValueError("assignment_digest does not match assignment")
        object.__setattr__(self, "assignment_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "assignment_id": self.assignment_id,
            "assignment_sequence": self.assignment_sequence,
            "task_owner_principal_id": self.task_owner_principal_id,
            "project_id": self.project_id,
            "parent_task_id": self.parent_task_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "parent_task_status": self.parent_task_status,
            "parent_cognitive_state": self.parent_cognitive_state,
            "parent_control_state_version": self.parent_control_state_version,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "workspace_generation": self.workspace_generation,
            "published_plan_revision_id": self.published_plan_revision_id,
            "published_plan_revision_digest": self.published_plan_revision_digest,
            "execution_epoch_digest": self.execution_epoch_digest,
            "plan_step_id": self.plan_step_id,
            "plan_step_digest": self.plan_step_digest,
            "plan_operation": self.plan_operation,
            "allowed_tools": list(self.allowed_tools),
            "child_execution_principal_id": self.child_execution_principal_id,
            "child_session_id": self.child_session_id,
            "child_runtime_id": self.child_runtime_id,
            "depth": self.depth,
            "policy_digest": self.policy_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if include_digest:
            payload["assignment_digest"] = self.assignment_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        """Return the complete canonical assignment payload."""
        return self._payload(include_digest=True)

    def canonical_json(self) -> str:
        return canonical_json_bytes(self.to_payload()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class DelegatedExecutionContext:
    """Structural runtime marker for plan-bound child execution."""

    assignment_id: str
    assignment_digest: str
    task_owner_principal_id: str
    parent_task_id: str
    child_execution_principal_id: str
    project_id: str
    workspace_id: str
    published_plan_revision_id: str
    plan_step_id: str
    execution_epoch_digest: str

    def __post_init__(self) -> None:
        for name in (
            "assignment_id", "assignment_digest", "task_owner_principal_id",
            "parent_task_id", "child_execution_principal_id", "project_id",
            "workspace_id", "published_plan_revision_id", "plan_step_id",
            "execution_epoch_digest",
        ):
            _required(getattr(self, name), name)
        if not self.child_execution_principal_id.startswith(
            f"subagent:{self.task_owner_principal_id}:"
        ):
            raise ValueError("delegated child principal is not owner-bound")


@dataclass(frozen=True, slots=True)
class SubAgentReport:
    """Bounded low-trust child result; durable state remains authoritative."""

    assignment_id: str
    parent_task_id: str
    plan_revision_id: str
    plan_step_id: str
    child_runtime_id: str
    run_state: AssignmentRunState
    step_state: str
    summary: str = ""
    route_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "assignment_id", "parent_task_id", "plan_revision_id",
            "plan_step_id", "child_runtime_id", "step_state",
        ):
            _required(getattr(self, name), name)
        if type(self.run_state) is not AssignmentRunState:
            object.__setattr__(self, "run_state", AssignmentRunState(self.run_state))
        if type(self.summary) is not str:
            raise ValueError("summary must be text")
        if len(self.summary.encode("utf-8")) > MAX_REPORT_BYTES:
            object.__setattr__(
                self, "summary", self.summary.encode("utf-8")[:MAX_REPORT_BYTES].decode("utf-8", "ignore")
            )
        object.__setattr__(self, "route_ids", tuple(self.route_ids))


@dataclass(frozen=True, slots=True)
class AssignmentRequestResult:
    """Bounded coordinator response."""

    disposition: AssignmentDisposition
    reason_code: str
    reason: str
    assignment: SubAgentAssignment | None = None
    report: SubAgentReport | None = None


class AssignmentDatabase(Protocol):
    def transaction(self) -> Any: ...
    def read_connection(self) -> Any: ...


class SubAgentAssignmentRepository:
    """Persist immutable assignments and CAS their operational runs."""

    def __init__(self, database: AssignmentDatabase) -> None:
        self._database = database

    async def append(self, assignment: SubAgentAssignment) -> SubAgentAssignment:
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT COALESCE(MAX(assignment_sequence), 0) + 1 AS next_sequence "
                "FROM agent_subagent_assignments WHERE task_owner_principal_id = ? AND project_id = ? AND parent_task_id = ?",
                (assignment.task_owner_principal_id, assignment.project_id, assignment.parent_task_id),
            )
            row = await cursor.fetchone()
            sequence = int(row["next_sequence"] if row is not None else 1)
            if sequence != assignment.assignment_sequence:
                raise RuntimeError("assignment sequence changed before publication")
            try:
                await conn.execute(
                    """INSERT INTO agent_subagent_assignments (
                        assignment_id, assignment_sequence, task_owner_principal_id,
                        project_id, parent_task_id, goal_spec_id, goal_spec_digest,
                        parent_task_status, parent_cognitive_state, parent_control_state_version,
                        workspace_id, repository_id, base_revision, workspace_generation,
                        published_plan_revision_id, published_plan_revision_digest,
                        execution_epoch_digest, plan_step_id, plan_step_digest, plan_operation,
                        allowed_tools, child_execution_principal_id, child_session_id,
                        child_runtime_id, depth, policy_digest, assignment_json,
                        assignment_digest, created_at, expires_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        assignment.assignment_id, assignment.assignment_sequence,
                        assignment.task_owner_principal_id, assignment.project_id,
                        assignment.parent_task_id, assignment.goal_spec_id,
                        assignment.goal_spec_digest, assignment.parent_task_status,
                        assignment.parent_cognitive_state, assignment.parent_control_state_version,
                        assignment.workspace_id, assignment.repository_id, assignment.base_revision,
                        assignment.workspace_generation, assignment.published_plan_revision_id,
                        assignment.published_plan_revision_digest, assignment.execution_epoch_digest,
                        assignment.plan_step_id, assignment.plan_step_digest, assignment.plan_operation,
                        json.dumps(list(assignment.allowed_tools), separators=(",", ":")),
                        assignment.child_execution_principal_id, assignment.child_session_id,
                        assignment.child_runtime_id, assignment.depth, assignment.policy_digest,
                        assignment.canonical_json(), assignment.assignment_digest,
                        assignment.created_at, assignment.expires_at,
                    ),
                )
                await conn.execute(
                    "INSERT INTO agent_subagent_runs (assignment_id, state, state_version, started_at, finished_at, error) VALUES (?, 'PENDING', 0, NULL, NULL, NULL)",
                    (assignment.assignment_id,),
                )
            except Exception as exc:
                raise RuntimeError("assignment publication conflict") from exc
        return assignment

    async def next_sequence(self, *, task_owner_principal_id: str, project_id: str, parent_task_id: str) -> int:
        """Read the next owner-scoped sequence for an immutable assignment."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT COALESCE(MAX(assignment_sequence), 0) + 1 AS next_sequence FROM agent_subagent_assignments WHERE task_owner_principal_id = ? AND project_id = ? AND parent_task_id = ?",
                (task_owner_principal_id, project_id, parent_task_id),
            )
            row = await cursor.fetchone()
        return int(row["next_sequence"] if row is not None else 1)

    async def get(self, assignment_id: str, *, task_owner_principal_id: str, project_id: str) -> SubAgentAssignment | None:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM agent_subagent_assignments WHERE assignment_id = ? AND task_owner_principal_id = ? AND project_id = ?",
                (assignment_id, task_owner_principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_assignment(row) if row is not None else None

    async def active_for_step(self, *, task_owner_principal_id: str, project_id: str, parent_task_id: str, execution_epoch_digest: str, plan_step_id: str) -> SubAgentAssignment | None:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """SELECT a.* FROM agent_subagent_assignments a
                   JOIN agent_subagent_runs r ON r.assignment_id = a.assignment_id
                   WHERE a.task_owner_principal_id = ? AND a.project_id = ? AND a.parent_task_id = ?
                     AND a.execution_epoch_digest = ? AND a.plan_step_id = ? AND r.state IN ('PENDING', 'ACTIVE')
                   LIMIT 1""",
                (task_owner_principal_id, project_id, parent_task_id, execution_epoch_digest, plan_step_id),
            )
            row = await cursor.fetchone()
        return _decode_assignment(row) if row is not None else None

    async def validate_active_for_route(
        self, *, assignment_id: str, assignment_digest: str,
        child_execution_principal_id: str, task_owner_principal_id: str,
        project_id: str, parent_task_id: str, workspace_id: str,
        published_plan_revision_id: str, plan_step_id: str,
        execution_epoch_digest: str,
    ) -> bool:
        """Re-read the assignment and run state at route admission."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """SELECT a.*, r.state FROM agent_subagent_assignments a
                   JOIN agent_subagent_runs r ON r.assignment_id = a.assignment_id
                   WHERE a.assignment_id = ?""",
                (assignment_id,),
            )
            row = await cursor.fetchone()
        if row is None:
            return False
        try:
            assignment = _decode_assignment(row)
        except RuntimeError:
            return False
        return (
            row["state"] == AssignmentRunState.ACTIVE.value
            and assignment.assignment_digest == assignment_digest
            and assignment.child_execution_principal_id == child_execution_principal_id
            and assignment.task_owner_principal_id == task_owner_principal_id
            and assignment.project_id == project_id
            and assignment.parent_task_id == parent_task_id
            and assignment.workspace_id == workspace_id
            and assignment.published_plan_revision_id == published_plan_revision_id
            and assignment.plan_step_id == plan_step_id
            and assignment.execution_epoch_digest == execution_epoch_digest
        )

    async def activate(self, assignment_id: str, *, expected_version: int = 0) -> bool:
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE agent_subagent_runs SET state = 'ACTIVE', state_version = state_version + 1, started_at = ? WHERE assignment_id = ? AND state = 'PENDING' AND state_version = ?",
                (now, assignment_id, expected_version),
            )
        return int(cursor.rowcount or 0) == 1

    async def transition(self, assignment_id: str, *, expected_version: int, state: AssignmentRunState, error: str | None = None) -> bool:
        if state not in {AssignmentRunState.COMPLETED, AssignmentRunState.FAILED, AssignmentRunState.CANCELLED, AssignmentRunState.STALE, AssignmentRunState.ORPHANED}:
            raise ValueError("run transition must be terminal")
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE agent_subagent_runs SET state = ?, state_version = state_version + 1, finished_at = ?, error = ? WHERE assignment_id = ? AND state IN ('PENDING', 'ACTIVE') AND state_version = ?",
                (state.value, now, error, assignment_id, expected_version),
            )
        return int(cursor.rowcount or 0) == 1

    async def reconcile_after_restart(self) -> int:
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE agent_subagent_runs SET state = 'ORPHANED', state_version = state_version + 1, finished_at = ?, error = 'restart reconciliation' WHERE state IN ('PENDING', 'ACTIVE')",
                (now,),
            )
        return int(cursor.rowcount or 0)

    async def active_count(self, *, task_owner_principal_id: str, project_id: str, parent_task_id: str) -> int:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """SELECT COUNT(*) AS count FROM agent_subagent_assignments a
                   JOIN agent_subagent_runs r ON r.assignment_id = a.assignment_id
                   WHERE a.task_owner_principal_id = ? AND a.project_id = ? AND a.parent_task_id = ?
                     AND r.state IN ('PENDING', 'ACTIVE')""",
                (task_owner_principal_id, project_id, parent_task_id),
            )
            row = await cursor.fetchone()
        return int(row["count"] if row is not None else 0)


def _decode_assignment(row: Any) -> SubAgentAssignment:
    try:
        raw_tools = json.loads(str(row["allowed_tools"]))
        if not isinstance(raw_tools, list):
            raise TypeError("allowed_tools is malformed")
        assignment = SubAgentAssignment(
            schema_version=ASSIGNMENT_SCHEMA_VERSION,
            assignment_id=str(row["assignment_id"]),
            assignment_sequence=int(row["assignment_sequence"]),
            task_owner_principal_id=str(row["task_owner_principal_id"]),
            project_id=str(row["project_id"]),
            parent_task_id=str(row["parent_task_id"]),
            goal_spec_id=str(row["goal_spec_id"]),
            goal_spec_digest=str(row["goal_spec_digest"]),
            parent_task_status=str(row["parent_task_status"]),
            parent_cognitive_state=str(row["parent_cognitive_state"]),
            parent_control_state_version=int(row["parent_control_state_version"]),
            workspace_id=str(row["workspace_id"]),
            repository_id=str(row["repository_id"]),
            base_revision=row["base_revision"],
            workspace_generation=int(row["workspace_generation"]),
            published_plan_revision_id=str(row["published_plan_revision_id"]),
            published_plan_revision_digest=str(row["published_plan_revision_digest"]),
            execution_epoch_digest=str(row["execution_epoch_digest"]),
            plan_step_id=str(row["plan_step_id"]),
            plan_step_digest=str(row["plan_step_digest"]),
            plan_operation=str(row["plan_operation"]),
            allowed_tools=tuple(str(item) for item in raw_tools),
            child_execution_principal_id=str(row["child_execution_principal_id"]),
            child_session_id=str(row["child_session_id"]),
            child_runtime_id=str(row["child_runtime_id"]),
            depth=int(row["depth"]),
            policy_digest=str(row["policy_digest"]),
            created_at=str(row["created_at"]),
            expires_at=row["expires_at"],
            assignment_digest=str(row["assignment_digest"]),
        )
        if row["assignment_json"] != assignment.canonical_json():
            raise ValueError("assignment canonical payload disagrees with columns")
        return assignment
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("malformed durable sub-agent assignment") from exc


def derive_allowed_tools(step: PlanningStep, registry: Any, policy: SubAgentPolicy) -> tuple[str, ...]:
    """Derive child tools from reviewed registry metadata and policy."""
    risk = step.risk.level.value
    if not getattr(policy, f"allow_{risk}_risk"):
        return ()
    if step.operation in {PlanOperation.MODIFY, PlanOperation.CREATE, PlanOperation.DELETE, PlanOperation.RENAME, PlanOperation.CONFIGURE} and not policy.allow_mutation:
        return ()
    if step.operation is PlanOperation.TEST and not policy.allow_verification:
        return ()
    names: list[str] = []
    definitions = (
        (registry.get(name) for name in registry.names())
        if hasattr(registry, "names")
        else registry
    )
    for definition in definitions:
        role = getattr(getattr(definition, "plan_tool_role", None), "value", None)
        compatible = {
            PlanOperation.MODIFY.value: {"file_mutation", "file_transaction"},
            PlanOperation.CREATE.value: {"file_create", "file_transaction"},
            PlanOperation.DELETE.value: {"file_delete", "file_transaction"},
            PlanOperation.RENAME.value: {"file_rename", "file_transaction"},
            PlanOperation.CONFIGURE.value: {"file_mutation", "file_transaction"},
            PlanOperation.TEST.value: {"verification_command"},
            PlanOperation.DOCUMENT.value: {"file_mutation", "file_transaction"},
        }.get(step.operation.value, set())
        if role in compatible or policy.allow_supporting_reads and role == "supporting_read":
            names.append(str(definition.name))
    return tuple(sorted(set(names)))


def descriptive_step_goal(step: PlanningStep) -> str:
    """Build child description from the trusted published step only."""
    targets = ", ".join(step.target_files) or "the planned scope"
    return f"{step.title}: {step.description} Target: {targets}. Expected: {step.expected_outcome}"


__all__ = [
    "ASSIGNMENT_SCHEMA_VERSION",
    "AssignmentDatabase",
    "AssignmentDisposition",
    "AssignmentRequestResult",
    "AssignmentRunState",
    "DelegatedExecutionContext",
    "SubAgentAssignment",
    "SubAgentAssignmentRepository",
    "SubAgentControlCoordinator",
    "SubAgentPolicy",
    "SubAgentReport",
    "derive_allowed_tools",
    "descriptive_step_goal",
]


class SubAgentControlCoordinator:
    """Admit and activate exactly one current published plan step."""

    def __init__(
        self,
        *,
        plan_repository: Any,
        assignment_repository: SubAgentAssignmentRepository,
        goal_spec_repository: Any,
        workspace_manager: Any,
        registry: Any,
        spawner: Any,
        policy: SubAgentPolicy | None = None,
    ) -> None:
        self.plan_repository = plan_repository
        self.assignment_repository = assignment_repository
        self.goal_spec_repository = goal_spec_repository
        self.workspace_manager = workspace_manager
        self.registry = registry
        self.spawner = spawner
        self.policy = policy or SubAgentPolicy()

    async def request(
        self,
        *,
        task_owner_principal_id: str,
        project_id: str,
        parent_task_id: str,
        plan_step_id: str,
        parent_runtime_id: str = "",
        advisory_note: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> AssignmentRequestResult:
        """Validate fresh parent state, publish an assignment, and spawn it.

        ``payload`` is accepted only as a compatibility envelope.  Its
        authority-shaped fields are intentionally ignored; the authoritative
        values are read from the owner-scoped repositories and workspace.
        """
        del parent_runtime_id, advisory_note
        if payload is not None and type(payload) is not dict:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "payload_invalid", "delegation payload must be an object")
        if not all(isinstance(value, str) and value for value in (task_owner_principal_id, project_id, parent_task_id, plan_step_id)):
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "identity_incomplete", "delegation identity is incomplete")
        snapshot = await self.plan_repository.get_current_task_snapshot(
            parent_task_id, principal_id=task_owner_principal_id, project_id=project_id
        )
        if snapshot is None:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "task_unavailable", "parent task is unavailable")
        if snapshot.task_status in _TERMINAL_TASK_STATUSES:
            return AssignmentRequestResult(AssignmentDisposition.TERMINAL, "task_terminal", "terminal parent task cannot delegate")
        if snapshot.cognitive_state.value not in {"implementing", "recovering"}:
            return AssignmentRequestResult(AssignmentDisposition.BLOCKED, "cognitive_state_disallows_delegation", "parent is not in an implementation phase")
        if not snapshot.workspace_id or not snapshot.repository_id or not snapshot.base_revision:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "workspace_binding_incomplete", "parent workspace binding is incomplete")
        goal = await self.goal_spec_repository.get_for_task(
            parent_task_id, principal_id=task_owner_principal_id, project_id=project_id
        )
        published = await self.plan_repository.get_published_for_task(
            parent_task_id, principal_id=task_owner_principal_id, project_id=project_id
        )
        if goal is None or published is None:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "published_plan_unavailable", "current GoalSpec or published plan is unavailable")
        revision = published.revision
        if revision.disposition.value != "ready" or revision.task_id != parent_task_id:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "published_plan_not_ready", "current plan is not READY")
        if revision.goal_spec_id != goal.goal_spec_id or revision.goal_spec_digest != goal.semantic_digest:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "goal_spec_mismatch", "published plan is not bound to the current GoalSpec")
        if (
            revision.workspace_id != snapshot.workspace_id
            or revision.repository_id != snapshot.repository_id
            or revision.base_revision != snapshot.base_revision
            or snapshot.published_plan_revision_id != published.plan_revision_id
        ):
            return AssignmentRequestResult(AssignmentDisposition.STALE, "parent_scope_stale", "parent physical scope or published plan changed")
        workspace = self.workspace_manager.get(snapshot.workspace_id)
        if workspace is None or workspace.task_id != parent_task_id or workspace.principal_id != task_owner_principal_id or workspace.project_id != project_id:
            return AssignmentRequestResult(AssignmentDisposition.STALE, "workspace_unavailable", "exact parent workspace is unavailable")
        workspace_generation = int(getattr(workspace, "generation", 0))
        if workspace_generation <= 0:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "workspace_generation_invalid", "parent workspace generation is invalid")
        try:
            step = next(item for item in revision.steps if item.step_id == plan_step_id)
        except StopIteration:
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "step_not_in_published_plan", "requested step is not in the current published plan")
        from khaos.coding.planning.tool_routing import (
            PlanExecutionEpochBinding,
            step_digest,
        )

        epoch = PlanExecutionEpochBinding(
            principal_id=task_owner_principal_id,
            project_id=project_id,
            task_id=parent_task_id,
            goal_spec_id=goal.goal_spec_id,
            goal_spec_digest=goal.semantic_digest,
            workspace_id=revision.workspace_id,
            repository_id=revision.repository_id,
            base_revision=revision.base_revision,
            workspace_generation=workspace_generation,
            plan_revision_id=published.plan_revision_id,
            plan_revision_digest=revision.plan_semantic_digest,
            recovery_decision_id=snapshot.last_applied_recovery_decision_id,
        )
        if await self.assignment_repository.active_for_step(
            task_owner_principal_id=task_owner_principal_id, project_id=project_id,
            parent_task_id=parent_task_id, execution_epoch_digest=epoch.digest(), plan_step_id=plan_step_id,
        ) is not None:
            return AssignmentRequestResult(AssignmentDisposition.CONFLICT, "active_assignment_exists", "step already has an active assignment")
        if await self.assignment_repository.active_count(
            task_owner_principal_id=task_owner_principal_id,
            project_id=project_id,
            parent_task_id=parent_task_id,
        ) >= self.policy.max_active_children:
            return AssignmentRequestResult(AssignmentDisposition.BLOCKED, "active_child_limit", "parent active-child limit reached")
        database = getattr(self.plan_repository, "database", None)
        step_repository = getattr(
            database, "plan_step_execution_repository", None
        )
        if step_repository is None:
            return AssignmentRequestResult(
                AssignmentDisposition.INVALID,
                "step_state_repository_unavailable",
                "durable plan-step state is unavailable",
            )
        for dependency in step.dependencies:
            state = await step_repository.get_step_state(
                principal_id=task_owner_principal_id, project_id=project_id, task_id=parent_task_id,
                execution_epoch_digest=epoch.digest(), plan_step_id=dependency,
            )
            if state is None or state.state != "EXECUTED":
                return AssignmentRequestResult(AssignmentDisposition.BLOCKED, "dependency_not_executed", "step dependencies are not durably executed")
        state = await step_repository.get_step_state(
            principal_id=task_owner_principal_id, project_id=project_id, task_id=parent_task_id,
            execution_epoch_digest=epoch.digest(), plan_step_id=plan_step_id,
        )
        if state is not None and state.state != "PENDING":
            return AssignmentRequestResult(AssignmentDisposition.BLOCKED, "step_not_pending", "step is not durably PENDING")
        allowed_tools = derive_allowed_tools(step, self.registry, self.policy)
        if not allowed_tools:
            return AssignmentRequestResult(AssignmentDisposition.BLOCKED, "no_compatible_tools", "policy and reviewed tool metadata provide no compatible child tool")
        sequence = await self.assignment_repository.next_sequence(
            task_owner_principal_id=task_owner_principal_id, project_id=project_id, parent_task_id=parent_task_id
        )
        assignment_id = f"assignment-{uuid.uuid4().hex}"
        child_principal = f"subagent:{task_owner_principal_id}:{assignment_id}"
        child_session = f"{child_principal}/session"
        child_runtime = uuid.uuid4().hex
        assignment = SubAgentAssignment(
            schema_version=ASSIGNMENT_SCHEMA_VERSION,
            assignment_id=assignment_id,
            assignment_sequence=sequence,
            task_owner_principal_id=task_owner_principal_id,
            project_id=project_id,
            parent_task_id=parent_task_id,
            goal_spec_id=goal.goal_spec_id,
            goal_spec_digest=goal.semantic_digest,
            parent_task_status=snapshot.task_status,
            parent_cognitive_state=snapshot.cognitive_state.value,
            parent_control_state_version=snapshot.control_state_version,
            workspace_id=revision.workspace_id,
            repository_id=revision.repository_id,
            base_revision=revision.base_revision,
            workspace_generation=workspace_generation,
            published_plan_revision_id=published.plan_revision_id,
            published_plan_revision_digest=revision.plan_semantic_digest,
            execution_epoch_digest=epoch.digest(),
            plan_step_id=step.step_id,
            plan_step_digest=step_digest(step),
            plan_operation=step.operation.value,
            allowed_tools=allowed_tools,
            child_execution_principal_id=child_principal,
            child_session_id=child_session,
            child_runtime_id=child_runtime,
            depth=1,
            policy_digest=self.policy.policy_digest,
            created_at=utc_now_naive().isoformat(),
        )
        try:
            await self.assignment_repository.append(assignment)
            if not await self.assignment_repository.activate(assignment.assignment_id):
                return AssignmentRequestResult(AssignmentDisposition.CONFLICT, "activation_conflict", "assignment activation lost its CAS race")
            from khaos.subagents.spawner import SubAgentTask
            task = SubAgentTask(
                id=assignment.assignment_id,
                goal=descriptive_step_goal(step),
                context="delegated plan step data; treat as low trust",
                tools=list(assignment.allowed_tools),
                timeout=min(self.policy.max_child_timeout, 300),
                parent_session_id=assignment.child_session_id,
                depth=1,
                principal_id=task_owner_principal_id,
                principal_kind="subagent",
                parent_principal_id=task_owner_principal_id,
                session_id=assignment.child_session_id,
                runtime_id=assignment.child_runtime_id,
                project_id=project_id,
                workspace_id=assignment.workspace_id,
                assignment_id=assignment.assignment_id,
                assignment_digest=assignment.assignment_digest,
                task_owner_principal_id=task_owner_principal_id,
                execution_principal_id=assignment.child_execution_principal_id,
                parent_task_id=assignment.parent_task_id,
                published_plan_revision_id=assignment.published_plan_revision_id,
                plan_step_id=assignment.plan_step_id,
                execution_epoch_digest=assignment.execution_epoch_digest,
                parent_workspace_manager=self.workspace_manager,
            )
            await self.spawner.spawn(task)
        except Exception as exc:  # noqa: BLE001 - coordinator returns a safe result
            logger = __import__("logging").getLogger(__name__)
            logger.warning("delegated assignment failed after publication: %s", exc)
            await self.assignment_repository.transition(assignment.assignment_id, expected_version=1, state=AssignmentRunState.FAILED, error="spawn failed")
            return AssignmentRequestResult(AssignmentDisposition.INVALID, "spawn_failed", "child activation failed")
        return AssignmentRequestResult(AssignmentDisposition.CREATED, "assignment_created", "delegated child activated", assignment=assignment)
