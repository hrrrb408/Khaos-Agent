"""Durable M8.5 child/merge projections and append-only events."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.subagents.contracts import (
    ChildWorkspaceBinding,
    ChildWorkspaceState,
    MergePlan,
    MergeResult,
    SubagentAssignment,
    SubagentResult,
    SubagentResultStatus,
)
from khaos.time_utils import utc_now_naive


class ParallelRepositoryDatabase(Protocol):
    """Small database port used by the M8.5 projection owner."""

    def transaction(self) -> Any: ...

    def read_connection(self) -> Any: ...


def _now() -> str:
    return utc_now_naive().isoformat()


_CHILD_STATE_TRANSITIONS: dict[ChildWorkspaceState, frozenset[ChildWorkspaceState]] = {
    ChildWorkspaceState.STARTING: frozenset(
        {
            ChildWorkspaceState.READY,
            ChildWorkspaceState.RUNNING,
            ChildWorkspaceState.CANCELLED,
            ChildWorkspaceState.FAILED,
            ChildWorkspaceState.UNKNOWN,
            ChildWorkspaceState.QUARANTINED,
        }
    ),
    ChildWorkspaceState.READY: frozenset(
        {
            ChildWorkspaceState.RUNNING,
            ChildWorkspaceState.CANCELLED,
            ChildWorkspaceState.FAILED,
            ChildWorkspaceState.UNKNOWN,
            ChildWorkspaceState.QUARANTINED,
        }
    ),
    ChildWorkspaceState.RUNNING: frozenset(
        {
            ChildWorkspaceState.VERIFYING,
            ChildWorkspaceState.SUCCESS,
            ChildWorkspaceState.CANCELLED,
            ChildWorkspaceState.FAILED,
            ChildWorkspaceState.STALE,
            ChildWorkspaceState.CONFLICT,
            ChildWorkspaceState.UNKNOWN,
            ChildWorkspaceState.QUARANTINED,
        }
    ),
    ChildWorkspaceState.VERIFYING: frozenset(
        {
            ChildWorkspaceState.SUCCESS,
            ChildWorkspaceState.CANCELLED,
            ChildWorkspaceState.FAILED,
            ChildWorkspaceState.STALE,
            ChildWorkspaceState.CONFLICT,
            ChildWorkspaceState.UNKNOWN,
            ChildWorkspaceState.QUARANTINED,
        }
    ),
    ChildWorkspaceState.SUCCESS: frozenset(
        {
            ChildWorkspaceState.CLEANED,
            ChildWorkspaceState.QUARANTINED,
            ChildWorkspaceState.UNKNOWN,
        }
    ),
    ChildWorkspaceState.FAILED: frozenset(
        {
            ChildWorkspaceState.CLEANED,
            ChildWorkspaceState.QUARANTINED,
            ChildWorkspaceState.UNKNOWN,
        }
    ),
    ChildWorkspaceState.CANCELLED: frozenset(
        {
            ChildWorkspaceState.CLEANED,
            ChildWorkspaceState.QUARANTINED,
            ChildWorkspaceState.UNKNOWN,
        }
    ),
    ChildWorkspaceState.STALE: frozenset(
        {
            ChildWorkspaceState.CLEANED,
            ChildWorkspaceState.QUARANTINED,
            ChildWorkspaceState.UNKNOWN,
        }
    ),
    ChildWorkspaceState.CONFLICT: frozenset(
        {
            ChildWorkspaceState.CLEANED,
            ChildWorkspaceState.QUARANTINED,
            ChildWorkspaceState.UNKNOWN,
        }
    ),
    ChildWorkspaceState.UNKNOWN: frozenset(
        {ChildWorkspaceState.CLEANED, ChildWorkspaceState.QUARANTINED}
    ),
    # Quarantine retains ownership until a later cleanup proves the
    # worktree/branch is gone; that recovery may transition to CLEANED.
    ChildWorkspaceState.QUARANTINED: frozenset({ChildWorkspaceState.CLEANED}),
    ChildWorkspaceState.CLEANED: frozenset(),
}


class ParallelSubagentRepository:
    """Persist immutable bindings/results and monotonic lifecycle projections."""

    def __init__(self, database: ParallelRepositoryDatabase) -> None:
        self._database = database

    async def record_assignment(self, assignment: SubagentAssignment) -> None:
        """Publish one assignment idempotently, rejecting digest collisions."""
        payload = canonical_json_bytes(assignment.to_payload()).decode("utf-8")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT OR IGNORE INTO agent_parallel_assignments (
                    assignment_id, parent_task_id, parent_workspace_id, project_id,
                    parent_principal_id, child_principal_id, child_runtime_id,
                    role, access_mode, base_generation, base_commit,
                    assignment_digest, assignment_json, state, revision,
                    created_at, updated_at, cleanup_state, quarantine_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'starting', 0, ?, ?, 'pending', '')
                """,
                (
                    assignment.assignment_id,
                    assignment.parent_task_id,
                    assignment.parent_workspace_id,
                    assignment.project_id,
                    assignment.parent_principal_id,
                    assignment.child_principal_id,
                    assignment.child_runtime_id,
                    assignment.role.value,
                    assignment.access_mode.value,
                    assignment.base_generation,
                    assignment.base_commit,
                    assignment.assignment_digest,
                    payload,
                    _now(),
                    _now(),
                ),
            )
            row = await self._assignment_row(conn, assignment.assignment_id)
            if row is None or row["assignment_digest"] != assignment.assignment_digest:
                raise RuntimeError("parallel assignment digest collision")

    async def record_binding(
        self,
        assignment: SubagentAssignment,
        binding: ChildWorkspaceBinding,
    ) -> None:
        """Persist one immutable child-workspace binding exactly once."""
        await self.record_assignment(assignment)
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT OR IGNORE INTO agent_parallel_child_workspaces (
                    assignment_id, child_task_id, child_workspace_id,
                    child_worktree_path, child_branch, base_generation, base_commit,
                    binding_digest, state, revision, created_at, cleaned_at,
                    quarantine_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', 0, ?, NULL, '')
                """,
                (
                    binding.assignment_id,
                    binding.child_task_id,
                    binding.child_workspace_id,
                    binding.child_worktree_path,
                    binding.child_branch,
                    binding.base_generation,
                    binding.base_commit,
                    binding.binding_digest,
                    _now(),
                ),
            )
            row = await self._binding_row(conn, binding.assignment_id)
            if row is None or row["binding_digest"] != binding.binding_digest:
                raise RuntimeError("parallel child binding digest collision")
            await conn.execute(
                "UPDATE agent_parallel_assignments SET state = CASE "
                "WHEN state IN ('cleaned', 'quarantined') THEN state ELSE 'ready' END, "
                "updated_at = ? WHERE assignment_id = ?",
                (_now(), assignment.assignment_id),
            )

    async def update_child_state(
        self,
        assignment_id: str,
        state: ChildWorkspaceState,
        *,
        result_status: SubagentResultStatus | None = None,
        reason: str = "",
    ) -> None:
        """Advance a child projection monotonically and record quarantine."""
        if not isinstance(state, ChildWorkspaceState):
            state = ChildWorkspaceState(state)
        if len(reason.encode("utf-8")) > 4096:
            raise ValueError("child state reason exceeds its bound")
        async with self._database.transaction() as conn:
            row = await self._binding_row(conn, assignment_id)
            if row is None:
                return
            revision = int(row["revision"])
            current_state = ChildWorkspaceState(str(row["state"]))
            if state is current_state:
                return
            if state not in _CHILD_STATE_TRANSITIONS[current_state]:
                raise RuntimeError(
                    f"invalid parallel child state transition: "
                    f"{current_state.value} -> {state.value}"
                )
            cleaned_at = _now() if state is ChildWorkspaceState.CLEANED else row["cleaned_at"]
            cursor = await conn.execute(
                """
                UPDATE agent_parallel_child_workspaces
                SET state = ?, revision = revision + 1, cleaned_at = ?, quarantine_reason = ?
                WHERE assignment_id = ? AND revision = ?
                """,
                (
                    state.value,
                    cleaned_at,
                    reason if state is ChildWorkspaceState.QUARANTINED else "",
                    assignment_id,
                    revision,
                ),
            )
            if int(getattr(cursor, "rowcount", 0)) != 1:
                raise RuntimeError("parallel child state CAS failed")
            assignment_state = (
                "quarantined"
                if state is ChildWorkspaceState.QUARANTINED
                else state.value
            )
            await conn.execute(
                """
                UPDATE agent_parallel_assignments
                SET state = ?, revision = revision + 1,
                    cleanup_state = ?, quarantine_reason = ?, updated_at = ?
                WHERE assignment_id = ?
                """,
                (
                    assignment_state,
                    "cleaned" if state is ChildWorkspaceState.CLEANED else "pending",
                    reason if state is ChildWorkspaceState.QUARANTINED else "",
                    _now(),
                    assignment_id,
                ),
            )

    async def child_state(self, assignment_id: str) -> ChildWorkspaceState | None:
        """Read the durable child state for idempotent cleanup/recovery."""
        async with self._database.read_connection() as conn:
            row = await self._binding_row(conn, assignment_id)
        if row is None:
            return None
        return ChildWorkspaceState(str(row["state"]))

    async def record_result(self, result: SubagentResult) -> None:
        """Persist a result once; duplicate retries must carry the same digest."""
        payload = canonical_json_bytes(result.to_payload()).decode("utf-8")
        assignment_state = {
            SubagentResultStatus.SUCCESS: "success",
            SubagentResultStatus.FAILED: "failed",
            SubagentResultStatus.CANCELLED: "cancelled",
            SubagentResultStatus.STALE: "stale",
            SubagentResultStatus.CONFLICT: "conflict",
            SubagentResultStatus.QUARANTINED: "quarantined",
        }[result.status]
        async with self._database.transaction() as conn:
            assignment = await self._assignment_row(conn, result.assignment_id)
            if assignment is None:
                raise RuntimeError("parallel result has no durable assignment")
            await conn.execute(
                """
                INSERT OR IGNORE INTO agent_parallel_subagent_results (
                    assignment_id, status, result_json, result_digest, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (result.assignment_id, result.status.value, payload, result.result_digest, _now()),
            )
            cursor = await conn.execute(
                "SELECT result_digest FROM agent_parallel_subagent_results WHERE assignment_id = ?",
                (result.assignment_id,),
            )
            row = await cursor.fetchone()
            if row is None or row["result_digest"] != result.result_digest:
                raise RuntimeError("parallel result digest collision")
            await conn.execute(
                """
                UPDATE agent_parallel_assignments
                SET state = CASE
                    WHEN state IN ('cleaned', 'quarantined') THEN state
                    ELSE ?
                END,
                updated_at = ?
                WHERE assignment_id = ?
                """,
                (assignment_state, _now(), result.assignment_id),
            )

    async def record_merge_plan(self, plan: MergePlan) -> None:
        """Persist a plan before integration-worktree mutation."""
        plan_json = canonical_json_bytes(plan.to_payload()).decode("utf-8")
        candidate_json = canonical_json_bytes(plan.candidate_ids).decode("utf-8")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT OR IGNORE INTO agent_parallel_merge_records (
                    merge_id, parent_task_id, parent_workspace_id,
                    expected_parent_head, expected_parent_generation,
                    candidate_ids_json, plan_json, plan_digest, state,
                    result_json, result_digest, published_head, published_generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'planned', NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    plan.merge_id,
                    plan.parent_task_id,
                    plan.parent_workspace_id,
                    plan.parent_base_commit,
                    plan.parent_generation,
                    candidate_json,
                    plan_json,
                    plan.plan_digest,
                    _now(),
                    _now(),
                ),
            )
            cursor = await conn.execute(
                "SELECT plan_digest FROM agent_parallel_merge_records WHERE merge_id = ?",
                (plan.merge_id,),
            )
            row = await cursor.fetchone()
            if row is None or row["plan_digest"] != plan.plan_digest:
                raise RuntimeError("parallel merge plan digest collision")

    async def record_merge_result(self, result: MergeResult) -> None:
        """Persist a terminal merge result idempotently."""
        payload = canonical_json_bytes(result._payload(include_digest=True)).decode("utf-8")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT result_digest FROM agent_parallel_merge_records WHERE merge_id = ?",
                (result.merge_id,),
            )
            row = await cursor.fetchone()
            if row is None:
                raise RuntimeError("merge result has no durable plan")
            if row["result_digest"] not in (None, result.result_digest):
                # A terminal plan may be replayed after its first result was
                # recorded.  Keep the original durable terminal projection;
                # the replay observation is captured by the append-only event
                # emitted by MergeCoordinator.  Never let a replay overwrite
                # the first result or turn a safe stale rejection into a
                # persistence error.
                return
            await conn.execute(
                """
                UPDATE agent_parallel_merge_records
                SET state = ?, result_json = ?, result_digest = ?,
                    published_head = ?, published_generation = ?, updated_at = ?
                WHERE merge_id = ? AND (result_digest IS NULL OR result_digest = ?)
                """,
                (
                    result.status.value,
                    payload,
                    result.result_digest,
                    result.published_head,
                    result.published_generation,
                    _now(),
                    result.merge_id,
                    result.result_digest,
                ),
            )

    async def mark_merge_recovery(self, merge_id: str, reason: str) -> None:
        """Move an unfinished merge to an explicit restart/unknown state."""
        if len(reason.encode("utf-8")) > 4096:
            raise ValueError("merge recovery reason exceeds its bound")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                UPDATE agent_parallel_merge_records
                SET state = 'unknown', updated_at = ?
                WHERE merge_id = ? AND state IN ('planned', 'running', 'merging', 'unknown')
                """,
                (_now(), merge_id),
            )

    async def append_event(
        self,
        *,
        event_type: str,
        payload: Mapping[str, object],
        assignment_id: str | None = None,
        merge_id: str | None = None,
    ) -> str:
        """Append one digest-bound lifecycle event; never update/delete it."""
        if type(event_type) is not str or not event_type or len(event_type) > 128:
            raise ValueError("event_type is invalid")
        payload_json = canonical_json_bytes(dict(payload)).decode("utf-8")
        payload_digest = canonical_digest(dict(payload))
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO agent_parallel_events (
                    assignment_id, merge_id, event_type, payload_json,
                    payload_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (assignment_id, merge_id, event_type, payload_json, payload_digest, _now()),
            )
        return payload_digest

    async def incomplete(self) -> tuple[dict[str, object], ...]:
        """Read child/merge records that need restart reconciliation."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT 'child' AS kind, assignment_id, state, revision,
                       quarantine_reason
                FROM agent_parallel_child_workspaces
                WHERE state IN (
                    'starting', 'ready', 'running', 'verifying', 'success',
                    'failed', 'cancelled', 'stale', 'conflict', 'unknown',
                    'quarantined'
                )
                UNION ALL
                SELECT 'merge' AS kind, merge_id AS assignment_id, state, 0,
                       '' AS quarantine_reason
                FROM agent_parallel_merge_records
                WHERE state IN (
                    'planned', 'running', 'merging', 'unknown', 'quarantined',
                    'published-quarantined'
                )
                ORDER BY kind, assignment_id
                """
            )
            rows = await cursor.fetchall()
        return tuple(dict(row) for row in rows)

    async def _assignment_row(self, conn: Any, assignment_id: str) -> Any:
        cursor = await conn.execute(
            "SELECT assignment_id, assignment_digest FROM agent_parallel_assignments WHERE assignment_id = ?",
            (assignment_id,),
        )
        return await cursor.fetchone()

    async def _binding_row(self, conn: Any, assignment_id: str) -> Any:
        cursor = await conn.execute(
            "SELECT * FROM agent_parallel_child_workspaces WHERE assignment_id = ?",
            (assignment_id,),
        )
        return await cursor.fetchone()


__all__ = ["ParallelSubagentRepository"]
