"""Durable M7.6 step progress and active dispatch fences."""

from __future__ import annotations

import json
import uuid
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol

from khaos.coding.planning.revision import plan_revision_from_canonical_json
from khaos.coding.planning.tool_routing import (
    PlanExecutionEpochBinding,
    PlanToolRouteBinding,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.time_utils import utc_now_naive

_EFFECT_STATUSES = frozenset({
    "not_started", "not_applied", "applied", "partial", "unknown",
})


class StepExecutionDatabase(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[Any]: ...
    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


@dataclass(frozen=True, slots=True)
class PlanStepExecutionState:
    principal_id: str
    project_id: str
    task_id: str
    execution_epoch_digest: str
    plan_revision_id: str
    plan_revision_digest: str
    plan_step_id: str
    plan_step_digest: str
    state: str
    attempt_generation: int
    covered_targets: tuple[str, ...]
    covered_targets_digest: str
    active_route_id: str | None
    active_route_digest: str | None
    updated_at: str


@dataclass(frozen=True, slots=True)
class PlanDispatchFence:
    fence_id: str
    route_id: str
    route_digest: str
    principal_id: str
    project_id: str
    task_id: str
    execution_epoch_digest: str
    plan_revision_id: str
    plan_step_id: str | None
    workspace_id: str
    workspace_generation: int
    status: str
    created_at: str
    binding: PlanToolRouteBinding | None = None


class PlanStepExecutionRepository:
    """Own mutable step evidence; route history remains append-only."""

    def __init__(self, database: StepExecutionDatabase) -> None:
        self._database = database

    async def get_step_state(
        self, *, principal_id: str, project_id: str, task_id: str,
        execution_epoch_digest: str, plan_step_id: str,
    ) -> PlanStepExecutionState | None:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM agent_plan_step_states WHERE principal_id = ? AND project_id = ? AND task_id = ? AND execution_epoch_digest = ? AND plan_step_id = ?",
                (principal_id, project_id, task_id, execution_epoch_digest, plan_step_id),
            )
            row = await cursor.fetchone()
        return _decode_state(row) if row is not None else None

    async def record_effect(
        self, binding: PlanToolRouteBinding, *, effect_status: str,
        affected_targets: tuple[str, ...] = (), effect_id: str = "",
    ) -> PlanStepExecutionState | None:
        if effect_status not in _EFFECT_STATUSES:
            raise ValueError("unknown plan dispatch effect status")
        if binding.plan_step_id is None or binding.execution_epoch_digest is None:
            return None
        normalized = tuple(sorted(set(affected_targets)))
        targets_match = True
        if effect_status == "applied":
            async with self._database.read_connection() as conn:
                cursor = await conn.execute(
                    "SELECT canonical_json FROM agent_plan_revisions WHERE plan_revision_id = ? AND principal_id = ? AND project_id = ? AND task_id = ?",
                    (
                        binding.plan_revision_id,
                        binding.principal_id,
                        binding.project_id,
                        binding.task_id,
                    ),
                )
                plan_row = await cursor.fetchone()
            try:
                plan = plan_revision_from_canonical_json(plan_row["canonical_json"])
                selected_step = next(
                    step for step in plan.steps if step.step_id == binding.plan_step_id
                )
                # Verification commands prove their exact argv, not a file
                # target. File operations must prove the complete canonical
                # target tuple before a dependency can advance.
                if binding.tool_name not in {"terminal_argv", "test_run"}:
                    targets_match = normalized == tuple(sorted(selected_step.target_files))
            except (KeyError, StopIteration, TypeError, ValueError):
                targets_match = False
        if effect_status == "applied" and targets_match:
            state = "EXECUTED"
        elif effect_status == "applied" or effect_status in {"partial", "unknown"}:
            state = "UNCERTAIN"
        else:
            state = "PENDING"
        now = utc_now_naive().isoformat()
        covered_digest = canonical_digest(list(normalized))
        async with self._database.transaction() as conn:
            await conn.execute(
                """INSERT INTO agent_plan_step_states (
                    principal_id, project_id, task_id, execution_epoch_digest,
                    plan_revision_id, plan_revision_digest, plan_step_id,
                    plan_step_digest, state, attempt_generation, covered_targets,
                    covered_targets_digest, active_route_id, active_route_digest,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, NULL, ?)
                ON CONFLICT(principal_id, project_id, task_id, execution_epoch_digest, plan_step_id)
                DO UPDATE SET state = excluded.state,
                    attempt_generation = agent_plan_step_states.attempt_generation + 1,
                    covered_targets = excluded.covered_targets,
                    covered_targets_digest = excluded.covered_targets_digest,
                    active_route_id = NULL, active_route_digest = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    binding.principal_id, binding.project_id, binding.task_id,
                    binding.execution_epoch_digest, binding.plan_revision_id,
                    binding.plan_revision_digest, binding.plan_step_id,
                    binding.plan_step_digest, state,
                    canonical_json_bytes(list(normalized)).decode("utf-8"),
                    covered_digest, now,
                ),
            )
            cursor = await conn.execute(
                "SELECT * FROM agent_plan_step_states WHERE principal_id = ? AND project_id = ? AND task_id = ? AND execution_epoch_digest = ? AND plan_step_id = ?",
                (binding.principal_id, binding.project_id, binding.task_id, binding.execution_epoch_digest, binding.plan_step_id),
            )
            row = await cursor.fetchone()
        return _decode_state(row)

    async def begin_dispatch(self, binding: PlanToolRouteBinding) -> PlanDispatchFence:
        if binding.plan_revision_id is None or binding.execution_epoch_digest is None:
            raise PermissionError("dispatch fence requires a plan-bound route")
        now = utc_now_naive().isoformat()
        fence_id = f"fence-{uuid.uuid4().hex}"
        async with self._database.transaction() as conn:
            task_cursor = await conn.execute(
                "SELECT published_plan_revision_id, project_id, principal_id, last_applied_recovery_decision_id, state_json FROM coding_tasks WHERE id = ? AND principal_id = ? AND project_id = ? AND status NOT IN ('completed', 'failed', 'cancelled')",
                (binding.task_id, binding.principal_id, binding.project_id),
            )
            task = await task_cursor.fetchone()
            if task is None or task["published_plan_revision_id"] != binding.plan_revision_id:
                raise PermissionError("published plan changed before dispatch")
            plan_cursor = await conn.execute(
                "SELECT canonical_json, plan_semantic_digest FROM agent_plan_revisions WHERE plan_revision_id = ? AND principal_id = ? AND project_id = ? AND task_id = ?",
                (binding.plan_revision_id, binding.principal_id, binding.project_id, binding.task_id),
            )
            plan_row = await plan_cursor.fetchone()
            if plan_row is None or plan_row["plan_semantic_digest"] != binding.plan_revision_digest:
                raise PermissionError("published plan digest changed before dispatch")
            try:
                plan = plan_revision_from_canonical_json(plan_row["canonical_json"])
            except (TypeError, ValueError, KeyError) as exc:
                raise PermissionError("published plan is malformed before dispatch") from exc
            try:
                task_state = json.loads(task["state_json"])
                metadata = task_state["metadata"]
                if type(metadata) is not dict:
                    raise ValueError("task metadata is malformed")
                if (
                    metadata.get("workspace_id") != plan.workspace_id
                    or metadata.get("repository_id") != plan.repository_id
                    or metadata.get("base_sha") != plan.base_revision
                ):
                    raise ValueError("task physical scope changed")
                current_epoch = PlanExecutionEpochBinding(
                    principal_id=binding.principal_id,
                    project_id=binding.project_id,
                    task_id=binding.task_id,
                    goal_spec_id=plan.goal_spec_id,
                    goal_spec_digest=plan.goal_spec_digest,
                    workspace_id=plan.workspace_id,
                    repository_id=plan.repository_id,
                    base_revision=plan.base_revision,
                    workspace_generation=binding.workspace_generation,
                    plan_revision_id=plan.plan_revision_id,
                    plan_revision_digest=plan.plan_semantic_digest,
                    recovery_decision_id=task["last_applied_recovery_decision_id"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PermissionError("current plan execution epoch is malformed") from exc
            if current_epoch.digest() != binding.execution_epoch_digest:
                raise PermissionError("plan execution epoch changed before dispatch")
            selected_step = next(
                (step for step in plan.steps if step.step_id == binding.plan_step_id), None
            )
            if selected_step is None:
                raise PermissionError("selected plan step is no longer present")
            if binding.plan_step_digest != canonical_digest(selected_step.to_payload()):
                raise PermissionError("selected plan step digest changed before dispatch")
            for dependency in selected_step.dependencies:
                dependency_cursor = await conn.execute(
                    "SELECT state FROM agent_plan_step_states WHERE principal_id = ? AND project_id = ? AND task_id = ? AND execution_epoch_digest = ? AND plan_step_id = ?",
                    (binding.principal_id, binding.project_id, binding.task_id, binding.execution_epoch_digest, dependency),
                )
                dependency_row = await dependency_cursor.fetchone()
                if dependency_row is None or dependency_row["state"] != "EXECUTED":
                    raise PermissionError("plan step dependency is not durably EXECUTED")
            # A route may be fenced exactly once.  The DB transaction is the
            # cross-runtime TOCTOU barrier; no asyncio lock is relied upon.
            await conn.execute(
                "INSERT INTO agent_plan_dispatch_fences (fence_id, route_id, route_digest, principal_id, project_id, task_id, execution_epoch_digest, plan_revision_id, plan_step_id, workspace_id, workspace_generation, status, created_at, finished_at, effect_status, effect_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, NULL, NULL, NULL)",
                (
                    fence_id, binding.route_id, binding.route_digest,
                    binding.principal_id, binding.project_id, binding.task_id,
                    binding.execution_epoch_digest, binding.plan_revision_id,
                    binding.plan_step_id, binding.workspace_id,
                    binding.workspace_generation, now,
                ),
            )
            if binding.plan_step_id is not None:
                await conn.execute(
                    """INSERT INTO agent_plan_step_states (
                        principal_id, project_id, task_id, execution_epoch_digest,
                        plan_revision_id, plan_revision_digest, plan_step_id,
                        plan_step_digest, state, attempt_generation, covered_targets,
                        covered_targets_digest, active_route_id, active_route_digest,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, '[]', ?, ?, ?, ?)
                    ON CONFLICT(principal_id, project_id, task_id, execution_epoch_digest, plan_step_id)
                    DO UPDATE SET state = 'ACTIVE', active_route_id = excluded.active_route_id,
                        active_route_digest = excluded.active_route_digest,
                        attempt_generation = agent_plan_step_states.attempt_generation + 1,
                        updated_at = excluded.updated_at
                    """,
                    (
                        binding.principal_id, binding.project_id, binding.task_id,
                        binding.execution_epoch_digest, binding.plan_revision_id,
                        binding.plan_revision_digest, binding.plan_step_id,
                        binding.plan_step_digest, canonical_digest([]),
                        binding.route_id, binding.route_digest, now,
                    ),
                )
        return PlanDispatchFence(
            fence_id, binding.route_id, binding.route_digest,
            binding.principal_id, binding.project_id, binding.task_id,
            binding.execution_epoch_digest, binding.plan_revision_id,
            binding.plan_step_id, binding.workspace_id, binding.workspace_generation,
            "ACTIVE", now, binding,
        )

    async def finish_dispatch(
        self, fence: PlanDispatchFence, *, effect_status: str, effect_id: str,
        affected_targets: tuple[str, ...] = (),
    ) -> None:
        if effect_status not in _EFFECT_STATUSES:
            raise ValueError("unknown plan dispatch effect status")
        if fence.status != "ACTIVE":
            raise PermissionError("dispatch fence is not active")
        finished = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE agent_plan_dispatch_fences SET status = 'TERMINAL', finished_at = ?, effect_status = ?, effect_id = ? WHERE fence_id = ? AND route_id = ? AND route_digest = ? AND status = 'ACTIVE'",
                (finished, effect_status, effect_id, fence.fence_id, fence.route_id, fence.route_digest),
            )
            if int(cursor.rowcount or 0) != 1:
                raise PermissionError("dispatch fence was changed or already finished")
        if fence.plan_step_id is not None:
            binding = fence.binding
            if binding is None:
                raise PermissionError("dispatch fence lost its route binding")
            # Preserve the durable state transition while avoiding a second
            # authority decision.  The fence already authenticated the route.
            await self.record_effect(binding, effect_status=effect_status, affected_targets=affected_targets, effect_id=effect_id)

    async def recover_active_dispatches(self) -> int:
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE agent_plan_dispatch_fences SET status = 'UNCERTAIN', finished_at = ?, effect_status = 'unknown' WHERE status = 'ACTIVE'",
                (now,),
            )
            count = int(cursor.rowcount or 0)
            await conn.execute(
                "UPDATE agent_plan_step_states SET state = 'UNCERTAIN', active_route_id = NULL, active_route_digest = NULL, updated_at = ? WHERE state = 'ACTIVE'",
                (now,),
            )
        return count


def _decode_state(row: Any) -> PlanStepExecutionState:
    try:
        targets = json.loads(row["covered_targets"])
        if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
            raise ValueError("covered targets malformed")
        state = str(row["state"])
        if state not in {"PENDING", "ACTIVE", "EXECUTED", "UNCERTAIN"}:
            raise ValueError("step state invalid")
        if canonical_digest(targets) != str(row["covered_targets_digest"]):
            raise ValueError("covered target digest mismatch")
        return PlanStepExecutionState(
            principal_id=str(row["principal_id"]), project_id=str(row["project_id"]),
            task_id=str(row["task_id"]), execution_epoch_digest=str(row["execution_epoch_digest"]),
            plan_revision_id=str(row["plan_revision_id"]), plan_revision_digest=str(row["plan_revision_digest"]),
            plan_step_id=str(row["plan_step_id"]), plan_step_digest=str(row["plan_step_digest"]),
            state=state, attempt_generation=int(row["attempt_generation"]),
            covered_targets=tuple(targets), covered_targets_digest=str(row["covered_targets_digest"]),
            active_route_id=row["active_route_id"], active_route_digest=row["active_route_digest"],
            updated_at=str(row["updated_at"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("malformed durable plan step state") from exc


__all__ = ["PlanDispatchFence", "PlanStepExecutionRepository", "PlanStepExecutionState"]
