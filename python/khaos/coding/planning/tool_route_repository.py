"""Append-only durable ledger for M7.6 tool route decisions."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol

from khaos.coding.planning.tool_routing import (
    PlanRouteDisposition,
    PlanToolRouteBinding,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.time_utils import utc_now_naive


class PlanRouteDatabase(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[Any]: ...
    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


@dataclass(frozen=True, slots=True)
class StoredPlanToolRoute:
    binding: PlanToolRouteBinding
    route_sequence: int
    created_at: str


class PlanToolRouteRepository:
    """Own route append and dispatch-fence transactions."""

    def __init__(self, database: PlanRouteDatabase) -> None:
        self._database = database
        from khaos.coding.planning.step_execution_repository import (
            PlanStepExecutionRepository,
        )
        self._step_repository = PlanStepExecutionRepository(database)

    @property
    def database(self) -> PlanRouteDatabase:
        return self._database

    async def append_route(self, binding: PlanToolRouteBinding) -> StoredPlanToolRoute:
        _validate_binding(binding)
        created_at = utc_now_naive().isoformat()
        payload = binding.payload()
        input_digest = _route_input_digest(binding)
        payload["route_digest"] = binding.route_digest
        payload["route_input_digest"] = input_digest
        canonical = canonical_json_bytes(payload).decode("utf-8")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT COALESCE(MAX(route_sequence), 0) + 1 AS next_sequence "
                "FROM agent_plan_tool_routes WHERE principal_id = ? AND project_id = ? AND task_id = ?",
                (binding.principal_id, binding.project_id, binding.task_id),
            )
            row = await cursor.fetchone()
            sequence = int(row["next_sequence"] if row is not None else 1)
            try:
                await conn.execute(
                    """INSERT INTO agent_plan_tool_routes (
                        route_id, route_sequence, principal_id, project_id, task_id,
                        execution_epoch_digest, plan_revision_id, plan_revision_digest,
                        plan_step_id, plan_step_digest, tool_name, tool_security_digest,
                        arguments_digest, authorization_resource_digest,
                        route_disposition, reason_code, route_input_digest,
                        route_digest, canonical_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        binding.route_id, sequence, binding.principal_id,
                        binding.project_id, binding.task_id,
                        binding.execution_epoch_digest, binding.plan_revision_id,
                        binding.plan_revision_digest, binding.plan_step_id,
                        binding.plan_step_digest, binding.tool_name,
                        binding.tool_security_digest, binding.arguments_digest,
                        binding.authorization_resource_digest,
                        binding.disposition.value, binding.reason_code,
                        input_digest, binding.route_digest,
                        canonical, created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError("plan route identity or sequence conflict") from exc
        return StoredPlanToolRoute(binding=binding, route_sequence=sequence, created_at=created_at)

    async def get_route(
        self, route_id: str, *, principal_id: str, project_id: str, task_id: str
    ) -> StoredPlanToolRoute | None:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM agent_plan_tool_routes WHERE route_id = ? AND principal_id = ? AND project_id = ? AND task_id = ?",
                (route_id, principal_id, project_id, task_id),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return _decode_route(row)

    async def get_step_state(self, **kwargs: Any) -> Any:
        return await self._step_repository.get_step_state(**kwargs)

    async def begin_dispatch(self, binding: PlanToolRouteBinding) -> Any:
        stored = await self.get_route(
            binding.route_id,
            principal_id=binding.principal_id,
            project_id=binding.project_id,
            task_id=binding.task_id,
        )
        if stored is None or stored.binding != binding:
            raise PermissionError("route is not current in the durable ledger")
        return await self._step_repository.begin_dispatch(binding)

    async def finish_dispatch(self, fence: Any, **kwargs: Any) -> None:
        await self._step_repository.finish_dispatch(fence, **kwargs)

    async def recover_active_dispatches(self) -> int:
        return await self._step_repository.recover_active_dispatches()

    async def active_dispatch_count(
        self, *, principal_id: str, project_id: str, task_id: str
    ) -> int:
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) AS count FROM agent_plan_dispatch_fences WHERE principal_id = ? AND project_id = ? AND task_id = ? AND status = 'ACTIVE'",
                (principal_id, project_id, task_id),
            )
            row = await cursor.fetchone()
        return int(row["count"] if row is not None else 0)


def _validate_binding(binding: PlanToolRouteBinding) -> None:
    for name in (
        "route_id", "principal_id", "project_id", "task_id", "workspace_id",
        "tool_name", "tool_security_digest", "arguments_digest",
        "authorization_resource_digest", "route_digest", "reason_code",
    ):
        value = getattr(binding, name)
        if type(value) is not str or not value:
            raise ValueError(f"route binding field {name} is invalid")
    if type(binding.disposition) is not PlanRouteDisposition:
        raise ValueError("route disposition is invalid")
    plan_fields = (
        binding.plan_revision_id,
        binding.plan_revision_digest,
        binding.plan_step_id,
        binding.plan_step_digest,
        binding.execution_epoch_digest,
    )
    if any(value is not None for value in plan_fields) and not all(
        type(value) is str and bool(value) for value in plan_fields
    ):
        raise ValueError("route plan binding is incomplete")
    if binding.disposition is PlanRouteDisposition.ALLOW and not all(
        type(value) is str and bool(value) for value in plan_fields
    ):
        raise ValueError("ALLOW route lacks a complete plan binding")
    if (
        binding.disposition is PlanRouteDisposition.SUPPORTING_READ
        and any(value is not None for value in plan_fields)
    ):
        raise ValueError("supporting-read route cannot carry a plan step binding")
    expected = binding.recompute_digest()
    if expected != binding.route_digest:
        raise ValueError("route digest does not match canonical binding")
    if binding.workspace_generation <= 0:
        raise ValueError("route workspace generation is invalid")


def _decode_route(row: Any) -> StoredPlanToolRoute:
    try:
        payload = json.loads(row["canonical_json"])
        if type(payload) is not dict:
            raise ValueError("route payload is not an object")
        binding = PlanToolRouteBinding(
            route_id=str(row["route_id"]),
            route_digest=str(row["route_digest"]),
            principal_id=str(row["principal_id"]),
            project_id=str(row["project_id"]),
            task_id=str(row["task_id"]),
            workspace_id=str(payload["workspace_id"]),
            workspace_generation=int(payload["workspace_generation"]),
            plan_revision_id=payload.get("plan_revision_id"),
            plan_revision_digest=payload.get("plan_revision_digest"),
            plan_step_id=payload.get("plan_step_id"),
            plan_step_digest=payload.get("plan_step_digest"),
            execution_epoch_digest=payload.get("execution_epoch_digest"),
            tool_name=str(row["tool_name"]),
            tool_security_digest=str(row["tool_security_digest"]),
            arguments_digest=str(row["arguments_digest"]),
            authorization_resource_digest=str(row["authorization_resource_digest"]),
            disposition=PlanRouteDisposition(str(row["route_disposition"])),
            reason_code=str(row["reason_code"]),
        )
        _validate_binding(binding)
        expected_payload = binding.payload()
        expected_payload["route_digest"] = binding.route_digest
        expected_payload["route_input_digest"] = _route_input_digest(binding)
        if payload != expected_payload or row["route_input_digest"] != expected_payload["route_input_digest"]:
            raise ValueError("route canonical payload disagrees with columns")
        return StoredPlanToolRoute(binding, int(row["route_sequence"]), str(row["created_at"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("malformed durable plan route") from exc


__all__ = ["PlanRouteDatabase", "PlanToolRouteRepository", "StoredPlanToolRoute"]


def _route_input_digest(binding: PlanToolRouteBinding) -> str:
    """Digest the admitted call inputs without server-assigned route identity."""
    return canonical_digest({
        "principal_id": binding.principal_id,
        "project_id": binding.project_id,
        "task_id": binding.task_id,
        "workspace_id": binding.workspace_id,
        "workspace_generation": binding.workspace_generation,
        "tool_name": binding.tool_name,
        "tool_security_digest": binding.tool_security_digest,
        "arguments_digest": binding.arguments_digest,
        "authorization_resource_digest": binding.authorization_resource_digest,
    })
