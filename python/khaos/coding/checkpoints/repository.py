"""Owner-scoped durable checkpoint and rewind-record persistence."""

from __future__ import annotations

import json
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.coding.checkpoints.contracts import (
    RewindExecutionResult,
    RewindPlan,
    TaskCheckpoint,
)
from khaos.coding.edit_transaction import (
    EditOperation,
    EditTransaction,
    TextEdit,
)
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.time_utils import utc_now_naive

MAX_CHECKPOINT_ROWS = 64
MAX_CHECKPOINT_JSON_BYTES = 16 * 1024 * 1024
MAX_REWIND_JSON_BYTES = 16 * 1024 * 1024


class CheckpointRepositoryDatabase(Protocol):
    """Minimal shared-connection port for checkpoint storage."""

    def transaction(self) -> AbstractAsyncContextManager[Any]: ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


class CheckpointRepositoryError(RuntimeError):
    """Base checkpoint persistence failure."""


class CheckpointConflictError(CheckpointRepositoryError):
    """Immutable checkpoint identity or digest collision."""


class CheckpointBindingError(CheckpointRepositoryError):
    """Checkpoint or rewind record belongs to a different owner."""


def _row_value(row: Any, key: str, index: int) -> Any:
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def _owner(principal_id: str, project_id: str) -> None:
    if type(principal_id) is not str or not principal_id:
        raise CheckpointBindingError("principal_id is required")
    if type(project_id) is not str or not project_id:
        raise CheckpointBindingError("project_id is required")


def _checkpoint_from_row(row: Any) -> TaskCheckpoint:
    payload = {
        "checkpoint_id": _row_value(row, "checkpoint_id", 0),
        "task_id": _row_value(row, "task_id", 1),
        "workspace_id": _row_value(row, "workspace_id", 2),
        "project_id": _row_value(row, "project_id", 4),
        "repository_generation": _row_value(row, "repository_generation", 5),
        "head_commit": _row_value(row, "head_commit", 6),
        "tree_digest": _row_value(row, "tree_digest", 7),
        "task_revision": _row_value(row, "task_revision", 8),
        "plan_revision": _row_value(row, "plan_revision", 9),
        "verification_evidence_digest": _row_value(row, "verification_evidence_digest", 10),
        "checkpoint_kind": _row_value(row, "checkpoint_kind", 11),
        "label": _row_value(row, "label", 12),
        "snapshot_digest": _row_value(row, "snapshot_digest", 13),
        "snapshot": json.loads(str(_row_value(row, "snapshot_json", 14))),
        "created_at": _row_value(row, "created_at", 15),
        "checkpoint_digest": _row_value(row, "checkpoint_digest", 16),
    }
    return TaskCheckpoint.from_payload(payload)


def _transaction_from_payload(value: object) -> EditTransaction | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise CheckpointRepositoryError("rewind transaction payload is malformed")
    operations: list[EditOperation] = []
    raw_operations = value.get("operations", [])
    if not isinstance(raw_operations, list):
        raise CheckpointRepositoryError("rewind operations are malformed")
    for raw in raw_operations:
        if not isinstance(raw, dict):
            raise CheckpointRepositoryError("rewind operation is malformed")
        edits: list[TextEdit] = []
        raw_edits = raw.get("text_edits", [])
        if not isinstance(raw_edits, list):
            raise CheckpointRepositoryError("rewind text edits are malformed")
        for edit in raw_edits:
            if not isinstance(edit, dict):
                raise CheckpointRepositoryError("rewind text edit is malformed")
            edits.append(TextEdit(
                start=edit.get("start", 0),
                end=edit.get("end", 0),
                replacement=edit.get("replacement", ""),
            ))
        operations.append(EditOperation(
            operation=raw.get("operation", ""),
            path=raw.get("path", ""),
            expected_exists=raw.get("expected_exists"),
            expected_digest=raw.get("expected_digest"),
            content=raw.get("content"),
            text_edits=tuple(edits),
            destination_path=raw.get("destination_path"),
        ))
    return EditTransaction(
        transaction_id=value.get("transaction_id", ""),
        workspace_id=value.get("workspace_id", ""),
        base_generation=value.get("base_generation", 0),
        operations=tuple(operations),
        expected_workspace_digest=value.get("expected_workspace_digest"),
        intent=value.get("intent", ""),
    )


def _rewind_from_row(row: Any) -> RewindPlan:
    # Keep the tuple fallbacks aligned with the v30 column order.  The
    # principal binding was deliberately added before project_id; using the
    # pre-v30 offsets here would decode a plan as a digest/status and could
    # turn a durable rewind record into a false stale or executable plan.
    payload = json.loads(str(_row_value(row, "plan_json", 13)))
    if not isinstance(payload, dict):
        raise CheckpointRepositoryError("rewind plan JSON is not an object")
    payload["plan_digest"] = _row_value(row, "plan_digest", 14)
    payload["transaction"] = _transaction_from_payload(payload.get("transaction"))
    payload["transaction_digest"] = _row_value(row, "transaction_digest", 15)
    return RewindPlan(
        rewind_id=payload.get("rewind_id", ""),
        task_id=payload.get("task_id", ""),
        workspace_id=payload.get("workspace_id", ""),
        project_id=payload.get("project_id", ""),
        source_generation=payload.get("source_generation", 0),
        source_head=payload.get("source_head", ""),
        source_tree=payload.get("source_tree", ""),
        target_checkpoint_id=payload.get("target_checkpoint_id", ""),
        target_checkpoint_digest=payload.get("target_checkpoint_digest", ""),
        target_generation=payload.get("target_generation", 0),
        target_head=payload.get("target_head", ""),
        target_tree=payload.get("target_tree", ""),
        source_snapshot_digest=payload.get("source_snapshot_digest", ""),
        affected_paths=tuple(payload.get("affected_paths", ())),
        preserved_paths=tuple(payload.get("preserved_paths", ())),
        user_drift=tuple(payload.get("user_drift", ())),
        conflicts=tuple(payload.get("conflicts", ())),
        transaction=payload.get("transaction"),
        transaction_digest=payload.get("transaction_digest"),
        expected_resulting_generation=payload.get("expected_resulting_generation", 0),
        status=payload.get("status", "planned"),
        created_at=payload.get("created_at", ""),
        plan_digest=payload.get("plan_digest", ""),
    )


class CheckpointRepository:
    """Persist immutable checkpoints and controlled rewind lifecycle records."""

    def __init__(self, database: CheckpointRepositoryDatabase) -> None:
        self._database = database

    async def create(
        self, checkpoint: TaskCheckpoint, *, principal_id: str = "legacy"
    ) -> TaskCheckpoint:
        """Insert one checkpoint idempotently and reject digest collisions."""
        _owner(principal_id, checkpoint.project_id)
        payload_json = canonical_json_bytes(checkpoint.to_payload()).decode("utf-8")
        if len(payload_json.encode("utf-8")) > MAX_CHECKPOINT_JSON_BYTES:
            raise CheckpointRepositoryError("checkpoint payload exceeds its bound")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_checkpoints WHERE checkpoint_id = ?",
                (checkpoint.checkpoint_id,),
            )
            existing_row = await cursor.fetchone()
            if existing_row is not None:
                existing = _checkpoint_from_row(existing_row)
                if existing.checkpoint_digest != checkpoint.checkpoint_digest:
                    raise CheckpointConflictError("checkpoint digest collision")
                if (
                    existing.task_id != checkpoint.task_id
                    or existing.workspace_id != checkpoint.workspace_id
                    or str(_row_value(existing_row, "principal_id", 3)) != principal_id
                    or existing.project_id != checkpoint.project_id
                ):
                    raise CheckpointBindingError("checkpoint identity is cross-bound")
                return existing
            await conn.execute(
                """
                INSERT INTO task_checkpoints (
                    checkpoint_id, task_id, workspace_id, principal_id, project_id,
                    repository_generation, head_commit, tree_digest,
                    task_revision, plan_revision, verification_evidence_digest,
                    checkpoint_kind, label, snapshot_digest, snapshot_json,
                    created_at, checkpoint_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint.checkpoint_id,
                    checkpoint.task_id,
                    checkpoint.workspace_id,
                    principal_id,
                    checkpoint.project_id,
                    checkpoint.repository_generation,
                    checkpoint.head_commit,
                    checkpoint.tree_digest,
                    checkpoint.task_revision,
                    checkpoint.plan_revision,
                    checkpoint.verification_evidence_digest,
                    checkpoint.checkpoint_kind.value,
                    checkpoint.label,
                    checkpoint.snapshot_digest,
                    canonical_json_bytes(checkpoint.snapshot).decode("utf-8"),
                    checkpoint.created_at,
                    checkpoint.checkpoint_digest,
                ),
            )
        return checkpoint

    insert = create

    async def get(
        self,
        checkpoint_id: str,
        *,
        principal_id: str,
        project_id: str,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> TaskCheckpoint | None:
        _owner(principal_id, project_id)
        query = (
            "SELECT * FROM task_checkpoints WHERE checkpoint_id = ? "
            "AND principal_id = ? AND project_id = ?"
        )
        params: list[object] = [checkpoint_id, principal_id, project_id]
        if task_id is not None:
            query += " AND task_id = ?"
            params.append(task_id)
        if workspace_id is not None:
            query += " AND workspace_id = ?"
            params.append(workspace_id)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(query, tuple(params))
            row = await cursor.fetchone()
        if row is None:
            return None
        checkpoint = _checkpoint_from_row(row)
        if checkpoint.project_id != project_id:
            return None
        return checkpoint

    get_checkpoint = get

    async def list(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str | None = None,
        limit: int = MAX_CHECKPOINT_ROWS,
    ) -> tuple[TaskCheckpoint, ...]:
        _owner(principal_id, project_id)
        if type(limit) is not int or limit <= 0 or limit > MAX_CHECKPOINT_ROWS:
            raise ValueError("checkpoint limit exceeds its bound")
        query = (
            "SELECT * FROM task_checkpoints WHERE task_id = ? AND principal_id = ? AND project_id = ?"
        )
        params: list[object] = [task_id, principal_id, project_id]
        if workspace_id is not None:
            query += " AND workspace_id = ?"
            params.append(workspace_id)
        query += " ORDER BY repository_generation ASC, created_at ASC LIMIT ?"
        params.append(limit)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
        return tuple(_checkpoint_from_row(row) for row in rows)

    list_checkpoints = list

    async def create_rewind_plan(
        self, plan: RewindPlan, *, principal_id: str = "legacy"
    ) -> RewindPlan:
        _owner(principal_id, plan.project_id)
        payload_json = canonical_json_bytes(plan.to_payload()).decode("utf-8")
        if len(payload_json.encode("utf-8")) > MAX_REWIND_JSON_BYTES:
            raise CheckpointRepositoryError("rewind plan exceeds its bound")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT * FROM rewind_records WHERE rewind_id = ?",
                (plan.rewind_id,),
            )
            existing_row = await cursor.fetchone()
            if existing_row is not None:
                existing = _rewind_from_row(existing_row)
                if (
                    existing.plan_digest != plan.plan_digest
                    or str(_row_value(existing_row, "principal_id", 3)) != principal_id
                    or existing.project_id != plan.project_id
                ):
                    raise CheckpointConflictError("rewind id is already bound to another plan")
                return existing
            await conn.execute(
                """
                INSERT INTO rewind_records (
                    rewind_id, task_id, workspace_id, principal_id, project_id,
                    source_generation, source_head, source_tree,
                    target_checkpoint_id, target_checkpoint_digest,
                    target_generation, target_head, target_tree,
                    plan_json, plan_digest, transaction_digest, status,
                    result_json, result_digest, resulting_generation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
                """,
                (
                    plan.rewind_id,
                    plan.task_id,
                    plan.workspace_id,
                    principal_id,
                    plan.project_id,
                    plan.source_generation,
                    plan.source_head,
                    plan.source_tree,
                    plan.target_checkpoint_id,
                    plan.target_checkpoint_digest,
                    plan.target_generation,
                    plan.target_head,
                    plan.target_tree,
                    payload_json,
                    plan.plan_digest,
                    plan.transaction_digest,
                    plan.status,
                    plan.created_at,
                    plan.created_at,
                ),
            )
        return plan

    async def get_rewind_plan(
        self, rewind_id: str, *, principal_id: str, project_id: str
    ) -> RewindPlan | None:
        _owner(principal_id, project_id)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM rewind_records WHERE rewind_id = ? AND principal_id = ? AND project_id = ?",
                (rewind_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return _rewind_from_row(row)

    async def finish_rewind(
        self,
        plan: RewindPlan,
        result: RewindExecutionResult,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        _owner(principal_id, project_id)
        result_json = canonical_json_bytes(result.to_payload()).decode("utf-8")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE rewind_records SET status = ?, result_json = ?,
                    result_digest = ?, resulting_generation = ?, updated_at = ?
                WHERE rewind_id = ? AND task_id = ? AND workspace_id = ?
                    AND principal_id = ? AND project_id = ? AND plan_digest = ?
                    AND result_json IS NULL
                """,
                (
                    result.status.value,
                    result_json,
                    result.result_digest,
                    result.resulting_generation,
                    utc_now_naive().isoformat(),
                    plan.rewind_id,
                    plan.task_id,
                    plan.workspace_id,
                    principal_id,
                    project_id,
                    plan.plan_digest,
                ),
            )
            if getattr(cursor, "rowcount", 1) == 0:
                existing_cursor = await conn.execute(
                    "SELECT result_json FROM rewind_records WHERE rewind_id = ? "
                    "AND task_id = ? AND workspace_id = ? AND principal_id = ? "
                    "AND project_id = ? AND plan_digest = ?",
                    (
                        plan.rewind_id,
                        plan.task_id,
                        plan.workspace_id,
                        principal_id,
                        project_id,
                        plan.plan_digest,
                    ),
                )
                existing_row = await existing_cursor.fetchone()
                existing_result = (
                    _row_value(existing_row, "result_json", 0)
                    if existing_row is not None
                    else None
                )
                if not existing_result:
                    raise CheckpointConflictError(
                        "rewind plan is no longer current"
                    )

    async def get_rewind_result(
        self, rewind_id: str, *, principal_id: str, project_id: str
    ) -> RewindExecutionResult | None:
        _owner(principal_id, project_id)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT result_json FROM rewind_records WHERE rewind_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (rewind_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        raw = _row_value(row, "result_json", 0)
        if not raw:
            return None
        payload = json.loads(str(raw))
        if not isinstance(payload, dict):
            raise CheckpointRepositoryError("rewind result JSON is not an object")
        return RewindExecutionResult(
            rewind_id=payload.get("rewind_id", rewind_id),
            task_id=payload.get("task_id", ""),
            status=payload.get("status", "FAILED"),
            effect_applied=payload.get("effect_applied", False),
            resulting_generation=payload.get("resulting_generation"),
            verification_status=payload.get("verification_status", "unknown"),
            reason=payload.get("reason", ""),
            result_digest=payload.get("result_digest", ""),
        )


__all__ = [
    "CheckpointBindingError",
    "CheckpointConflictError",
    "CheckpointRepository",
    "CheckpointRepositoryError",
]
