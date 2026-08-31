"""Owner-scoped durable persistence for immutable GoalSpec declarations."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.agent.control.goal import GoalSpec
from khaos.time_utils import utc_now_naive


class GoalSpecDatabase(Protocol):
    """Minimal database port required by ``GoalSpecRepository``."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class GoalSpecRepositoryError(RuntimeError):
    """Base error for durable GoalSpec persistence failures."""


class GoalSpecConflictError(GoalSpecRepositoryError):
    """A task or GoalSpec identity is already bound to another declaration."""


class GoalSpecIntegrityError(GoalSpecRepositoryError):
    """A durable GoalSpec row failed closed integrity validation."""


class GoalSpecRepository:
    """Persist and retrieve GoalSpecs without providing mutation APIs.

    All reads require the caller's principal and project.  Foreign rows are
    intentionally indistinguishable from missing rows at this repository
    boundary, preventing an ID probe from becoming an ownership oracle.
    """

    def __init__(self, database: GoalSpecDatabase) -> None:
        self._database = database

    @property
    def database(self) -> GoalSpecDatabase:
        """Return the composed database port for explicit transaction sharing."""
        return self._database

    async def insert(
        self,
        spec: GoalSpec,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
        created_at: str | None = None,
    ) -> None:
        """Insert one immutable, owner-bound GoalSpec.

        Duplicate task or identity collisions are explicit conflicts.  There
        is deliberately no update, delete, or ``INSERT OR REPLACE`` path.
        """
        if not isinstance(spec, GoalSpec):
            raise TypeError("spec must be a GoalSpec")
        _validate_owner_inputs(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        canonical_json = spec.canonical_json()
        timestamp = created_at or utc_now_naive().isoformat()
        try:
            async with self._database.transaction() as conn:
                await conn.execute(
                    """
                    INSERT INTO agent_goal_specs (
                        goal_spec_id, task_id, principal_id, project_id,
                        schema_version, semantic_digest, canonical_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        spec.goal_spec_id,
                        task_id,
                        principal_id,
                        project_id,
                        spec.schema_version,
                        spec.semantic_digest,
                        canonical_json,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise GoalSpecConflictError(
                "GoalSpec identity or task_id is already bound; immutable insert refused"
            ) from exc

    async def get_by_id(
        self,
        goal_spec_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> GoalSpec | None:
        """Read one GoalSpec only inside the supplied owner scope."""
        _validate_owner_inputs(
            task_id="lookup",
            principal_id=principal_id,
            project_id=project_id,
        )
        if type(goal_spec_id) is not str or not goal_spec_id:
            raise ValueError("goal_spec_id must be a non-empty string")
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT goal_spec_id, task_id, principal_id, project_id,
                       schema_version, semantic_digest, canonical_json, created_at
                FROM agent_goal_specs
                WHERE goal_spec_id = ? AND principal_id = ? AND project_id = ?
                """,
                (goal_spec_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_goal_spec_id=goal_spec_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def get_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> GoalSpec | None:
        """Read the canonical GoalSpec for a task in its owner scope."""
        _validate_owner_inputs(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT goal_spec_id, task_id, principal_id, project_id,
                       schema_version, semantic_digest, canonical_json, created_at
                FROM agent_goal_specs
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                """,
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_task_id=task_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )


def _validate_owner_inputs(
    *, task_id: str, principal_id: str, project_id: str
) -> None:
    if type(task_id) is not str or not task_id:
        raise ValueError("task_id must be a non-empty string")
    if type(principal_id) is not str or not principal_id:
        raise ValueError("principal_id must be a non-empty string")
    if type(project_id) is not str:
        raise ValueError("project_id must be a string")


def _decode_row(
    row: Any,
    *,
    expected_goal_spec_id: str | None = None,
    expected_task_id: str | None = None,
    expected_principal_id: str | None = None,
    expected_project_id: str | None = None,
) -> GoalSpec | None:
    if row is None:
        return None
    try:
        row_goal_spec_id = row["goal_spec_id"]
        row_task_id = row["task_id"]
        row_principal_id = row["principal_id"]
        row_project_id = row["project_id"]
        row_schema_version = row["schema_version"]
        row_digest = row["semantic_digest"]
        canonical_json = row["canonical_json"]
        if any(
            type(value) is not str or not value
            for value in (row_goal_spec_id, row_task_id, row_principal_id)
        ) or type(row_project_id) is not str:
            raise GoalSpecIntegrityError("stored GoalSpec owner/identity is invalid")
        if expected_goal_spec_id is not None and row_goal_spec_id != expected_goal_spec_id:
            raise GoalSpecIntegrityError("GoalSpec identity mismatch")
        if expected_task_id is not None and row_task_id != expected_task_id:
            raise GoalSpecIntegrityError("GoalSpec task identity mismatch")
        if (
            expected_principal_id is not None
            and row_principal_id != expected_principal_id
        ):
            raise GoalSpecIntegrityError("GoalSpec principal identity mismatch")
        if (
            expected_project_id is not None
            and row_project_id != expected_project_id
        ):
            raise GoalSpecIntegrityError("GoalSpec project identity mismatch")
        if type(row_schema_version) is not int:
            raise GoalSpecIntegrityError("stored GoalSpec schema_version is invalid")
        if type(row_digest) is not str or not row_digest:
            raise GoalSpecIntegrityError("stored GoalSpec digest is invalid")
        if type(canonical_json) is not str:
            raise GoalSpecIntegrityError("stored GoalSpec JSON is invalid")
        spec = GoalSpec.from_canonical_json(
            canonical_json,
            expected_digest=row_digest,
        )
        if spec.schema_version != row_schema_version:
            raise GoalSpecIntegrityError(
                "stored GoalSpec schema_version disagrees with canonical JSON"
            )
        if spec.goal_spec_id != row_goal_spec_id:
            raise GoalSpecIntegrityError(
                "stored GoalSpec goal_spec_id disagrees with canonical JSON"
            )
        return spec
    except GoalSpecIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise GoalSpecIntegrityError("stored GoalSpec row failed integrity validation") from exc


__all__ = [
    "GoalSpecConflictError",
    "GoalSpecDatabase",
    "GoalSpecIntegrityError",
    "GoalSpecRepository",
    "GoalSpecRepositoryError",
]
