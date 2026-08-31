"""Owner-scoped SQL CAS persistence for Agent Cognitive State."""

from __future__ import annotations

import json
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from khaos.agent.control.state import (
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)


class ControlStateDatabase(Protocol):
    """Minimal database port required by the control-state repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction owner."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class CognitiveTransitionStatus(str, Enum):
    """Typed result of an owner-scoped cognitive-state operation."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"
    NOT_FOUND = "not_found"
    OWNER_MISMATCH = "owner_mismatch"
    STALE_VERSION = "stale_version"
    STALE_STATE = "stale_state"
    STALE_TASK_STATUS = "stale_task_status"
    STALE_WORKSPACE_BINDING = "stale_workspace_binding"
    ILLEGAL_TRANSITION = "illegal_transition"
    TERMINAL_TASK = "terminal_task"


TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


@dataclass(frozen=True, slots=True)
class CognitiveStateSnapshot:
    """Authoritative owner-scoped cognitive state read from SQL."""

    task_id: str
    principal_id: str
    project_id: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str

    @property
    def state(self) -> AgentCognitiveState:
        """Compatibility alias for callers that use a short field name."""
        return self.cognitive_state

    @property
    def version(self) -> int:
        """Compatibility alias for the control-state CAS version."""
        return self.control_state_version


@dataclass(frozen=True, slots=True)
class CognitiveWorkspaceBinding:
    """Optional durable workspace facts used as an additional CAS fence.

    These values identify the workspace snapshot observed by a caller.  They
    do not grant access to that workspace or change any execution authority.
    """

    workspace_id: str | None
    base_revision: str | None
    repository_id: str | None

    def __post_init__(self) -> None:
        for field_name in ("workspace_id", "base_revision", "repository_id"):
            value = getattr(self, field_name)
            if value is not None and (type(value) is not str or not value):
                raise ValueError(f"{field_name} must be None or a non-empty string")


@dataclass(frozen=True, slots=True)
class CognitiveTransitionResult:
    """Typed outcome returned by CAS and controller seams.

    ``current_state`` and ``control_state_version`` are an observation when
    available.  A stale result never mutates a caller's in-memory projection;
    the caller must explicitly refresh before making another decision.
    """

    status: CognitiveTransitionStatus
    task_id: str
    expected_state: AgentCognitiveState
    expected_version: int
    target_state: AgentCognitiveState
    current_state: AgentCognitiveState | None = None
    control_state_version: int | None = None
    task_status: str | None = None

    @property
    def state(self) -> AgentCognitiveState | None:
        """Return the observed/resulting state, if one was available."""
        return self.current_state

    @property
    def version(self) -> int | None:
        """Return the observed/resulting CAS version, if one was available."""
        return self.control_state_version

    @property
    def updated(self) -> bool:
        """Whether this result committed a real state transition."""
        return self.status is CognitiveTransitionStatus.UPDATED

    @classmethod
    def illegal_transition(
        cls,
        *,
        task_id: str,
        current_state: AgentCognitiveState,
        current_version: int,
        target_state: AgentCognitiveState,
    ) -> CognitiveTransitionResult:
        """Construct the typed result for pure-machine rejection."""
        return cls(
            status=CognitiveTransitionStatus.ILLEGAL_TRANSITION,
            task_id=task_id,
            expected_state=current_state,
            expected_version=current_version,
            target_state=target_state,
            current_state=current_state,
            control_state_version=current_version,
        )


class CognitiveStateIntegrityError(RuntimeError):
    """Raised when durable control-state columns cannot be decoded safely."""


class AgentControlStateRepository:
    """Persist cognitive state through an owner-bound SQL compare-and-set.

    This class owns transaction and row classification only.  It delegates
    target legality to the pure ``AgentCognitiveStateMachine`` as a defensive
    check; it does not define or duplicate the transition graph.
    """

    def __init__(self, database: ControlStateDatabase) -> None:
        self._database = database

    @property
    def database(self) -> ControlStateDatabase:
        """Return the composed database port used by this repository."""
        return self._database

    async def get_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> CognitiveStateSnapshot | None:
        """Read current control state within the supplied owner scope."""
        _validate_owner_inputs(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            row = await self._select_owned(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
        return _decode_snapshot(row)

    async def get_current(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> CognitiveStateSnapshot | None:
        """Alias for ``get_snapshot`` with an explicit current-state name."""
        return await self.get_snapshot(
            task_id,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def compare_and_transition(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        expected_state: AgentCognitiveState,
        expected_version: int,
        target_state: AgentCognitiveState,
        expected_task_status: str | None = None,
        expected_workspace_binding: CognitiveWorkspaceBinding | None = None,
    ) -> CognitiveTransitionResult:
        """Atomically CAS one non-terminal task's cognitive state.

        The SQL predicate binds task identity, both ownership dimensions,
        expected state/version, and non-terminal task status.  A self
        transition performs only an owner-scoped observation and returns
        ``UNCHANGED`` without incrementing the version.  When supplied,
        ``expected_task_status`` is an additional lifecycle fence; it does
        not make this repository a TaskStatus writer.
        """
        _validate_owner_inputs(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        _validate_state(expected_state, label="expected_state")
        _validate_state(target_state, label="target_state")
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a non-negative integer")
        if expected_task_status is not None and (
            type(expected_task_status) is not str or not expected_task_status
        ):
            raise ValueError("expected_task_status must be a non-empty string")
        if expected_workspace_binding is not None and type(
            expected_workspace_binding
        ) is not CognitiveWorkspaceBinding:
            raise TypeError(
                "expected_workspace_binding must be a CognitiveWorkspaceBinding"
            )
        if (
            AgentCognitiveStateMachine.validate_transition(
                expected_state, target_state
            )
            is CognitiveTransitionValidation.ILLEGAL
        ):
            return CognitiveTransitionResult.illegal_transition(
                task_id=task_id,
                current_state=expected_state,
                current_version=expected_version,
                target_state=target_state,
            )

        async with self._database.transaction() as conn:
            if expected_state is target_state:
                row = await self._select_owned(
                    conn,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                snapshot = _decode_snapshot(row)
                if snapshot is None:
                    return _not_found_result(
                        task_id=task_id,
                        expected_state=expected_state,
                        expected_version=expected_version,
                        target_state=target_state,
                    )
                mismatch = _classify_cas_mismatch(
                    snapshot,
                    expected_state=expected_state,
                    expected_version=expected_version,
                    target_state=target_state,
                    expected_task_status=expected_task_status,
                )
                if mismatch is not None:
                    return mismatch
                if _workspace_binding_mismatch(row, expected_workspace_binding):
                    return _result_from_snapshot(
                        CognitiveTransitionStatus.STALE_WORKSPACE_BINDING,
                        snapshot,
                        expected_state=expected_state,
                        expected_version=expected_version,
                        target_state=target_state,
                    )
                return _result_from_snapshot(
                    CognitiveTransitionStatus.UNCHANGED,
                    snapshot,
                    expected_state=expected_state,
                    expected_version=expected_version,
                    target_state=target_state,
                )

            if expected_workspace_binding is not None:
                row = await self._select_owned(
                    conn,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                snapshot = _decode_snapshot(row)
                if snapshot is None:
                    return _not_found_result(
                        task_id=task_id,
                        expected_state=expected_state,
                        expected_version=expected_version,
                        target_state=target_state,
                    )
                mismatch = _classify_cas_mismatch(
                    snapshot,
                    expected_state=expected_state,
                    expected_version=expected_version,
                    target_state=target_state,
                    expected_task_status=expected_task_status,
                )
                if mismatch is not None:
                    return mismatch
                if _workspace_binding_mismatch(row, expected_workspace_binding):
                    return _result_from_snapshot(
                        CognitiveTransitionStatus.STALE_WORKSPACE_BINDING,
                        snapshot,
                        expected_state=expected_state,
                        expected_version=expected_version,
                        target_state=target_state,
                    )

            cursor = await conn.execute(
                """
                UPDATE coding_tasks
                SET cognitive_state = ?,
                    control_state_version = control_state_version + 1
                WHERE id = ?
                  AND principal_id = ?
                  AND project_id = ?
                  AND cognitive_state = ?
                  AND control_state_version = ?
                  AND (? IS NULL OR status = ?)
                  AND status NOT IN ('completed', 'failed', 'cancelled')
                """,
                (
                    target_state.value,
                    task_id,
                    principal_id,
                    project_id,
                    expected_state.value,
                    expected_version,
                    expected_task_status,
                    expected_task_status,
                ),
            )
            if int(cursor.rowcount or 0) == 1:
                row = await self._select_owned(
                    conn,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                snapshot = _decode_snapshot(row)
                if snapshot is None:
                    raise CognitiveStateIntegrityError(
                        "cognitive state row disappeared after a successful CAS"
                    )
                return _result_from_snapshot(
                    CognitiveTransitionStatus.UPDATED,
                    snapshot,
                    expected_state=expected_state,
                    expected_version=expected_version,
                    target_state=target_state,
                )

            # The owner-scoped probe distinguishes stale/terminal rows while
            # keeping foreign task IDs indistinguishable from NOT_FOUND.
            row = await self._select_owned(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            snapshot = _decode_snapshot(row)
            if snapshot is None:
                return _not_found_result(
                    task_id=task_id,
                    expected_state=expected_state,
                    expected_version=expected_version,
                    target_state=target_state,
                )
            mismatch = _classify_cas_mismatch(
                snapshot,
                expected_state=expected_state,
                expected_version=expected_version,
                target_state=target_state,
                expected_task_status=expected_task_status,
            )
            if mismatch is None:
                raise CognitiveStateIntegrityError(
                    "cognitive state CAS affected zero rows despite matching predicate"
                )
            return mismatch

    async def _select_owned(
        self,
        conn: Any,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
    ) -> Any:
        cursor = await conn.execute(
            """
            SELECT id, principal_id, project_id, cognitive_state,
                   control_state_version, status, state_json
            FROM coding_tasks
            WHERE id = ? AND principal_id = ? AND project_id = ?
            """,
            (task_id, principal_id, project_id),
        )
        return await cursor.fetchone()


def _workspace_binding_mismatch(
    row: Any, expected: CognitiveWorkspaceBinding | None
) -> bool:
    if expected is None:
        return False
    if row is None:
        return True
    try:
        raw_state = row["state_json"]
        if type(raw_state) is not str:
            raise CognitiveStateIntegrityError("coding task state_json is malformed")
        state = json.loads(raw_state)
        if type(state) is not dict:
            raise CognitiveStateIntegrityError("coding task state_json root is malformed")
        metadata = state.get("metadata", {})
        if type(metadata) is not dict:
            raise CognitiveStateIntegrityError(
                "coding task metadata projection is malformed"
            )
        actual = {
            "workspace_id": metadata.get("workspace_id"),
            "base_revision": metadata.get("base_sha"),
            "repository_id": metadata.get("repository_id"),
        }
        for field_name, value in actual.items():
            if value is not None and (type(value) is not str or not value):
                raise CognitiveStateIntegrityError(
                    f"coding task {field_name} projection is malformed"
                )
    except CognitiveStateIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise CognitiveStateIntegrityError(
            "coding task workspace projection is malformed"
        ) from exc
    return any(
        actual[field_name] != getattr(expected, field_name)
        for field_name in ("workspace_id", "base_revision", "repository_id")
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


def _validate_state(value: AgentCognitiveState, *, label: str) -> None:
    if type(value) is not AgentCognitiveState:
        raise TypeError(f"{label} must be an AgentCognitiveState")


def _decode_snapshot(row: Any) -> CognitiveStateSnapshot | None:
    if row is None:
        return None
    try:
        task_id = row["id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        raw_state = row["cognitive_state"]
        version = row["control_state_version"]
        status = row["status"]
    except (KeyError, IndexError, TypeError) as exc:
        raise CognitiveStateIntegrityError(
            "coding task cognitive state row is malformed"
        ) from exc
    if any(type(value) is not str or not value for value in (task_id, principal_id)):
        raise CognitiveStateIntegrityError("coding task owner or id is malformed")
    if type(project_id) is not str or type(status) is not str or not status:
        raise CognitiveStateIntegrityError("coding task project or status is malformed")
    try:
        state = AgentCognitiveState.parse(raw_state)
    except ValueError as exc:
        raise CognitiveStateIntegrityError(
            f"coding task {task_id!r} has an unknown cognitive state"
        ) from exc
    if type(version) is not int or version < 0:
        raise CognitiveStateIntegrityError(
            f"coding task {task_id!r} has an invalid control state version"
        )
    return CognitiveStateSnapshot(
        task_id=task_id,
        principal_id=principal_id,
        project_id=project_id,
        cognitive_state=state,
        control_state_version=version,
        task_status=status,
    )


def _result_from_snapshot(
    status: CognitiveTransitionStatus,
    snapshot: CognitiveStateSnapshot,
    *,
    expected_state: AgentCognitiveState,
    expected_version: int,
    target_state: AgentCognitiveState,
) -> CognitiveTransitionResult:
    return CognitiveTransitionResult(
        status=status,
        task_id=snapshot.task_id,
        expected_state=expected_state,
        expected_version=expected_version,
        target_state=target_state,
        current_state=snapshot.cognitive_state,
        control_state_version=snapshot.control_state_version,
        task_status=snapshot.task_status,
    )


def _not_found_result(
    *,
    task_id: str,
    expected_state: AgentCognitiveState,
    expected_version: int,
    target_state: AgentCognitiveState,
) -> CognitiveTransitionResult:
    return CognitiveTransitionResult(
        status=CognitiveTransitionStatus.NOT_FOUND,
        task_id=task_id,
        expected_state=expected_state,
        expected_version=expected_version,
        target_state=target_state,
    )


def _classify_cas_mismatch(
    snapshot: CognitiveStateSnapshot,
    *,
    expected_state: AgentCognitiveState,
    expected_version: int,
    target_state: AgentCognitiveState,
    expected_task_status: str | None = None,
) -> CognitiveTransitionResult | None:
    if snapshot.task_status in TERMINAL_TASK_STATUSES:
        return _result_from_snapshot(
            CognitiveTransitionStatus.TERMINAL_TASK,
            snapshot,
            expected_state=expected_state,
            expected_version=expected_version,
            target_state=target_state,
        )
    if snapshot.control_state_version != expected_version:
        return _result_from_snapshot(
            CognitiveTransitionStatus.STALE_VERSION,
            snapshot,
            expected_state=expected_state,
            expected_version=expected_version,
            target_state=target_state,
        )
    if snapshot.cognitive_state is not expected_state:
        return _result_from_snapshot(
            CognitiveTransitionStatus.STALE_STATE,
            snapshot,
            expected_state=expected_state,
            expected_version=expected_version,
            target_state=target_state,
        )
    if expected_task_status is not None and snapshot.task_status != expected_task_status:
        return _result_from_snapshot(
            CognitiveTransitionStatus.STALE_TASK_STATUS,
            snapshot,
            expected_state=expected_state,
            expected_version=expected_version,
            target_state=target_state,
        )
    return None


__all__ = [
    "TERMINAL_TASK_STATUSES",
    "AgentControlStateRepository",
    "CognitiveStateIntegrityError",
    "CognitiveStateSnapshot",
    "CognitiveTransitionResult",
    "CognitiveTransitionStatus",
    "CognitiveWorkspaceBinding",
    "ControlStateDatabase",
]
