"""Durable owner-scoped projections for M8.7 extension facts."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.extensions.contracts import (
    ExtensionRecord,
    InvocationBinding,
    InvocationStatus,
)
from khaos.extensions.hooks import HookDescriptor
from khaos.extensions.skills import SkillActivation
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.time_utils import utc_now_naive

MAX_EXTENSION_JSON_BYTES = 64 * 1024
MAX_RUNTIME_JSON_BYTES = 16 * 1024
MAX_INVOCATION_ROWS = 4096


class ExtensionRepositoryDatabase(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[Any]: ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


class ExtensionRepositoryError(RuntimeError):
    """Raised when a durable extension projection cannot be safely written."""


def _owner(principal_id: str, project_id: str) -> None:
    if type(principal_id) is not str or not principal_id:
        raise ExtensionRepositoryError("principal_id is required")
    if type(project_id) is not str or not project_id:
        raise ExtensionRepositoryError("project_id is required")


def _json(value: object, maximum: int, label: str) -> str:
    try:
        encoded = canonical_json_bytes(value)
    except Exception as exc:
        raise ExtensionRepositoryError(f"{label} is not JSON-safe") from exc
    if len(encoded) > maximum:
        raise ExtensionRepositoryError(f"{label} exceeds its bound")
    return encoded.decode("utf-8")


class ExtensionRepository:
    """Persist immutable metadata and mutable lifecycle projections."""

    def __init__(self, database: ExtensionRepositoryDatabase) -> None:
        self._database = database

    async def save_record(
        self,
        record: ExtensionRecord,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        _owner(principal_id, project_id)
        descriptor = record.descriptor
        descriptor_json = _json(descriptor.to_payload(), MAX_EXTENSION_JSON_BYTES, "descriptor")
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO extension_descriptors (
                    extension_id, principal_id, project_id, extension_json,
                    descriptor_digest, provenance, lifecycle_state, state_reason,
                    state_generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(extension_id, principal_id, project_id) DO UPDATE SET
                    lifecycle_state = excluded.lifecycle_state,
                    state_reason = excluded.state_reason,
                    state_generation = excluded.state_generation,
                    updated_at = excluded.updated_at
                WHERE extension_descriptors.extension_json = excluded.extension_json
                  AND extension_descriptors.descriptor_digest = excluded.descriptor_digest
                """,
                (
                    descriptor.extension_id,
                    principal_id,
                    project_id,
                    descriptor_json,
                    descriptor.descriptor_digest,
                    str(descriptor.provenance),
                    str(record.state),
                    record.reason,
                    record.state_generation,
                    now,
                    now,
                ),
            )
            cursor = await conn.execute(
                "SELECT descriptor_digest FROM extension_descriptors WHERE extension_id = ? AND principal_id = ? AND project_id = ?",
                (descriptor.extension_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
            if row is None or str(row[0]) != descriptor.descriptor_digest:
                raise ExtensionRepositoryError("extension descriptor identity conflicts with durable state")
            for capability in record.capabilities:
                capability_json = _json(capability.to_payload(), MAX_EXTENSION_JSON_BYTES, "capability")
                try:
                    await conn.execute(
                        """
                        INSERT INTO extension_capabilities (
                            capability_id, extension_id, principal_id, project_id,
                            capability_json, capability_digest, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            capability.capability_id,
                            capability.extension_id,
                            principal_id,
                            project_id,
                            capability_json,
                            capability.capability_digest,
                            now,
                        ),
                    )
                except Exception as exc:
                    cursor = await conn.execute(
                        "SELECT capability_digest FROM extension_capabilities WHERE capability_id = ? AND principal_id = ? AND project_id = ?",
                        (capability.capability_id, principal_id, project_id),
                    )
                    existing = await cursor.fetchone()
                    if existing is None or str(existing[0]) != capability.capability_digest:
                        raise ExtensionRepositoryError("extension capability identity conflicts with durable state") from exc

    async def save_runtime(
        self,
        *,
        instance_id: str,
        extension_id: str,
        task_id: str,
        principal_id: str,
        project_id: str,
        lifecycle_state: str,
        runtime: Mapping[str, object] | None = None,
        session_id: str = "",
        process_identity: str = "",
        started_at: str | None = None,
        stopped_at: str | None = None,
        quarantine_reason: str = "",
    ) -> None:
        _owner(principal_id, project_id)
        runtime_json = _json(dict(runtime or {}), MAX_RUNTIME_JSON_BYTES, "runtime")
        if any(type(value) is not str or not value for value in (instance_id, extension_id, task_id, lifecycle_state)):
            raise ExtensionRepositoryError("runtime identity is invalid")
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            existing_cursor = await conn.execute(
                "SELECT extension_id, task_id, session_id, principal_id, project_id, process_identity FROM extension_runtime_instances WHERE instance_id = ?",
                (instance_id,),
            )
            existing = await existing_cursor.fetchone()
            if existing is not None and (
                str(existing[3]) != principal_id
                or str(existing[4]) != project_id
                or str(existing[0]) != extension_id
                or str(existing[1]) != task_id
                or str(existing[2]) != session_id
                or str(existing[5]) != process_identity
            ):
                raise ExtensionRepositoryError("runtime instance identity conflicts with durable state")
            await conn.execute(
                """
                INSERT INTO extension_runtime_instances (
                    instance_id, extension_id, task_id, session_id, principal_id,
                    project_id, lifecycle_state, process_identity, runtime_json,
                    started_at, stopped_at, quarantine_reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    lifecycle_state = excluded.lifecycle_state,
                    process_identity = excluded.process_identity,
                    runtime_json = excluded.runtime_json,
                    stopped_at = excluded.stopped_at,
                    quarantine_reason = excluded.quarantine_reason,
                    updated_at = excluded.updated_at
                WHERE extension_runtime_instances.principal_id = excluded.principal_id
                  AND extension_runtime_instances.project_id = excluded.project_id
                """,
                (
                    instance_id,
                    extension_id,
                    task_id,
                    session_id,
                    principal_id,
                    project_id,
                    lifecycle_state,
                    process_identity,
                    runtime_json,
                    started_at,
                    stopped_at,
                    quarantine_reason,
                    now,
                ),
            )

    async def append_invocation(
        self,
        binding: InvocationBinding,
        *,
        status: InvocationStatus | str,
        session_id: str = "",
        response_bytes: int = 0,
        response_digest: str = "",
    ) -> str:
        if type(binding) is not InvocationBinding:
            raise TypeError("binding must be an InvocationBinding")
        status_value = status.value if isinstance(status, InvocationStatus) else InvocationStatus(str(status)).value
        if type(response_bytes) is not int or response_bytes < 0 or response_bytes > 4 * 1024 * 1024:
            raise ExtensionRepositoryError("response_bytes is invalid")
        if type(response_digest) is not str or len(response_digest) not in {0, 64} or any(
            character not in "0123456789abcdef" for character in response_digest
        ):
            raise ExtensionRepositoryError("response_digest must be empty or a SHA-256 digest")
        now = utc_now_naive().isoformat()
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO extension_invocations (
                    invocation_id, extension_id, capability_id, task_id, session_id,
                    principal_id, project_id, arguments_digest, effect_digest,
                    status, response_bytes, response_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binding.invocation_id,
                    binding.effective.extension_id,
                    binding.effective.capability_id,
                    binding.effective.task_id,
                    session_id,
                    binding.effective.principal_id,
                    binding.effective.project_id,
                    binding.arguments_digest,
                    binding.binding_digest,
                    status_value,
                    response_bytes,
                    response_digest,
                    now,
                ),
            )
        return binding.invocation_id

    async def append_hook_registration(
        self,
        descriptor: HookDescriptor,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        _owner(principal_id, project_id)
        registration_json = _json(descriptor.to_payload(), 32 * 1024, "hook registration")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO hook_registrations (
                    hook_id, extension_id, principal_id, project_id,
                    registration_json, registration_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    descriptor.hook_id,
                    descriptor.extension_id,
                    principal_id,
                    project_id,
                    registration_json,
                    descriptor.descriptor_digest,
                    utc_now_naive().isoformat(),
                ),
            )

    async def append_skill_activation(self, activation: SkillActivation) -> str:
        if type(activation) is not SkillActivation:
            raise TypeError("activation must be a SkillActivation")
        activation_id = f"skill-act:{uuid.uuid4().hex}"
        missing_json = _json(list(activation.missing_required_tools), 8192, "missing required tools")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO skill_activations (
                    activation_id, skill_id, version, package_digest,
                    selection_reason, task_id, principal_id, project_id,
                    status, missing_tools_json, stale, activation_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    activation_id,
                    activation.skill_id,
                    activation.version,
                    activation.package_digest,
                    activation.selection_reason,
                    activation.task_id,
                    activation.principal_id,
                    activation.project_id,
                    str(activation.status),
                    missing_json,
                    int(activation.stale),
                    activation.activation_digest,
                    utc_now_naive().isoformat(),
                ),
            )
        return activation_id

    async def list_records(self, *, principal_id: str, project_id: str, limit: int = 256) -> tuple[dict[str, object], ...]:
        _owner(principal_id, project_id)
        if type(limit) is not int or limit <= 0 or limit > MAX_INVOCATION_ROWS:
            raise ExtensionRepositoryError("limit is invalid")
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT extension_id, extension_json, descriptor_digest, provenance, lifecycle_state, state_reason, state_generation, created_at, updated_at FROM extension_descriptors WHERE principal_id = ? AND project_id = ? ORDER BY extension_id LIMIT ?",
                (principal_id, project_id, limit),
            )
            rows = await cursor.fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            try:
                payload = json.loads(str(row[1]))
            except json.JSONDecodeError as exc:
                raise ExtensionRepositoryError("durable extension descriptor is malformed") from exc
            result.append({
                "extension_id": str(row[0]),
                "descriptor": payload,
                "descriptor_digest": str(row[2]),
                "provenance": str(row[3]),
                "lifecycle_state": str(row[4]),
                "state_reason": str(row[5]),
                "state_generation": int(row[6]),
                "created_at": str(row[7]),
                "updated_at": str(row[8]),
            })
        return tuple(result)


__all__ = [
    "ExtensionRepository",
    "ExtensionRepositoryDatabase",
    "ExtensionRepositoryError",
]
