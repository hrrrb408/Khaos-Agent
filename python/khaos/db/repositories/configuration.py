"""Persistence owner for runtime configuration and principal modes.

The :class:`Database` facade remains the public compatibility surface, but
this repository owns the SQL shape and value conversion for configuration
state. It consumes only the database transaction/read ports; it does not
reach into private connection attributes or manage lifecycle.
"""

from __future__ import annotations

import json
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol


class ConfigurationDatabase(Protocol):
    """Minimal connection/transaction port required by this repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class ConfigurationRepository:
    """Own SQL for user configuration and principal-scoped modes."""

    def __init__(self, database: ConfigurationDatabase) -> None:
        self._database = database

    async def set_config(self, key: str, value: Any) -> None:
        """Persist one JSON configuration value atomically."""
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO user_config (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = datetime('now')
                """,
                (key, json.dumps(value)),
            )

    async def get_config(self, key: str, default: Any = None) -> Any:
        """Read and decode one JSON configuration value."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT value FROM user_config WHERE key = ?", (key,)
            )
            row = await cursor.fetchone()
        if row is None:
            return default
        return json.loads(str(row["value"]))

    async def get_principal_mode(
        self,
        principal_id: str,
        session_id: str = "",
        default: str = "office",
        *,
        project_id: str = "",
    ) -> str:
        """Resolve a session override, then a principal default."""
        async with self._database.read_connection() as conn:
            if session_id:
                cursor = await conn.execute(
                    "SELECT mode FROM principal_modes "
                    "WHERE project_id = ? AND principal_id = ? "
                    "AND session_id = ?",
                    (project_id, principal_id, session_id),
                )
                row = await cursor.fetchone()
                if row is not None:
                    return str(row["mode"])

            cursor = await conn.execute(
                "SELECT mode FROM principal_modes "
                "WHERE project_id = ? AND principal_id = ? AND session_id = ''",
                (project_id, principal_id),
            )
            row = await cursor.fetchone()
        return str(row["mode"]) if row is not None else default

    async def set_principal_mode(
        self,
        principal_id: str,
        mode: str,
        session_id: str = "",
        *,
        project_id: str = "",
    ) -> None:
        """Persist a principal default or session-specific mode override."""
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO principal_modes
                    (principal_id, project_id, session_id, mode)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(project_id, principal_id, session_id) DO UPDATE SET
                    mode = excluded.mode,
                    updated_at = datetime('now')
                """,
                (principal_id, project_id, session_id, mode),
            )


__all__ = ["ConfigurationDatabase", "ConfigurationRepository"]
