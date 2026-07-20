"""Database migration command."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from khaos.db import Database
from khaos.db.state_root import open_state_db_safely, resolve_state_db_path


async def run(path: str) -> None:
    """Apply migrations to the target database path."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    await db.close()


def main() -> None:
    """CLI entrypoint for migrations.

    M4 batch 3.1.16A-1: by default, migrations are applied to the
    trusted state root DB (``~/.khaos/state/<project-id>/state.db``),
    not the project directory.  Pass ``--db PATH`` to target a
    specific file, or set ``KHAOS_ALLOW_PROJECT_DB=1`` to allow
    project-directory paths (tests).
    """
    parser = argparse.ArgumentParser(prog="python -m khaos.db.migrate")
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    args = parser.parse_args()
    db_path = open_state_db_safely(
        resolve_state_db_path(Path.cwd(), args.db)
    )
    asyncio.run(run(str(db_path)))


if __name__ == "__main__":
    main()

