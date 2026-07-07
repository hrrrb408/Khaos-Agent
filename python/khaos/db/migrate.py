"""Database migration command."""

from __future__ import annotations

import argparse
import asyncio

from khaos.db import Database


async def run(path: str) -> None:
    """Apply migrations to the target database path."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    await db.close()


def main() -> None:
    """CLI entrypoint for migrations."""
    parser = argparse.ArgumentParser(prog="python -m khaos.db.migrate")
    parser.add_argument("--db", default="khaos.db")
    args = parser.parse_args()
    asyncio.run(run(args.db))


if __name__ == "__main__":
    main()

