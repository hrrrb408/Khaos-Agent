"""CLI adapters for durable Coding supervision and checkpoint state."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from khaos.db import Database
from khaos.db.state_root import open_state_db_safely, resolve_state_db_path
from khaos.db.state_root import project_id as compute_project_id
from khaos.rpc.task_service import TaskService
from khaos.runtime import RequestContext


def _root(args: Any) -> Path:
    value = getattr(args, "project_root", None)
    return Path(value).resolve() if value is not None else Path.cwd().resolve()


def _print(value: object, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    elif isinstance(value, dict):
        for key, item in value.items():
            print(f"{key}: {item}")
    elif isinstance(value, list):
        for item in value:
            print(item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, sort_keys=True, default=str))
    else:
        print(value)


async def _open(args: Any) -> tuple[Database, TaskService, RequestContext]:
    root = _root(args)
    db_path = open_state_db_safely(resolve_state_db_path(root, getattr(args, "db", None)))
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    context = RequestContext.for_cli(project_id=compute_project_id(root))
    return db, TaskService(db), context


async def _task_command_async(args: Any) -> int:
    db, service, context = await _open(args)
    try:
        task_id = args.task_id
        task = await service.get(context, task_id)
        if "error" in task:
            _print(task, as_json=args.as_json)
            return 1
        command = args.task_command
        if command == "status":
            result = await service.supervision(context, task_id)
            _print(result, as_json=args.as_json)
            return 0 if "error" not in result else 1
        if command == "events":
            events: list[dict[str, object]] = []
            async for event in service.supervision_events(
                context, task_id, after_sequence=args.after, limit=args.limit
            ):
                events.append(event)
            _print(events, as_json=args.as_json)
            return 0
        if command in {"pause", "resume", "cancel"}:
            result = await getattr(service, command)(
                context,
                task_id,
                command_id=args.command_id,
                expected_revision=args.expected_revision,
            )
            _print(result, as_json=args.as_json)
            return 0 if result.get("ok") else 1
        raise ValueError(f"unknown task command: {command}")
    finally:
        await db.close()


def cmd_task(args: Any) -> int:
    """Inspect or control one owner-scoped Coding task."""
    try:
        return asyncio.run(_task_command_async(args))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"task command failed: {exc}", file=sys.stderr)
        return 2


async def _checkpoint_command_async(args: Any) -> int:
    db, service, context = await _open(args)
    try:
        command = args.checkpoint_command
        if command == "list":
            if not args.task_id:
                raise ValueError("checkpoint list requires TASK_ID")
            result = await service.checkpoint_list(context, args.task_id)
            _print(result, as_json=args.as_json)
            return 0
        if command == "show":
            result = await service.checkpoint(context, args.checkpoint_id)
            _print(result, as_json=args.as_json)
            return 0 if "error" not in result else 1
        if command == "create":
            result = await service.create_checkpoint(
                context,
                args.task_id,
                label=" ".join(args.label),
                kind=args.kind,
                expected_generation=args.expected_generation,
                idempotency_key=args.idempotency_key,
            )
            _print(result, as_json=args.as_json)
            return 0 if result.get("ok") else 1
        raise ValueError(f"unknown checkpoint command: {command}")
    finally:
        await db.close()


def cmd_checkpoint(args: Any) -> int:
    """Inspect or request a bounded checkpoint through TaskService."""
    try:
        return asyncio.run(_checkpoint_command_async(args))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"checkpoint command failed: {exc}", file=sys.stderr)
        return 2


async def _rewind_command_async(args: Any) -> int:
    db, service, context = await _open(args)
    try:
        if args.rewind_command == "plan":
            result = await service.rewind_plan(
                context,
                args.checkpoint_id,
                task_id=args.task_id,
                workspace_id=args.workspace_id,
                idempotency_key=args.idempotency_key,
            )
        else:
            result = await service.rewind(
                context,
                args.rewind_id,
                args.task_id,
                plan_digest=args.plan_digest,
            )
        _print(result, as_json=args.as_json)
        return 0 if result.get("ok") else 1
    finally:
        await db.close()


def cmd_rewind(args: Any) -> int:
    """Build or execute a digest-bound rewind via the active owner."""
    try:
        return asyncio.run(_rewind_command_async(args))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"rewind command failed: {exc}", file=sys.stderr)
        return 2


__all__ = ["cmd_checkpoint", "cmd_rewind", "cmd_task"]
