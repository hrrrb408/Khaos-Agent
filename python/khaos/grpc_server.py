"""Python AgentService and MemoryService.

The service classes mirror the LLD gRPC surface. The JSON-line Unix socket
server keeps the control plane local without generated protobuf dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import AsyncIterator

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.approval import ApprovalBroker
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.audit import AuditLogger
from khaos.coding.task_manager import TaskManager
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.channels import ChannelRegistry, ChannelType, PlatformMessage, WebhookHandler
from khaos.db import Database
from khaos.memory import (
    Memory,
    MemoryBudget,
    MemoryConfidence,
    MemoryManager,
    MemoryScope,
    MemoryStore,
)
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.rust_bridge import get_token_engine
from khaos.routing.router import create_default_router
from khaos.routing import ModelRouter
from khaos.scheduler import CronEngine
from khaos.security.middleware import SecurityMiddleware
from khaos.security.policy import load_policy
from khaos.skills import SkillGenerator, SkillManager
from khaos.subagents import SubAgentConfig, SubAgentRunner, SubAgentService, SubAgentSpawner
from khaos.tools import create_runtime_registry
from khaos.tools.channel_tools import set_channel_registry
from khaos.tools.cron_tools import set_cron_engine
from khaos.tools.scheduler import ToolScheduler


@dataclass
class ChatRequest:
    session_id: str
    message: str
    mode: str = ""
    principal_id: str = ""


@dataclass
class ConfirmRequest:
    session_id: str
    tool_call_id: str
    approved: bool
    remember: bool = False
    principal_id: str = ""
    binding_digest: str = ""


class AgentService:
    """Agent RPC service backed by AgentLoop."""

    def __init__(self, db: Database, project_root: Path | None = None, config_path: Path | None = None, router=None):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self.config_path = config_path or self.project_root / "config.yaml"
        self._router = router
        self.pending_confirmations: dict[str, dict] = {}
        self.approval_broker = ApprovalBroker()
        # Shared coding-task tracker so the TUI / TaskService can observe
        # long-running coding turns alongside the AgentLoop.
        self.task_manager = TaskManager(db=db)
        self.cron_engine = CronEngine(db=db, executor=self._execute_scheduled_prompt)
        set_cron_engine(self.cron_engine)
        self.channel_registry = ChannelRegistry()
        set_channel_registry(self.channel_registry)
        # Security policy loaded once (not per chat call) and cached; rebuild
        # the middleware stack from it for every runtime.
        self._policy = load_policy(project_root / "khaos_policy.yaml")

    async def start(self) -> None:
        """Start process-scoped background services."""
        await self.task_manager.load()
        await self.cron_engine.start()

    async def shutdown(self) -> None:
        """Stop process-scoped background services."""
        await self.cron_engine.stop()

    async def _execute_scheduled_prompt(self, task_id: str, prompt: str) -> str:
        """Run a scheduled prompt through the normal office-mode agent path."""
        contents: list[str] = []
        async for event in self.chat(ChatRequest(f"cron:{task_id}", prompt, "office")):
            if event.get("event") == "message":
                content = event.get("data", {}).get("content")
                if content:
                    contents.append(str(content))
        return "\n".join(contents)

    async def chat(self, request: ChatRequest) -> AsyncIterator[dict]:
        """Stream chat events."""
        session_id = request.session_id or str(uuid.uuid4())
        mode_manager, loop = await self._build_runtime(
            session_id,
            request.mode,
            request.principal_id or f"local-uid:{os.getuid()}",
        )
        del mode_manager
        async for message in loop.run(request.message, session_id):
            yield _message_to_event(message)

    async def switch_mode(self, session_id: str, target_mode: str) -> dict:
        mode_manager = ModeManager(self.db, project_root=self.project_root)
        await mode_manager.load()
        mode = ModeManager.parse(target_mode)
        await mode_manager.switch(mode)
        if session_id:
            await self.db.create_session(session_id, mode.value)
        return {"current_mode": mode.value}

    async def confirm_permission(self, request: ConfirmRequest) -> dict:
        if not request.principal_id or not request.binding_digest:
            return {"ok": False, "error": "approval principal/binding required"}
        return {
            "ok": await self.approval_broker.resolve(
                request.tool_call_id,
                request.approved,
                request.remember,
                principal_id=request.principal_id,
                session_id=request.session_id,
                binding_digest=request.binding_digest,
            )
        }

    async def handle_webhook(
        self,
        platform: str,
        channel_id: str,
        headers: dict[str, str],
        body: str,
    ) -> dict[str, str]:
        """Validate and process one inbound platform webhook."""
        channel = self.channel_registry.get(channel_id)
        if channel is None or not channel.is_enabled:
            return {"status": "channel_not_found_or_disabled"}
        try:
            channel_type = ChannelType.WEBHOOK_IN if platform == "generic" else ChannelType(platform)
        except ValueError:
            return {"status": "unsupported_platform"}
        if channel.channel_type != channel_type:
            return {"status": "channel_type_mismatch"}
        handler = WebhookHandler(
            channel_type,
            secret=channel.config.secret,
            on_message=lambda message: self._on_webhook_message(channel_id, message),
        )
        return await handler.handle(headers, body.encode("utf-8"))

    async def _on_webhook_message(self, channel_id: str, message: PlatformMessage) -> None:
        session_id = f"{message.channel.value}:{message.target or message.sender.id}"
        async for _event in self.chat(ChatRequest(session_id, message.to_agent_input())):
            pass
        self.channel_registry.record_success(channel_id, received=True)

    def list_channels(self) -> dict[str, object]:
        return {"channels": self.channel_registry.get_health_report()}

    def set_channel_enabled(self, channel_id: str, enabled: bool) -> dict[str, object]:
        changed = self.channel_registry.enable(channel_id) if enabled else self.channel_registry.disable(channel_id)
        return {"ok": changed, "channel_id": channel_id}

    async def _build_runtime(
        self, session_id: str, mode: str, principal_id: str = ""
    ) -> tuple[ModeManager, AgentLoop]:
        await self.db.create_session(session_id, mode or "office")
        from khaos.runtime import RuntimeConfig, build_runtime

        result = await build_runtime(RuntimeConfig(
            project_root=self.project_root, config_path=self.config_path,
            mode_override=mode or None, confirm_callback=self._wait_for_confirmation,
            db=self.db, audit_logger=AuditLogger(self.db) if self._policy.audit_enabled else None,
            task_manager=self.task_manager,
            approval_broker=self.approval_broker,
            router=self._router,
            principal_id=principal_id or f"local-uid:{os.getuid()}",
        ))
        return result.mode_manager, result.loop

    async def _wait_for_confirmation(self, request: dict) -> dict:
        return await self.approval_broker.wait(
            request["id"],
            timeout=120.0,
            binding_digest=request["binding_digest"],
        )

    def _build_security_middleware(self) -> SecurityMiddleware:
        """Build the full security stack from the policy file.

        Wiring chain (see 批次 5 of the Codex-alignment doc):
        policy → Sandbox(mode) + NetworkGuard(network_*) + policy-extended
        guards + audit_logger → SecurityMiddleware → ToolScheduler.pre_check.

        Components are optional and imported lazily so the server starts even
        before all batches are present; a missing class simply means that
        layer is not enforced yet.
        """
        policy = self._policy
        sandbox = None
        network_guard = None
        # Sandbox: capability constraint layer.
        try:
            from khaos.security.sandbox import Sandbox

            sandbox = Sandbox.from_policy_mode(policy.mode, self.project_root)
        except ImportError:
            pass
        # NetworkGuard: network access control.
        try:
            from khaos.security.network_guard import NetworkGuard

            network_guard = NetworkGuard(
                network_enabled=policy.network_enabled,
                allowed_domains=policy.network_allowed_domains,
                blocked_domains=policy.network_blocked_domains,
            )
        except ImportError:
            pass
        audit_logger = AuditLogger(self.db) if policy.audit_enabled else None
        return SecurityMiddleware(
            policy=policy,
            sandbox=sandbox,
            network_guard=network_guard,
            audit_logger=audit_logger,
        )


class MemoryService:
    """Memory RPC service backed by MemoryStore."""

    def __init__(self, store: MemoryStore):
        self.store = store

    async def get_memory(self, scope: str, key: str) -> dict:
        memory = await self.store.get(MemoryScope(scope), key)
        if memory is None:
            raise KeyError(key)
        return _memory_to_dict(memory)

    async def set_memory(
        self,
        scope: str,
        key: str,
        value: str,
        ttl: int = 604800,
        confidence: int = 2,
    ) -> dict:
        memory = await self.store.set(
            Memory(
                id=None,
                scope=MemoryScope(scope),
                key=key,
                value=value,
                ttl=ttl,
                confidence=MemoryConfidence(confidence),
            )
        )
        return {"ok": True, "id": memory.id}

    async def delete_memory(self, memory_id: int) -> dict:
        await self.store.db.delete_memory_by_id(memory_id)
        return {"ok": True}

    async def search_memory(self, query: str, top_k: int = 5) -> list[dict]:
        return [_memory_to_dict(memory) for memory in await self.store.search(query, top_k)]


class AuditService:
    """Audit RPC service backed by AuditLogger."""

    def __init__(self, logger: AuditLogger):
        self.logger = logger

    async def query(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        entries = await self.logger.query(
            action=action, result=result, since=since, until=until, limit=limit
        )
        return [entry.to_dict() for entry in entries]


class TaskService:
    """Coding-task RPC service backed by a shared :class:`TaskManager`."""

    def __init__(self, task_manager: TaskManager, approval_broker: ApprovalBroker | None = None):
        self.task_manager = task_manager
        self.approval_broker = approval_broker

    async def list(self, active_only: bool = False) -> list[dict]:
        """List tasks — active ones by default, all when ``active_only`` is set."""
        if active_only:
            return await self.task_manager.list_active()
        return await self.task_manager.list_all()

    async def get(self, task_id: str) -> dict:
        """Return one task's state, or ``{"error": "not found"}``."""
        task = await self.task_manager.get(task_id)
        if task is None:
            return {"error": "task not found", "task_id": task_id}
        return task.to_dict()

    async def create(self, goal: str) -> dict:
        return (await self.task_manager.create(goal)).to_dict()

    async def cancel(self, task_id: str) -> dict:
        from khaos.coding.task_manager import TransitionResult

        result = await self.task_manager.cancel(task_id)
        if result == TransitionResult.NOT_FOUND:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if result == TransitionResult.INVALID_TRANSITION:
            return {"ok": False, "error": "task already terminal", "task_id": task_id}
        return {"ok": True, "task_id": task_id}

    async def approve(
        self,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        task = await self.task_manager.get(task_id)
        if task is None:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }
        result = await self.task_manager.transition(task_id, expected={TaskStatus.BLOCKED}, target=TaskStatus.RUNNING, pending_approval=None)
        if result != TransitionResult.UPDATED:
            return {"ok": False, "error": "task is no longer blocked", "task_id": task_id}
        resolved = await self.approval_broker.resolve(
            pending.get("tool_call_id", ""),
            True,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
        )
        if not resolved:
            await self.task_manager.update_status(
                task_id,
                TaskStatus.FAILED,
                error="approval capability was stale or already consumed",
            )
        return {"ok": resolved, "task_id": task_id}

    async def reject(
        self,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        task = await self.task_manager.get(task_id)
        if task is None:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }
        result = await self.task_manager.transition(task_id, expected={TaskStatus.BLOCKED}, target=TaskStatus.FAILED, error="rejected by user", pending_approval=None)
        if result != TransitionResult.UPDATED:
            return {"ok": False, "error": "task is no longer blocked", "task_id": task_id}
        resolved = await self.approval_broker.resolve(
            pending.get("tool_call_id", ""),
            False,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
        )
        return {"ok": resolved, "task_id": task_id}

    async def artifacts(self, task_id: str) -> list[dict]:
        task = await self.task_manager.get(task_id)
        if task is None:
            return []
        return ([{"type": "file", "path": path} for path in task.files_modified] + [{"type": "test_result", "data": result} for result in task.test_results])


async def serve_json_lines(
    socket_path: str,
    db_path: str,
    project_root: Path | None = None,
    config_path: Path | None = None,
    enable_subagents: bool = False,
    router=None,
) -> None:
    """Serve the privileged JSON-line control plane over a mode-0600 UDS."""
    uds_path = Path(socket_path).expanduser().resolve()
    uds_path.parent.mkdir(parents=True, exist_ok=True)
    if uds_path.exists() or uds_path.is_symlink():
        mode = uds_path.lstat().st_mode
        if not stat.S_ISSOCK(mode):
            raise PermissionError(f"refusing to replace non-socket RPC path: {uds_path}")
        uds_path.unlink()

    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    agent = AgentService(db, project_root=project_root, config_path=config_path, router=router)
    await agent.start()
    memory = MemoryService(MemoryStore(db))
    audit_service = AuditService(AuditLogger(db))
    task_service = TaskService(agent.task_manager, agent.approval_broker)
    subagent_service: SubAgentService | None = None
    if enable_subagents:
        subagent_service = await _build_subagent_service(db, project_root, config_path)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                request = _parse_json_line(line)
            except ValueError as exc:
                writer.write(
                    (
                        json.dumps(
                            {
                                "event": "error",
                                "data": {
                                    "code": "INVALID_JSON",
                                    "message": str(exc),
                                    "recoverable": True,
                                },
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    ).encode("utf-8")
                )
                await writer.drain()
                return
            method = request.get("method")
            payload = request.get("payload", {})
            if method == "AgentService.Chat":
                try:
                    async for event in agent.chat(ChatRequest(**payload)):
                        writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                        await writer.drain()
                except Exception as exc:
                    writer.write(
                        (
                            json.dumps(
                                {
                                    "event": "error",
                                    "data": {
                                        "code": exc.__class__.__name__,
                                        "message": str(exc),
                                        "recoverable": False,
                                    },
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
            elif method == "AgentService.SwitchMode":
                response = await agent.switch_mode(payload.get("session_id", ""), payload["target_mode"])
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "AgentService.ConfirmPermission":
                response = await agent.confirm_permission(ConfirmRequest(**payload))
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "AgentService.HandleWebhook":
                response = await agent.handle_webhook(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method in {"ChannelService.List", "ChannelService.Health"}:
                writer.write((json.dumps(agent.list_channels(), ensure_ascii=False) + "\n").encode("utf-8"))
            elif method in {"ChannelService.Enable", "ChannelService.Disable"}:
                response = agent.set_channel_enabled(payload["channel_id"], method.endswith("Enable"))
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "MemoryService.SetMemory":
                response = await memory.set_memory(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "MemoryService.GetMemory":
                response = await memory.get_memory(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "MemoryService.SearchMemory":
                response = await memory.search_memory(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "AuditService.Query":
                response = await audit_service.query(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "TaskService.List":
                response = await task_service.list(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "TaskService.Get":
                response = await task_service.get(**payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "TaskService.Create":
                writer.write((json.dumps(await task_service.create(**payload), ensure_ascii=False) + "\n").encode("utf-8"))
            elif method in {"TaskService.Cancel", "TaskService.Approve", "TaskService.Reject"}:
                action = method.rsplit(".", 1)[-1].lower()
                writer.write((json.dumps(await getattr(task_service, action)(**payload), ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "TaskService.Artifacts":
                writer.write((json.dumps(await task_service.artifacts(payload["task_id"]), ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "TaskService.Events":
                async for event in task_service.task_manager.subscribe(payload["task_id"]):
                    writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
            elif method == "SubAgentService.Spawn":
                response = await _handle_optional_subagent(subagent_service, "spawn", payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "SubAgentService.Collect":
                response = await _handle_optional_subagent(subagent_service, "collect", payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "SubAgentService.Status":
                response = await _handle_optional_subagent(subagent_service, "status", payload)
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            else:
                writer.write(json.dumps({"error": "unknown method"}).encode("utf-8") + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    try:
        server = await asyncio.start_unix_server(handle, path=str(uds_path))
        os.chmod(uds_path, 0o600)
        async with server:
            await server.serve_forever()
    finally:
        if uds_path.exists() and stat.S_ISSOCK(uds_path.lstat().st_mode):
            uds_path.unlink()
        await agent.shutdown()
        await db.close()


def _parse_json_line(line: bytes) -> dict:
    """Decode one JSON-line request into a dict.

    Empty connection probes are handled before this function. Malformed payloads get a
    structured error response instead of bubbling into asyncio's
    client_connected_cb exception logger.
    """
    try:
        request = json.loads(line.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("request must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("request must be a JSON object line") from exc
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    return request


async def _build_subagent_service(
    db: Database,
    project_root: Path | None,
    config_path: Path | None,
) -> SubAgentService:
    root = project_root or Path.cwd()
    resolved_config = config_path or root / "config.yaml"
    mode_manager = ModeManager(db, project_root=root)
    await mode_manager.load()
    router = load_router_from_config(resolved_config, project_root=root)
    permission_engine = PermissionEngine(db)
    await permission_engine.load_rules()
    memory_store = MemoryStore(db)
    memory_manager = MemoryManager(
        memory_store,
        budget=MemoryBudget(),
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
    )
    skill_manager = SkillManager()
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        skill_manager.load_from_dir(skills_dir)
    runner = SubAgentRunner(
        router=router,
        db=db,
        mode_manager=mode_manager,
        tool_scheduler=ToolScheduler(create_runtime_registry(), permission_engine),
        memory_manager=memory_manager,
        skill_manager=skill_manager if len(skill_manager.registry) > 0 else None,
        token_engine=get_token_engine(),
    )
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=3, max_spawn_depth=1, allow_nesting=False),
        db,
        runner=runner.run,
        registry=create_runtime_registry(),
    )
    return SubAgentService(spawner, runner)


async def _handle_optional_subagent(
    subagent_service: SubAgentService | None,
    action: str,
    payload: dict,
) -> dict:
    if subagent_service is None:
        return {"ok": False, "error": "subagents not enabled"}
    if action == "spawn":
        return await subagent_service.handle_spawn(payload)
    if action == "collect":
        return await subagent_service.handle_collect(payload)
    if action == "status":
        return await subagent_service.handle_status(payload)
    return {"ok": False, "error": "unknown subagent action"}


def load_router_from_config(config_path: Path, project_root: Path | None = None) -> ModelRouter:
    """Load model router, merging user config for the project template path."""
    expanded_config = config_path.expanduser()
    if not expanded_config.exists():
        return create_default_router(str(expanded_config), honor_no_config=False)
    root = project_root or Path.cwd()
    project_config = (root / "config.yaml").resolve()
    resolved_config = expanded_config.resolve()
    if resolved_config == project_config:
        return create_default_router(honor_no_config=False)
    return create_default_router(str(expanded_config), honor_no_config=False)


def _message_to_event(message) -> dict:
    event = message.event or ("done" if message.content == "done" and message.role == "system" else "message")
    if event in {"tool_call", "permission_request", "tool_result", "error"}:
        data = message.metadata
    elif event == "done":
        data = {"total_tokens": message.token_count, "stop_reason": message.stop_reason}
    else:
        data = {"role": message.role, "content": message.content, "token_count": message.token_count}
    return {"event": event, "data": data}


def _memory_to_dict(memory: Memory) -> dict:
    data = asdict(memory)
    data["scope"] = memory.scope.value
    data["confidence"] = memory.confidence.value
    data["created_at"] = memory.created_at.isoformat() if memory.created_at else ""
    data["updated_at"] = memory.updated_at.isoformat() if memory.updated_at else ""
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/khaos-agent.sock")
    parser.add_argument("--db", default="khaos.db")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--subagents", action="store_true")
    args = parser.parse_args()
    asyncio.run(
        serve_json_lines(
            args.socket,
            args.db,
            project_root=Path.cwd(),
            config_path=Path(args.config),
            enable_subagents=args.subagents,
        )
    )


if __name__ == "__main__":
    main()
