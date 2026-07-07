"""Python AgentService and MemoryService.

The service classes mirror the LLD gRPC surface. The optional JSON-line TCP
server keeps Phase 2 testable without generated protobuf dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import AsyncIterator

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
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
from khaos.routing.router import create_default_router
from khaos.routing import ModelRouter, ProviderManager, RoutingRule
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


@dataclass
class ChatRequest:
    session_id: str
    message: str
    mode: str = ""


@dataclass
class ConfirmRequest:
    session_id: str
    tool_call_id: str
    approved: bool
    remember: bool = False


class AgentService:
    """Agent RPC service backed by AgentLoop."""

    def __init__(self, db: Database, project_root: Path | None = None, config_path: Path | None = None):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self.config_path = config_path or self.project_root / "config.yaml"
        self.pending_confirmations: dict[str, dict] = {}

    async def chat(self, request: ChatRequest) -> AsyncIterator[dict]:
        """Stream chat events."""
        session_id = request.session_id or str(uuid.uuid4())
        mode_manager, loop = await self._build_runtime(session_id, request.mode)
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
        self.pending_confirmations[request.tool_call_id] = {
            "approved": request.approved,
            "remember": request.remember,
        }
        return {"ok": True}

    async def _build_runtime(self, session_id: str, mode: str) -> tuple[ModeManager, AgentLoop]:
        await self.db.create_session(session_id, mode or "office")
        mode_manager = ModeManager(self.db, project_root=self.project_root)
        await mode_manager.load()
        if mode:
            await mode_manager.switch(ModeManager.parse(mode))
        router = load_router_from_config(self.config_path)
        permission_engine = PermissionEngine(self.db)
        await permission_engine.load_rules()
        memory_store = MemoryStore(self.db)
        memory_manager = MemoryManager(
            memory_store,
            budget=MemoryBudget(),
            mode_getter=lambda: mode_manager.current_mode,
            intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
        )
        compressor = ContextCompressor(router, memory_manager=memory_manager)
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            router,
            self.db,
            tool_scheduler=ToolScheduler(create_runtime_registry(), permission_engine),
            confirm_callback=self._wait_for_confirmation,
            context_compressor=compressor,
            memory_manager=memory_manager,
            error_handler=ErrorHandler(db=self.db, router=router, compressor=compressor),
        )
        return mode_manager, loop

    async def _wait_for_confirmation(self, request: dict) -> dict:
        tool_call_id = request["id"]
        for _ in range(1200):
            if tool_call_id in self.pending_confirmations:
                return self.pending_confirmations.pop(tool_call_id)
            await asyncio.sleep(0.1)
        return {"approved": False, "remember": False}


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


async def serve_json_lines(
    host: str,
    port: int,
    db_path: str,
    project_root: Path | None = None,
    config_path: Path | None = None,
) -> None:
    """Serve JSON-line RPC requests over TCP."""
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    agent = AgentService(db, project_root=project_root, config_path=config_path)
    memory = MemoryService(MemoryStore(db))

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            request = json.loads(line.decode("utf-8"))
            method = request.get("method")
            payload = request.get("payload", {})
            if method == "AgentService.Chat":
                async for event in agent.chat(ChatRequest(**payload)):
                    writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
            elif method == "AgentService.SwitchMode":
                response = await agent.switch_mode(payload.get("session_id", ""), payload["target_mode"])
                writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
            elif method == "AgentService.ConfirmPermission":
                response = await agent.confirm_permission(ConfirmRequest(**payload))
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
            else:
                writer.write(json.dumps({"error": "unknown method"}).encode("utf-8") + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()


def load_router_from_config(config_path: Path) -> ModelRouter:
    """Load model router from config.yaml, falling back to mock when absent."""
    if not config_path.exists():
        return create_default_router()
    import yaml

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    models_config = config.get("models")
    if not isinstance(models_config, dict) or not models_config.get("providers"):
        return create_default_router()
    provider_manager = ProviderManager.from_config(config)
    default_model = str(models_config.get("default_model", ""))
    if not default_model:
        return create_default_router()
    router = ModelRouter(provider_manager)
    router.set_rule("agent_loop", RoutingRule("agent_loop", default_model, []))
    router.set_rule("coding", RoutingRule("coding", default_model, [], prefer_coding_model=True))
    router.set_rule("compression", RoutingRule("compression", default_model, []))
    return router


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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--db", default="khaos.db")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()
    asyncio.run(
        serve_json_lines(
            args.host,
            args.port,
            args.db,
            project_root=Path.cwd(),
            config_path=Path(args.config),
        )
    )


if __name__ == "__main__":
    main()
