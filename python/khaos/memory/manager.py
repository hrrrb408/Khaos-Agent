"""Memory injection and cross-mode orchestration."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

from khaos.agent.core import SimpleTokenEngine
from khaos.memory.core import (
    ContextAssembler,
    MemoryAuthority,
    MemoryBroker,
    MemoryBudget,
    MemoryCandidate,
    MemoryEvent,
    MemoryEventType,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
)
from khaos.memory.events import MemoryEventBridge
from khaos.memory.extraction import (
    extract_candidates_from_event,
    extract_memories_from_messages,
)
from khaos.memory.models import Memory, MemoryScope
from khaos.memory.ownership import MemoryVisibility
from khaos.memory.retrieval import MemoryRetriever
from khaos.memory.retrieval_policy import (
    MemoryRetrievalNeed,
    MemoryRetrievalPolicy,
    MemoryRetrievalRequest,
    MemoryRetrievalScope,
    MemoryRetrievalService,
    MemoryRetrievalUnavailable,
    format_memory_bundle,
)
from khaos.memory.store import MemoryStore
from khaos.modes import Mode

logger = logging.getLogger(__name__)

MemoryExtractor = Callable[[list[Any], MemoryScope], list[Memory]]


class MemoryManager:
    """Coordinate retrieval, formatting, and proactive extraction."""

    def __init__(
        self,
        store: MemoryStore,
        budget: MemoryBudget | None = None,
        token_engine: SimpleTokenEngine | None = None,
        mode_getter: Callable[[], Any] | None = None,
        intent_getter: Callable[[], str] | None = None,
        *,
        retriever: MemoryRetriever | None = None,
        extractor: MemoryExtractor | None = None,
        broker: MemoryBroker | None = None,
        runtime_context_factory: Callable[..., RuntimeMemoryContext] | None = None,
        provider_manager: Any = None,
        profile: Any = None,
        transfer_service: Any = None,
        codegraph: Any = None,
        owns_provider_manager: bool = True,
        retrieval_policy: MemoryRetrievalPolicy | None = None,
        retrieval_service: MemoryRetrievalService | None = None,
    ) -> None:
        self.store = store
        self.budget = budget or MemoryBudget()
        self.token_engine = token_engine or SimpleTokenEngine()
        self.mode_getter = mode_getter
        self.intent_getter = intent_getter
        self.retriever = retriever or MemoryRetriever()
        self.extractor = extractor or extract_memories_from_messages
        self.broker = broker
        self.runtime_context_factory = runtime_context_factory
        self.provider_manager = provider_manager
        self.profile = profile
        self.transfer_service = transfer_service
        self.codegraph = codegraph
        self.owns_provider_manager = owns_provider_manager
        self.profile_registry: Any = None
        self.profile_store: Any = None
        self.observability: Any = None
        self.memory_host: Any = None
        self.context_assembler = ContextAssembler(self.token_engine)
        self.event_bridge = MemoryEventBridge(broker) if broker is not None else None
        self.retrieval_policy = retrieval_policy or MemoryRetrievalPolicy.production()
        self.retrieval_service = retrieval_service or (
            MemoryRetrievalService(broker, self.retrieval_policy)
            if broker is not None
            else None
        )

    async def inject(
        self,
        session_id: str,
        *,
        task_id: str | None = None,
        repository_generation: str | None = None,
    ) -> str:
        """Return durable L0/L1/L2 memory text within the total budget.

        Session-private rows are intentionally excluded from generic prompt
        injection.  Callers that need them must request an explicit
        :class:`MemoryVisibility.for_session` view rather than widening the
        durable memory boundary by accident.
        """

        if self.broker is not None:
            runtime = self._runtime_context(session_id, task_id=task_id)
            query = self.intent_getter() if self.intent_getter is not None else ""
            if self.retrieval_service is None:
                return ""
            request = MemoryRetrievalRequest.from_runtime(
                runtime,
                policy=self.retrieval_policy,
                query=query,
                scope=MemoryRetrievalScope.PROJECT_HISTORY,
                needs=(
                    MemoryRetrievalNeed.USER_PREFERENCES,
                    MemoryRetrievalNeed.PROJECT_CONVENTIONS,
                    MemoryRetrievalNeed.PRIOR_ENGINEERING_EPISODES,
                    MemoryRetrievalNeed.REPOSITORY_HINTS,
                ),
                repository_generation=repository_generation,
            )
            try:
                bundle = await self.retrieval_service.retrieve(request, runtime)
            except (MemoryRetrievalUnavailable, PermissionError, ValueError):
                logger.warning("memory retrieval unavailable; continuing without memory", exc_info=True)
                return ""
            return self._truncate_to_tokens(
                format_memory_bundle(bundle),
                self.budget.total_tokens,
            )
        durable_view = MemoryVisibility.durable()
        current_mode = self._current_scope()
        layers = self.retriever.build_layers(
            await self.store.list_by_scope(
                MemoryScope.GLOBAL,
                visibility=durable_view,
            ),
            await self.store.list_by_scope(
                current_mode,
                visibility=durable_view,
            ),
            await self.store.list_all(visibility=durable_view),
            current_mode,
        )
        sections = [
            self._format_section(
                "L0 全局记忆", layers.global_memories, self.budget.l0_max_tokens
            ),
            self._format_section(
                "L1 模式记忆",
                layers.current_mode_memories,
                self.budget.l1_max_tokens,
            ),
            self._format_section(
                "L2 相关记忆",
                layers.cross_mode_memories,
                self.budget.l2_max_tokens,
            ),
        ]
        text = "\n".join(section for section in sections if section)
        return self._truncate_to_tokens(text, self.budget.total_tokens)

    async def cross_mode_transfer(self, old_mode: Mode, new_mode: Mode) -> str:
        """Format the transient intent buffer between mode switches."""

        intent = self.intent_getter() if self.intent_getter is not None else ""
        if not intent:
            return ""
        return f"跨模式上下文: {old_mode.value} -> {new_mode.value}: {intent}"

    async def update_from_conversation(
        self,
        messages: list[Any],
        mode: Mode,
    ) -> list[Memory]:
        """Extract and persist declarative user facts with conflict policy."""

        if self.broker is not None:
            return await self._update_v2_from_conversation(messages, mode)
        del mode
        candidates = self.extractor(messages, MemoryScope.GLOBAL)
        persisted: list[Memory] = []
        for memory in candidates:
            stored = await self.store.set(memory, on_conflict="resolve")
            if stored is not None:
                persisted.append(stored)
        if persisted:
            logger.info("proactive memory extracted %d fact(s)", len(persisted))
        return persisted

    async def record_message(
        self,
        message: Any,
        *,
        session_id: str,
        task_id: str | None = None,
        workspace_id: str | None = None,
        repo_id: str | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
    ) -> None:
        """Append a live message event without making it model-visible."""

        if self.broker is None:
            return
        role = str(getattr(message, "role", ""))
        event_type = {
            "user": MemoryEventType.USER_MESSAGE,
            "assistant": MemoryEventType.ASSISTANT_MESSAGE,
            "tool": MemoryEventType.TOOL_RESULT,
        }.get(role, MemoryEventType.ASSISTANT_MESSAGE)
        source_type = (
            SourceType.USER
            if role == "user"
            else SourceType.TOOL
            if role == "tool"
            else SourceType.SYSTEM
        )
        runtime = self._runtime_context(
            session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            repo_id=repo_id,
            commit_sha=commit_sha,
            branch=branch,
        )
        if self.event_bridge is None:
            raise RuntimeError("MemoryManager has no canonical event bridge")
        metadata = getattr(message, "metadata", {})
        message_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        payload = {
            "role": role,
            "content": str(getattr(message, "content", "")),
            "token_count": int(getattr(message, "token_count", 0) or 0),
            **message_metadata,
            "metadata": message_metadata,
        }
        tool_calls = getattr(message, "tool_calls", ())
        if tool_calls:
            payload["tool_calls"] = list(tool_calls)[:32]
        event = await self.event_bridge.record(
            event_type,
            runtime,
            payload,
            source_type=source_type,
            trust_hint=(
                TrustHint.USER_STATED
                if role == "user"
                else TrustHint.TOOL_OBSERVED
                if role == "tool"
                else TrustHint.AGENT_INFERRED
            ),
        )
        if role == "assistant" and tool_calls:
            for call in list(tool_calls)[:32]:
                if not isinstance(call, dict):
                    continue
                await self.event_bridge.tool_call(
                    runtime,
                    tool_call_id=str(call.get("id", call.get("tool_call_id", ""))),
                    name=str(call.get("name", "")),
                    arguments=call.get("arguments", {}),
                )
        await self._admit_event_candidates(event, runtime)

    def _current_scope(self) -> MemoryScope:
        if self.mode_getter is None:
            return MemoryScope.GLOBAL
        mode = self.mode_getter()
        if isinstance(mode, Mode):
            return MemoryScope(mode.value)
        return MemoryScope(str(mode))

    def _runtime_context(
        self,
        session_id: str,
        *,
        task_id: str | None = None,
        workspace_id: str | None = None,
        repo_id: str | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
    ) -> RuntimeMemoryContext:
        if self.runtime_context_factory is not None:
            factory = self.runtime_context_factory
            parameters = inspect.signature(factory).parameters
            supports_kwargs = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                or name in parameters
                for name, parameter in parameters.items()
            )
            if supports_kwargs:
                return factory(
                    session_id,
                    task_id=task_id,
                    workspace_id=workspace_id,
                    repo_id=repo_id,
                    commit_sha=commit_sha,
                    branch=branch,
                )
            # This branch is deliberately limited to explicitly injected
            # test adapters.  The production factory always exposes the full
            # binding and therefore cannot silently drop provenance fields.
            return factory(session_id)
        return RuntimeMemoryContext(
            principal_id=self.store.principal_id,
            project_id=self.store.project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            mode=self._current_scope().value,
            environment_fingerprint="runtime:default",
            repo_id=repo_id,
            commit_sha=commit_sha,
            branch=branch,
        )

    def runtime_context(self, session_id: str) -> RuntimeMemoryContext:
        """Return the host-bound context used by Broker-backed UI commands."""

        return self._runtime_context(session_id)

    async def _update_v2_from_conversation(
        self,
        messages: list[Any],
        mode: Mode,
    ) -> list[Memory]:
        """Promote only explicit user facts through the V2 Broker."""

        del mode
        runtime = self._runtime_context("")
        persisted: list[Memory] = []
        broker = self.broker
        event_bridge = self.event_bridge
        if broker is None or event_bridge is None:
            raise RuntimeError("MemoryManager has no canonical memory broker")
        for message in messages:
            if getattr(message, "role", "") != "user":
                continue
            event = await event_bridge.record(
                MemoryEventType.USER_MESSAGE,
                runtime,
                {"role": "user", "content": str(getattr(message, "content", ""))},
                source_type=SourceType.USER,
                trust_hint=TrustHint.USER_STATED,
            )
            for extracted in self.extractor([message], MemoryScope.GLOBAL):
                candidate = MemoryCandidate(
                    memory_type="USER_MEMORY",
                    claim=f"{extracted.key}: {extracted.value}",
                    key=extracted.key,
                    authority=MemoryAuthority.USER_STATED,
                    confidence=extracted.confidence.value / 3.0,
                    source_event_ids=(event.event_id,),
                    scope=extracted.scope.value,
                    namespace="private",
                )

                decision = await broker.propose_memory(candidate, runtime)
                if decision.accepted and decision.memory_id:
                    persisted.append(extracted)
        return persisted

    async def record_runtime_event(
        self,
        event_type: MemoryEventType | str,
        *,
        session_id: str,
        payload: dict[str, Any],
        task_id: str | None = None,
        workspace_id: str | None = None,
        repo_id: str | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
        source_type: SourceType | str = SourceType.SYSTEM,
        trust_hint: TrustHint | str = TrustHint.AGENT_INFERRED,
    ) -> MemoryEvent | None:
        """Publish a bounded domain event through the canonical bridge."""

        if self.event_bridge is None:
            return None
        runtime = self._runtime_context(
            session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            repo_id=repo_id,
            commit_sha=commit_sha,
            branch=branch,
        )
        event = await self.event_bridge.record(
            event_type,
            runtime,
            payload,
            source_type=source_type,
            trust_hint=trust_hint,
        )
        await self._admit_event_candidates(event, runtime)
        return event

    async def _admit_event_candidates(
        self,
        event: MemoryEvent,
        runtime: RuntimeMemoryContext,
    ) -> None:
        """Admit only bounded candidates derived from one canonical event."""

        if self.broker is None:
            return
        max_mutations = int(getattr(self.profile, "max_mutations_per_event", 16))
        if max_mutations <= 0:
            return
        candidates = extract_candidates_from_event(event, profile=self.profile)
        for candidate in candidates[:max_mutations]:
            try:
                await self.broker.propose_memory(candidate, runtime)
            except (TypeError, ValueError, RuntimeError):
                # Extraction is proactive convenience, never a reason to
                # break message persistence or the agent turn.
                logger.warning(
                    "memory candidate admission failed for event %s",
                    event.event_id,
                    exc_info=True,
                )

    def _format_section(
        self,
        title: str,
        memories: list[Memory],
        token_budget: int,
    ) -> str:
        if token_budget <= 0:
            return ""
        lines: list[str] = []
        used = 0
        for memory in memories:
            line = f"- ({memory.scope.value}) {memory.key}: {memory.value}"
            tokens = self.token_engine.count_tokens(line)
            if used + tokens > token_budget:
                break
            used += tokens
            lines.append(line)
        if not lines:
            return ""
        return f"{title}:\n" + "\n".join(lines)

    def _truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate on word boundaries while respecting the active tokenizer."""

        if max_tokens <= 0 or not text:
            return ""
        if self.token_engine.count_tokens(text) <= max_tokens:
            return text
        words = text.split()
        low, high = 0, len(words)
        best = ""
        while low <= high:
            middle = (low + high) // 2
            candidate = " ".join(words[:middle])
            if self.token_engine.count_tokens(candidate) <= max_tokens:
                best = candidate
                low = middle + 1
            else:
                high = middle - 1
        return best

    async def aclose(self) -> None:
        """Close provider resources when a provider exposes a lifecycle hook."""

        if self.provider_manager is not None and self.owns_provider_manager:
            registry = getattr(self.provider_manager, "registry", None)
            close_registry = getattr(registry, "close", None)
            if callable(close_registry):
                await cast(Callable[..., Awaitable[Any]], close_registry)()
                return
        close = getattr(self.broker.provider, "aclose", None) if self.broker else None
        if callable(close):
            await cast(Callable[..., Awaitable[Any]], close)()


__all__ = ["MemoryBudget", "MemoryManager"]
