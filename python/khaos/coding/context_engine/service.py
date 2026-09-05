"""M8.4 Context Engine orchestration service.

The service is intentionally a narrow composition layer.  It calls an
already-composed repository-intelligence facade when supplied, but it never
scans repositories, executes tools, authorizes edits, runs verification, or
decides completion.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, TypeVar, cast

from khaos.coding.context_engine.cache import ContextCache, ContextCacheKey
from khaos.coding.context_engine.compression import ContextCompactor
from khaos.coding.context_engine.contracts import (
    ContextBudget,
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextMessage,
    ContextMetricsSnapshot,
    ContextOperation,
    ContextRequirements,
    ContextSource,
    ContextTrust,
    ModelContext,
    _normalize_generation,
    approximate_token_count,
)
from khaos.coding.context_engine.discovery import (
    DeferredToolDiscovery,
    LazySkillDiscovery,
)
from khaos.coding.context_engine.selector import ContextSelector
from khaos.coding.context_engine.serializer import ContextSerializer
from khaos.coding.context_engine.tools import (
    ToolOutputEnvelope,
    ToolOutputLimits,
    ToolOutputPolicy,
)
from khaos.coding.context_engine.working_set import (
    WORKING_SET_METADATA_KEY,
    InMemoryWorkingSetStore,
    TaskWorkingSet,
    WorkingSetEvent,
)
from khaos.security.protocol_boundary import canonical_digest

_ContextEnum = TypeVar("_ContextEnum", bound=Enum)


class ContextEngineService:
    """Build and maintain bounded context snapshots for parent/child tasks."""

    def __init__(
        self,
        *,
        repo_intelligence: object | None = None,
        project_root: str | Path | None = None,
        instruction_resolver: object | None = None,
        task_manager: object | None = None,
        tool_registry: object | None = None,
        skill_manager: object | None = None,
        working_set_store: InMemoryWorkingSetStore | None = None,
        cache: ContextCache | None = None,
        default_budget: ContextBudget | None = None,
        tool_output_limits: ToolOutputLimits | None = None,
        principal_id: str = "",
        project_id: str = "",
        recent_message_count: int = 12,
    ) -> None:
        self.repo_intelligence = repo_intelligence
        self.project_root = Path(project_root).expanduser().resolve() if project_root else None
        self.instruction_resolver = instruction_resolver
        self.task_manager = task_manager
        self.tool_registry = tool_registry
        self.skill_manager = skill_manager
        self.working_set_store = working_set_store or InMemoryWorkingSetStore()
        self.cache = cache or ContextCache()
        self.default_budget = default_budget or ContextBudget()
        self.tool_output_policy = ToolOutputPolicy(tool_output_limits)
        self.principal_id = principal_id
        self.project_id = project_id
        if type(recent_message_count) is not int or recent_message_count < 0:
            raise ValueError("recent_message_count must be non-negative")
        self.recent_message_count = recent_message_count
        self.selector = ContextSelector()
        self.serializer = ContextSerializer()
        self.compactor = ContextCompactor()
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self._locks_guard = RLock()
        self._metrics_lock = RLock()
        self._metrics: dict[str, int | None] = {
            "context_builds": 0,
            "context_input_tokens": 0,
            "context_input_bytes": 0,
            "context_l0_tokens": 0,
            "context_l1_tokens": 0,
            "context_l2_tokens": 0,
            "context_l3_tokens": 0,
            "context_items_selected": 0,
            "context_items_evicted": 0,
            "context_items_compressed": 0,
            "context_truncated_count": 0,
            "context_stale_retries": 0,
            "context_partial_builds": 0,
            "context_compactions": 0,
            "context_cache_hits": 0,
            "context_cache_misses": 0,
            "context_stable_prefix_tokens": 0,
            "context_stable_prefix_bytes": 0,
            "context_selected_file_count": 0,
            "context_selected_symbol_count": 0,
            "context_memory_items_selected": 0,
            "context_repo_items_selected": 0,
            "context_diagnostics_selected": 0,
            "tool_schema_tokens": 0,
            "tool_schema_bytes": 0,
            "deferred_tool_discoveries": 0,
            "deferred_skill_discoveries": 0,
            "deferred_skill_loads": 0,
            "skill_tokens": 0,
            "tool_output_tokens": 0,
            "tool_output_bytes": 0,
            "tool_output_truncated_count": 0,
        }

    async def build(
        self,
        requirements: ContextRequirements,
        candidates: Iterable[ContextItem] = (),
        *,
        repo_bundle: object | None = None,
        scope_id: str = "parent",
        partial: bool = False,
    ) -> ModelContext:
        """Select and serialize one immutable context snapshot."""

        if type(requirements) is not ContextRequirements:
            raise TypeError("context requirements are required")
        values = [item for item in candidates if type(item) is ContextItem]
        if repo_bundle is not None:
            values.extend(self.items_from_repo_bundle(repo_bundle, requirements=requirements))
        values, stale = self._filter_generation(values, requirements.generation)
        values, scope_mismatch = self._filter_workspace(values, requirements.workspace_id)
        if scope_mismatch:
            self._inc("context_stale_retries")
        partial = partial or stale or scope_mismatch
        state_key = (requirements.task_id, requirements.workspace_id, scope_id)
        state_snapshot = self.working_set_store.get(state_key)
        state_digest = state_snapshot.digest if state_snapshot is not None else None
        candidate_digest = canonical_digest(
            [
                item.to_payload(include_content=False)
                for item in sorted(values, key=lambda value: (value.item_id, value.digest))
            ]
        )
        key = ContextCacheKey(
            workspace_id=requirements.workspace_id,
            task_id=requirements.task_id,
            generation=requirements.generation,
            plan_revision=requirements.plan_revision,
            step_id=requirements.step_id or None,
            requirements_digest=requirements.digest(),
            candidate_digest=candidate_digest,
            verification_state=requirements.verification_state,
            scope_id=scope_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        cached = self.cache.get(key)
        if cached is not None and not self._working_set_changed(state_key, state_digest):
            self._inc("context_cache_hits")
            return replace(cached, cache_hit=True, partial=partial or cached.partial)
        if cached is not None:
            partial = True
            self._inc("context_stale_retries")
        self._inc("context_cache_misses")
        lock = self._lock_for((requirements.task_id, requirements.workspace_id, scope_id))
        async with lock:
            cached = self.cache.get(key)
            race = self._working_set_changed(state_key, state_digest)
            if cached is not None and not race:
                self._inc("context_cache_hits")
                return replace(cached, cache_hit=True, partial=partial or cached.partial)
            if race:
                partial = True
                self._inc("context_stale_retries")
            selection = self.selector.select(values, requirements)
            serialized = self.serializer.serialize(selection)
            context = ModelContext(
                messages=serialized.messages,
                selection=selection,
                requirements_digest=requirements.digest(),
                context_digest=serialized.context_digest,
                cache_hit=False,
                partial=partial or race,
            )
            if not race:
                self.cache.put(key, context)
            self._record_build(context, serialized.stable_prefix_tokens, serialized.stable_prefix_bytes)
            return context

    async def build_for_agent(
        self,
        *,
        system_prompt: str,
        history: Sequence[object] = (),
        active_facts: Sequence[object] = (),
        memory_message: object | None = None,
        repo_message: object | None = None,
        repo_bundle: object | None = None,
        requirements: ContextRequirements | None = None,
        task_id: str = "",
        workspace_id: str = "",
        generation: str | None = None,
        plan_revision: str | None = None,
        step_id: str = "",
        goal: str = "",
        operation: ContextOperation = ContextOperation.GENERAL,
        target_path: str | Path | None = None,
        scope_id: str = "parent",
    ) -> ModelContext:
        """Build an AgentLoop-compatible context from existing owners."""

        if type(generation) is int:
            generation = str(generation)
        if requirements is not None:
            # A typed requirements object is the per-turn binding.  Accepting
            # omitted convenience arguments keeps this API safe for direct
            # callers without silently assembling a context for a different
            # task/workspace than the one they requested.
            task_id = requirements.task_id or task_id
            workspace_id = requirements.workspace_id or workspace_id
            generation = requirements.generation or generation
            plan_revision = requirements.plan_revision or plan_revision
            step_id = requirements.step_id or step_id
            operation = requirements.operation
            goal = goal or requirements.query
            requirements = replace(
                requirements,
                task_id=task_id,
                workspace_id=workspace_id,
                generation=generation,
                plan_revision=plan_revision,
                step_id=step_id,
                query=goal,
            )
        if requirements is None:
            requirements = ContextRequirements(
                operation=operation,
                task_id=task_id,
                step_id=step_id,
                workspace_id=workspace_id,
                generation=generation,
                plan_revision=plan_revision,
                query=goal,
                recent_message_count=self.recent_message_count,
                budget=self.default_budget,
            )
        candidates: list[ContextItem] = []
        candidates.append(
            ContextItem(
                kind=ContextItemKind.TASK_STATE,
                payload=system_prompt or "",
                layer=ContextLayer.L0,
                source=ContextSource.SYSTEM,
                trust=ContextTrust.TRUSTED_SYSTEM,
                workspace_id=workspace_id,
                generation=generation,
                priority=1000,
                required=True,
                sequence=0,
                metadata={"role": "system", "context_layer": "L0"},
            )
        )
        instruction_text = await self._resolve_instructions(target_path)
        if instruction_text and instruction_text not in (system_prompt or ""):
            candidates.append(
                ContextItem(
                    kind=ContextItemKind.PROJECT_INSTRUCTION,
                    payload=instruction_text,
                    layer=ContextLayer.L0,
                    source=ContextSource.PROJECT,
                    trust=ContextTrust.TRUSTED_PROJECT,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=990,
                    required=True,
                    sequence=1,
                    metadata={"role": "system", "context_layer": "L0"},
                )
            )
        if goal:
            candidates.append(
                ContextItem(
                    kind=ContextItemKind.GOAL,
                    payload=goal,
                    layer=ContextLayer.L1,
                    source=ContextSource.RUNTIME,
                    trust=ContextTrust.TRUSTED_RUNTIME,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=950,
                    required=True,
                    sequence=2,
                    metadata={"role": "user", "context_layer": "L1"},
                )
            )
        sequence = 10
        for raw in active_facts:
            item = self._message_to_item(
                raw,
                layer=ContextLayer.L1,
                source=ContextSource.RUNTIME,
                trust=ContextTrust.TRUSTED_RUNTIME,
                kind=ContextItemKind.TASK_STATE,
                priority=700,
                sequence=sequence,
                required=True,
                workspace_id=workspace_id,
                generation=generation,
            )
            if item is not None:
                candidates.append(item)
                sequence += 1
        history_values = list(history)
        recent_start = max(0, len(history_values) - requirements.recent_message_count)
        for index, raw in enumerate(history_values):
            # The exact transcript remains durable in the session store, but
            # the model-facing projection is recent-only.  Older state is
            # represented by the canonical TaskStateSummary below rather
            # than replayed as an ever-growing prompt prefix.
            if index < recent_start:
                continue
            role = str(getattr(raw, "role", "user"))
            raw_metadata = getattr(raw, "metadata", {}) or {}
            raw_metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
            raw_event = str(getattr(raw, "event", "") or "")
            if role == "tool":
                layer = ContextLayer.L3
                source = ContextSource.TOOL
                trust = ContextTrust.UNTRUSTED_TOOL
                kind = ContextItemKind.TOOL_RESULT
            elif raw_metadata.get("context_layer") == "historical-memory":
                layer = ContextLayer.L1
                source = ContextSource.MEMORY
                trust = ContextTrust.UNTRUSTED_MEMORY
                kind = ContextItemKind.MEMORY
            elif raw_metadata.get("context_layer") == "workspace-bound-observation":
                layer = ContextLayer.L2
                source = ContextSource.REPO_INTELLIGENCE
                trust = ContextTrust.UNTRUSTED_REPO
                kind = ContextItemKind.FILE_REGION
            elif raw_event in {
                "verification_result",
                "verification_unavailable",
                "verify_fix",
                "verify_fix_report",
            } or raw_metadata.get("trusted") is False:
                layer = ContextLayer.L3
                source = ContextSource.VERIFICATION
                trust = ContextTrust.UNTRUSTED_TOOL
                kind = ContextItemKind.VERIFICATION_SUMMARY
            elif role == "system":
                layer = ContextLayer.L1
                source = ContextSource.RUNTIME
                trust = ContextTrust.TRUSTED_RUNTIME
                kind = ContextItemKind.TASK_STATE
            else:
                layer = ContextLayer.L1
                source = ContextSource.CONVERSATION
                trust = ContextTrust.TRUSTED_RUNTIME
                kind = ContextItemKind.CONVERSATION
            item = self._message_to_item(
                raw,
                layer=layer,
                source=source,
                trust=trust,
                kind=kind,
                priority=300 + index,
                sequence=100 + index,
                required=True,
                workspace_id=workspace_id,
                generation=generation,
            )
            if item is not None:
                candidates.append(item)
        for raw, kind, trust, source, layer, priority in (
            (
                memory_message,
                ContextItemKind.MEMORY,
                ContextTrust.UNTRUSTED_MEMORY,
                ContextSource.MEMORY,
                ContextLayer.L1,
                250,
            ),
            (
                repo_message,
                ContextItemKind.FILE_REGION,
                ContextTrust.UNTRUSTED_REPO,
                ContextSource.REPO_INTELLIGENCE,
                ContextLayer.L2,
                500,
            ),
        ):
            if kind is ContextItemKind.MEMORY and not self._memory_is_in_scope(
                raw,
                task_id=task_id,
                workspace_id=workspace_id,
                goal=goal,
            ):
                continue
            item = self._message_to_item(
                raw,
                layer=layer,
                source=source,
                trust=trust,
                kind=kind,
                priority=priority,
                sequence=1000 if kind is ContextItemKind.MEMORY else 1100,
                required=False,
                workspace_id=workspace_id,
                generation=generation,
            )
            if item is not None:
                candidates.append(item)
        working_set = await self.get_working_set(
            task_id=task_id,
            workspace_id=workspace_id,
            scope_id=scope_id,
            goal=goal,
            generation=generation,
        )
        if goal and not working_set.goal:
            working_set = replace(working_set, goal=goal)
        candidates.extend(self._working_set_candidates(working_set))
        if working_set.event_sequence or len(history_values) > requirements.recent_message_count:
            summary = working_set.summary()
            candidates.append(
                ContextItem(
                    kind=ContextItemKind.TASK_STATE,
                    payload=summary.to_text(),
                    layer=ContextLayer.L1,
                    source=ContextSource.RUNTIME,
                    # The structured summary contains runtime facts plus
                    # untrusted diagnostics/hypotheses.  Keep the aggregate
                    # low-trust so compression cannot turn model/tool text
                    # into a system instruction; trusted goal/plan items
                    # remain separate candidates.
                    trust=ContextTrust.UNTRUSTED_MODEL,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=800,
                    required=True,
                    sequence=5,
                    metadata={"role": "user", "context_layer": "L1"},
                )
            )
            if len(history_values) > requirements.recent_message_count:
                self._inc("context_compactions")
        return await self.build(
            requirements,
            candidates,
            repo_bundle=repo_bundle,
            scope_id=scope_id,
        )

    @staticmethod
    def _memory_is_in_scope(
        message: object | None,
        *,
        task_id: str,
        workspace_id: str,
        goal: str,
    ) -> bool:
        """Reject explicitly stale memory without guessing authority."""

        if message is None:
            return False
        metadata = getattr(message, "metadata", {}) or {}
        if isinstance(metadata, Mapping):
            if metadata.get("relevant") is False:
                return False
            for key, expected in (
                ("task_id", task_id),
                ("workspace_id", workspace_id),
            ):
                observed = metadata.get(key)
                if observed not in (None, "", expected):
                    return False
        return True

    @staticmethod
    def _working_set_candidates(working_set: TaskWorkingSet) -> list[ContextItem]:
        """Project bounded task state into typed candidates for this turn."""

        values: list[ContextItem] = []
        sequence = 20
        # Plan and step state is the durable control spine of a long-running
        # task.  Keep only the newest item of each kind so repeated plan
        # revisions cannot consume the whole turn budget, while preserving
        # the runtime trust/source classification of the stored item.
        for kind in (ContextItemKind.PLAN, ContextItemKind.PLAN_STEP):
            current = max(
                (
                    item
                    for item in working_set.items
                    if item.kind is kind
                ),
                key=lambda item: (item.sequence, item.item_id),
                default=None,
            )
            if current is not None:
                metadata = dict(current.metadata)
                metadata.update({"role": "system", "context_layer": "L1"})
                values.append(
                    replace(
                        current,
                        layer=ContextLayer.L1,
                        workspace_id=working_set.workspace_id,
                        generation=working_set.generation,
                        priority=max(current.priority, 900),
                        required=True,
                        sequence=sequence,
                        metadata=metadata,
                    )
                )
                sequence += 1
        for path in working_set.changed_files[:64]:
            values.append(
                ContextItem(
                    kind=ContextItemKind.EDIT_SUMMARY,
                    payload=f"changed_file: {path}",
                    layer=ContextLayer.L1,
                    source=ContextSource.EDIT_TRANSACTION,
                    trust=ContextTrust.TRUSTED_RUNTIME,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=830,
                    required=True,
                    sequence=sequence,
                    metadata={"role": "system", "context_layer": "L1"},
                )
            )
            sequence += 1
        for constraint in working_set.constraints[:64]:
            values.append(
                ContextItem(
                    kind=ContextItemKind.DECISION,
                    payload=f"constraint: {constraint}",
                    layer=ContextLayer.L1,
                    source=ContextSource.RUNTIME,
                    trust=ContextTrust.TRUSTED_RUNTIME,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=910,
                    required=True,
                    sequence=sequence,
                    metadata={"role": "user", "context_layer": "L1"},
                )
            )
            sequence += 1
        for diagnostic in working_set.active_diagnostics[:64]:
            values.append(
                ContextItem(
                    kind=ContextItemKind.DIAGNOSTIC,
                    payload=diagnostic,
                    layer=ContextLayer.L2,
                    source=ContextSource.VERIFICATION,
                    trust=ContextTrust.UNTRUSTED_TOOL,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=940,
                    required=True,
                    sequence=sequence,
                )
            )
            sequence += 1
        for symbol in working_set.important_symbols[:64]:
            values.append(
                ContextItem(
                    kind=ContextItemKind.SYMBOL,
                    payload=f"important_symbol: {symbol}",
                    layer=ContextLayer.L2,
                    source=ContextSource.REPO_INTELLIGENCE,
                    trust=ContextTrust.UNTRUSTED_REPO,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=700,
                    symbol=symbol,
                    required=False,
                    sequence=sequence,
                )
            )
            sequence += 1
        for path in working_set.important_paths[:64]:
            values.append(
                ContextItem(
                    kind=ContextItemKind.RELATION,
                    payload=f"important_path: {path}",
                    layer=ContextLayer.L2,
                    source=ContextSource.REPO_INTELLIGENCE,
                    trust=ContextTrust.UNTRUSTED_REPO,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=680,
                    path=path,
                    sequence=sequence,
                )
            )
            sequence += 1
        for label, kind, values_to_add, trust, priority in (
            (
                "decision",
                ContextItemKind.DECISION,
                working_set.decisions,
                ContextTrust.UNTRUSTED_MODEL,
                760,
            ),
            (
                "hypothesis",
                ContextItemKind.HYPOTHESIS,
                working_set.hypotheses,
                ContextTrust.UNTRUSTED_MODEL,
                520,
            ),
            (
                "blocker",
                ContextItemKind.BLOCKER,
                working_set.open_questions,
                ContextTrust.TRUSTED_RUNTIME,
                900,
            ),
        ):
            for value in values_to_add[:64]:
                values.append(
                    ContextItem(
                        kind=kind,
                        payload=f"{label}: {value}",
                        layer=ContextLayer.L1,
                        source=ContextSource.RUNTIME,
                        trust=trust,
                        workspace_id=working_set.workspace_id,
                        generation=working_set.generation,
                        priority=priority,
                        required=kind is ContextItemKind.BLOCKER,
                        sequence=sequence,
                    )
                )
                sequence += 1
        if working_set.verification_state:
            values.append(
                ContextItem(
                    kind=ContextItemKind.VERIFICATION_SUMMARY,
                    payload=working_set.verification_state,
                    layer=ContextLayer.L1,
                    source=ContextSource.VERIFICATION,
                    trust=ContextTrust.UNTRUSTED_TOOL,
                    workspace_id=working_set.workspace_id,
                    generation=working_set.generation,
                    priority=820,
                    required=True,
                    sequence=sequence,
                )
            )
        return values

    async def rebalance_messages(
        self,
        messages: Sequence[object],
        *,
        requirements: ContextRequirements | None = None,
        scope_id: str = "parent",
    ) -> list[object]:
        """Re-select an accumulated turn without invoking legacy compression."""

        if requirements is None:
            requirements = ContextRequirements(
                task_id="",
                workspace_id="",
                recent_message_count=self.recent_message_count,
                budget=self.default_budget,
            )
        working_set = await self.get_working_set(
            task_id=requirements.task_id,
            workspace_id=requirements.workspace_id,
            scope_id=scope_id,
            generation=requirements.generation,
        )
        recent_start = max(0, len(messages) - requirements.recent_message_count)
        persistent_kinds = {
            ContextItemKind.GOAL,
            ContextItemKind.PROJECT_INSTRUCTION,
            ContextItemKind.PLAN,
            ContextItemKind.PLAN_STEP,
            ContextItemKind.TASK_STATE,
            ContextItemKind.EDIT_SUMMARY,
            ContextItemKind.FILE_REGION,
            ContextItemKind.SYMBOL,
            ContextItemKind.RELATION,
            ContextItemKind.DIAGNOSTIC,
        }
        candidates: list[ContextItem] = []
        for index, raw in enumerate(messages):
            role = str(getattr(raw, "role", "user"))
            metadata = getattr(raw, "metadata", {}) or {}
            metadata = metadata if isinstance(metadata, Mapping) else {}
            # Typed classifications are trusted only on messages emitted by
            # this engine.  Provider/user data may contain the same-looking
            # keys, but those keys are not an authority channel.
            typed_metadata = metadata.get("context_engine") is True and (
                isinstance(raw, ContextMessage)
                or getattr(raw, "_context_engine_message", False) is True
            )
            kind = (
                _enum_from_value(ContextItemKind, metadata.get("context_kind"))
                if typed_metadata
                else None
            )
            layer = (
                _enum_from_value(ContextLayer, metadata.get("context_layer"))
                if typed_metadata
                else None
            )
            source = (
                _enum_from_value(ContextSource, metadata.get("context_source"))
                if typed_metadata
                else None
            )
            trust = (
                _enum_from_value(ContextTrust, metadata.get("context_trust"))
                if typed_metadata
                else None
            )
            if role == "tool":
                layer = layer or ContextLayer.L3
                source = source or ContextSource.TOOL
                trust = trust or ContextTrust.UNTRUSTED_TOOL
                kind = kind or ContextItemKind.TOOL_RESULT
            elif getattr(raw, "event", None) in {
                "verification_result",
                "verification_unavailable",
                "verify_fix",
                "verify_fix_report",
            }:
                layer = layer or ContextLayer.L3
                source = source or ContextSource.VERIFICATION
                trust = trust or ContextTrust.UNTRUSTED_TOOL
                kind = kind or ContextItemKind.VERIFICATION_SUMMARY
            else:
                layer = layer or (ContextLayer.L0 if role == "system" and index == 0 else ContextLayer.L1)
                source = source or (
                    ContextSource.SYSTEM if layer is ContextLayer.L0 else ContextSource.RUNTIME
                )
                trust = trust or (
                    ContextTrust.TRUSTED_SYSTEM
                    if layer is ContextLayer.L0
                    else ContextTrust.TRUSTED_RUNTIME
                )
                kind = kind or (ContextItemKind.TASK_STATE if role == "system" else ContextItemKind.CONVERSATION)
            assert layer is not None and source is not None and trust is not None and kind is not None
            if index < recent_start and kind not in persistent_kinds and layer is not ContextLayer.L0:
                continue
            if (
                kind is ContextItemKind.DIAGNOSTIC
                and source is ContextSource.VERIFICATION
                and working_set.active_diagnostics
                and not any(value in str(getattr(raw, "content", "")) for value in working_set.active_diagnostics)
            ):
                continue
            if (
                kind is ContextItemKind.DIAGNOSTIC
                and source is ContextSource.VERIFICATION
                and not working_set.active_diagnostics
            ):
                continue
            required = (
                layer is ContextLayer.L0
                or kind in {
                    ContextItemKind.GOAL,
                    ContextItemKind.PLAN,
                    ContextItemKind.PLAN_STEP,
                    ContextItemKind.DIAGNOSTIC,
                    ContextItemKind.VERIFICATION_SUMMARY,
                    ContextItemKind.BLOCKER,
                }
                or index >= max(0, len(messages) - requirements.recent_message_count)
            )
            item = self._message_to_item(
                raw,
                layer=layer,
                source=source,
                trust=trust,
                kind=kind,
                priority=1000 if layer is ContextLayer.L0 else 100 + index,
                sequence=index,
                required=required,
                workspace_id=requirements.workspace_id,
                generation=requirements.generation,
            )
            if item is not None:
                candidates.append(item)
        if len(messages) > requirements.recent_message_count:
            summary = working_set.summary()
            candidates.append(
                ContextItem(
                    kind=ContextItemKind.TASK_STATE,
                    payload=summary.to_text(),
                    layer=ContextLayer.L1,
                    source=ContextSource.RUNTIME,
                    trust=ContextTrust.UNTRUSTED_MODEL,
                    workspace_id=requirements.workspace_id,
                    generation=requirements.generation,
                    priority=800,
                    required=True,
                    sequence=1,
                    metadata={"role": "user", "context_layer": "L1"},
                )
            )
            self._inc("context_compactions")
        context = await self.build(requirements, candidates, scope_id=scope_id)
        if len(context.selection.evicted) or context.selection.compressed:
            self._inc("context_compactions")
        return [self._to_agent_message(message) for message in context.messages]

    async def build_child_context(
        self,
        parent_messages: Sequence[object],
        *,
        task_id: str,
        workspace_id: str,
        generation: str | None = None,
        budget: ContextBudget | None = None,
        scope_id: str = "child",
    ) -> ModelContext:
        """Return a bounded parent-to-child projection; no worktree merge."""

        requirements = ContextRequirements(
            operation=ContextOperation.GENERAL,
            task_id=task_id,
            workspace_id=workspace_id,
            generation=generation,
            recent_message_count=8,
            budget=budget or ContextBudget(
                total_tokens=6_000,
                total_bytes=128 * 1024,
                output_reserve_tokens=1_024,
                output_reserve_bytes=16 * 1024,
                layer_token_budgets=(1_024, 2_048, 2_560, 1_000),
                layer_byte_budgets=(24 * 1024, 40 * 1024, 48 * 1024, 16 * 1024),
            ),
        )
        candidates = [
            item
            for index, message in enumerate(parent_messages)
            if (item := self._message_to_item(
                message,
                layer=ContextLayer.L1 if index else ContextLayer.L0,
                source=ContextSource.RUNTIME,
                trust=ContextTrust.TRUSTED_RUNTIME,
                kind=ContextItemKind.CONVERSATION,
                priority=500 if index else 1000,
                sequence=index,
                required=index == 0,
                workspace_id=workspace_id,
                generation=generation,
            )) is not None
        ]
        return await self.build(requirements, candidates, scope_id=scope_id)

    def tool_schemas(
        self,
        *,
        mode: str,
        intent: str = "",
        allowlist: Iterable[str] | None = None,
    ) -> list[dict[str, object]] | None:
        """Return visibility-filtered schemas; authority stays in the registry."""

        if self.tool_registry is None:
            return None
        discovery = DeferredToolDiscovery(self.tool_registry, mode=mode)
        result = discovery.discover(intent=intent, allowlist=allowlist)
        self._inc("deferred_tool_discoveries", result.deferred_count)
        schemas: list[dict[str, object]] = []
        for definition in result.definitions:
            schema = {
                "type": "function",
                "function": {
                    "name": getattr(definition, "name", ""),
                    "description": getattr(definition, "description", ""),
                    "parameters": getattr(definition, "parameters", {}),
                },
            }
            schemas.append(schema)
        try:
            encoded = json.dumps(schemas, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            self._set("tool_schema_bytes", len(encoded.encode("utf-8")))
            self._set("tool_schema_tokens", approximate_token_count(encoded))
        except (TypeError, ValueError):
            self._set("tool_schema_bytes", None)
            self._set("tool_schema_tokens", None)
        return schemas or None

    def discover_skill_metadata(self, mode: str, user_text: str) -> tuple[object, ...]:
        discovery = LazySkillDiscovery(self.skill_manager)
        result = discovery.discover(mode, user_text)
        self._inc("deferred_skill_discoveries", len(result))
        return result

    def skill_prompt(self, mode: str, user_text: str) -> str:
        """Load selected skill bodies only after bounded metadata matching."""

        metadata = self.discover_skill_metadata(mode, user_text)
        manager = self.skill_manager
        if manager is None or not metadata:
            return ""
        skills = [
            skill
            for skill in (self.load_skill(str(getattr(item, "name", ""))) for item in metadata)
            if skill is not None
        ]
        formatter = getattr(manager, "format_for_prompt", None)
        if not callable(formatter):
            return ""
        return str(formatter(skills) or "")

    def load_skill(self, name: str) -> object | None:
        skill = LazySkillDiscovery(self.skill_manager).load_full(name)
        if skill is not None:
            self._inc("deferred_skill_loads")
            body = str(getattr(skill, "body", ""))
            self._inc("skill_tokens", approximate_token_count(body))
        return skill

    def bound_tool_result(self, result: object) -> ToolOutputEnvelope:
        envelope = self.tool_output_policy.envelope(result)
        visible = envelope.to_json(max_bytes=self.tool_output_policy.limits.max_bytes)
        self._inc("tool_output_tokens", approximate_token_count(visible))
        self._inc("tool_output_bytes", len(visible.encode("utf-8")))
        if envelope.truncated:
            self._inc("tool_output_truncated_count")
        return envelope

    async def observe_event(
        self,
        task_id: str,
        event: WorkingSetEvent | str | Mapping[str, object],
        payload: Mapping[str, object] | None = None,
        *,
        workspace_id: str = "",
        scope_id: str = "parent",
        goal: str = "",
        generation: str | None = None,
    ) -> TaskWorkingSet:
        """Apply a runtime event with per-task copy-on-write serialization."""

        key = (task_id, workspace_id, scope_id)
        lock = self._lock_for(key)
        async with lock:
            current = await self.get_working_set(
                task_id=task_id,
                workspace_id=workspace_id,
                scope_id=scope_id,
                goal=goal,
                generation=generation,
            )
            event_payload: dict[str, object] = dict(payload or {})
            event_kind: str | None = None
            event_sequence = 0
            if isinstance(event, WorkingSetEvent):
                event_kind = event.kind
                event_sequence = event.sequence
                event_payload = {**dict(event.payload), **event_payload}
            elif isinstance(event, Mapping):
                event_kind = str(event.get("kind") or event.get("event") or "unknown")
                raw_sequence = event.get("sequence", 0)
                event_sequence = raw_sequence if type(raw_sequence) is int else 0
                raw_nested = event.get("payload")
                if isinstance(raw_nested, Mapping):
                    event_payload = {**dict(raw_nested), **event_payload}
            else:
                event_kind = event
            # The scoped arguments are the caller's current runtime binding;
            # they override stale fields that may have travelled with an old
            # diagnostic/result payload.
            if workspace_id:
                event_payload["workspace_id"] = workspace_id
            if generation is not None:
                event_payload["generation"] = generation
            observed_event = WorkingSetEvent(
                kind=event_kind,
                payload=event_payload,
                sequence=event_sequence,
            )
            updated = current.apply_event(observed_event)
            self.working_set_store.put(key, updated)
            await self._persist_working_set(updated)
            self.cache.invalidate(task_id=task_id, workspace_id=workspace_id, scope_id=scope_id)
            return updated

    async def get_working_set(
        self,
        *,
        task_id: str,
        workspace_id: str = "",
        scope_id: str = "parent",
        goal: str = "",
        generation: str | None = None,
    ) -> TaskWorkingSet:
        generation = _normalize_generation(generation, label="generation")
        key = (task_id, workspace_id, scope_id)
        value = self.working_set_store.get(key)
        if value is None:
            value = await self._load_persisted_working_set(task_id, scope_id=scope_id)
        if value is not None and value.workspace_id not in {"", workspace_id}:
            value = None
        if value is not None and value.principal_id not in {"", self.principal_id}:
            value = None
        if value is not None and value.project_id not in {"", self.project_id}:
            value = None
        if value is not None and value.workspace_id == "" and workspace_id:
            value = replace(value, workspace_id=workspace_id)
        if value is not None and generation is not None and value.generation != generation:
            # M8.1 uses ``<workspace epoch>:<manifest digest>`` as its
            # repository-generation identity, while edit/verification events
            # can arrive between the mutation and the next fresh bundle with
            # only the new workspace epoch.  That narrow pending-generation
            # form is safe to rebind; a full old generation is never treated
            # as compatible merely because its epoch happens to match.
            if _pending_generation_matches(value.generation, generation):
                value = replace(
                    value,
                    generation=generation,
                    items=tuple(
                        replace(item, generation=generation)
                        for item in value.items
                    ),
                )
            else:
                # Restart recovery retains task-level control summaries but
                # never reuses source/diagnostic evidence from the previous
                # workspace generation.
                value = replace(
                    value,
                    generation=generation,
                    active_diagnostics=(),
                    verification_state=None,
                    items=tuple(
                        item
                        for item in value.items
                        if item.generation in (None, generation)
                        or item.kind
                        in {
                            ContextItemKind.GOAL,
                            ContextItemKind.PLAN,
                            ContextItemKind.PLAN_STEP,
                            ContextItemKind.DECISION,
                            ContextItemKind.HYPOTHESIS,
                            ContextItemKind.BLOCKER,
                        }
                    ),
                )
        if value is None:
            value = TaskWorkingSet.empty(
                task_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                workspace_id=workspace_id,
                goal=goal,
                generation=generation,
            )
        self.working_set_store.put(key, value)
        return value

    def metrics_snapshot(self) -> ContextMetricsSnapshot:
        with self._metrics_guard():
            values = dict(self._metrics)
        # The public snapshot has a deliberately mixed int/None vocabulary,
        # while the internal counters are initialized as integers and a few
        # optional measurements may be set to None at runtime.  Keep the
        # conversion at this single boundary instead of weakening the typed
        # snapshot contract for every caller.
        snapshot_type = cast(Any, ContextMetricsSnapshot)
        return cast(ContextMetricsSnapshot, snapshot_type(**values))

    def clear_cache(self) -> None:
        self.cache.clear()

    def _working_set_changed(
        self,
        key: tuple[str, str, str],
        snapshot_digest: str | None,
    ) -> bool:
        current = self.working_set_store.get(key)
        current_digest = current.digest if current is not None else None
        return current_digest != snapshot_digest

    @staticmethod
    def items_from_repo_bundle(
        bundle: object,
        *,
        requirements: ContextRequirements | None = None,
    ) -> list[ContextItem]:
        """Project M8.1 typed evidence into final-selector candidates."""

        values: list[ContextItem] = []
        workspace_id = str(getattr(bundle, "workspace_id", ""))
        generation = str(getattr(bundle, "repository_generation", "") or "") or None
        sequence = 2000
        for document in tuple(getattr(bundle, "documents", ()) or ()):
            path = str(getattr(document, "relative_path", ""))
            content = str(getattr(document, "content", ""))
            if not path:
                continue
            values.append(
                ContextItem(
                    kind=ContextItemKind.FILE_REGION,
                    payload=f"# {path}\n{content}",
                    layer=ContextLayer.L2,
                    source=ContextSource.REPO_INTELLIGENCE,
                    trust=ContextTrust.UNTRUSTED_REPO,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=500 + int(getattr(document, "relevance_score", 0) or 0),
                    path=path,
                    region_start=int(getattr(document, "excerpt_start", 0) or 0),
                    region_end=int(getattr(document, "excerpt_end", 0) or 0),
                    digest=str(getattr(document, "content_digest", "") or ""),
                    truncated=bool(getattr(document, "truncated", False)),
                    sequence=sequence,
                    metadata={
                        "role": "user",
                        "context_layer": "L2",
                        "content_digest": str(getattr(document, "content_digest", "") or ""),
                        "repository_id": str(getattr(document, "repository_id", "") or ""),
                        "index_generation": str(getattr(document, "index_generation", "") or ""),
                    },
                )
            )
            sequence += 1
        for symbol in tuple(getattr(bundle, "symbols", ()) or ()):
            name = str(getattr(symbol, "qualified_name", ""))
            path = str(getattr(symbol, "relative_path", ""))
            if not name or not path:
                continue
            values.append(
                ContextItem(
                    kind=ContextItemKind.SYMBOL,
                    payload=(
                        f"{name} ({getattr(symbol, 'kind', 'symbol')}) "
                        f"at {path}:{getattr(symbol, 'start_line', 0)}-"
                        f"{getattr(symbol, 'end_line', 0)}"
                    ),
                    layer=ContextLayer.L2,
                    source=ContextSource.REPO_INTELLIGENCE,
                    trust=ContextTrust.UNTRUSTED_REPO,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=450,
                    digest=str(getattr(symbol, "content_digest", "") or ""),
                    path=path,
                    symbol=name,
                    region_start=int(getattr(symbol, "start_line", 0) or 0),
                    region_end=int(getattr(symbol, "end_line", 0) or 0),
                    sequence=sequence,
                    metadata={
                        "role": "user",
                        "context_layer": "L2",
                        "content_digest": str(getattr(symbol, "content_digest", "") or ""),
                        "index_generation": str(getattr(symbol, "index_generation", "") or ""),
                    },
                )
            )
            sequence += 1
        for evidence in tuple(getattr(bundle, "evidence", ()) or ()):
            subject = str(getattr(evidence, "subject_path", "") or "")
            evidence_kind = getattr(evidence, "kind", "relation")
            description = str(getattr(evidence_kind, "value", evidence_kind))
            if not subject:
                continue
            values.append(
                ContextItem(
                    kind=ContextItemKind.RELATION,
                    payload=f"{description}: {subject}",
                    layer=ContextLayer.L2,
                    source=ContextSource.REPO_INTELLIGENCE,
                    trust=ContextTrust.UNTRUSTED_REPO,
                    workspace_id=workspace_id,
                    generation=generation,
                    priority=350,
                    digest=str(getattr(evidence, "digest", "") or ""),
                    path=subject,
                    sequence=sequence,
                    metadata={
                        "role": "user",
                        "context_layer": "L2",
                        "evidence_ref_id": str(getattr(evidence, "ref_id", "") or ""),
                    },
                )
            )
            sequence += 1
        structure = getattr(bundle, "structure_paths", None)
        if not structure:
            # Keep compatibility with early development bundles while using
            # the canonical M8.1 field on the normal path.
            structure = getattr(bundle, "structure", ()) or ()
        if structure:
            structure_values: list[str] = []
            structure_items = tuple(structure)[:512]
            try:
                structure_values = sorted(
                    {
                        str(path)
                        for path in structure_items
                        if isinstance(path, str) and path
                    }
                )
                max_structure_bytes = 32 * 1024
                while structure_values and len(
                    json.dumps(
                        structure_values,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ) > max_structure_bytes:
                    structure_values.pop()
                structure_text = json.dumps(
                    structure_values,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            except (TypeError, ValueError):
                structure_text = ""
            if structure_text:
                values.append(
                    ContextItem(
                        kind=ContextItemKind.RELATION,
                        payload=f"repository_structure: {structure_text}",
                        layer=ContextLayer.L2,
                        source=ContextSource.REPO_INTELLIGENCE,
                        trust=ContextTrust.UNTRUSTED_REPO,
                        workspace_id=workspace_id,
                        generation=generation,
                        priority=300,
                        sequence=sequence,
                        truncated=len(structure_values) < len(structure_items),
                        metadata={"role": "user", "context_layer": "L2"},
                    )
                )
        return values

    def _filter_generation(
        self,
        values: list[ContextItem],
        generation: str | None,
    ) -> tuple[list[ContextItem], bool]:
        if not generation:
            return values, False
        stale = [item for item in values if item.generation not in (None, generation)]
        if not stale:
            return values, False
        self._inc("context_stale_retries")
        return [item for item in values if item not in stale], True

    @staticmethod
    def _filter_workspace(
        values: list[ContextItem], workspace_id: str
    ) -> tuple[list[ContextItem], bool]:
        """Drop workspace-bound candidates from another or missing scope."""

        if not workspace_id:
            stale = [item for item in values if item.workspace_id]
            return [item for item in values if not item.workspace_id], bool(stale)
        stale = [
            item
            for item in values
            if item.workspace_id != workspace_id
            and (
                item.workspace_id
                or item.source
                in {
                    ContextSource.REPO_INTELLIGENCE,
                    ContextSource.EDIT_TRANSACTION,
                    ContextSource.VERIFICATION,
                }
            )
        ]
        return [item for item in values if item not in stale], bool(stale)

    async def _resolve_instructions(self, target_path: str | Path | None) -> str:
        resolver = self.instruction_resolver
        if resolver is None:
            return ""
        resolve = getattr(resolver, "resolve", None)
        if not callable(resolve):
            return ""
        try:
            value = await asyncio.to_thread(resolve, target_path)
            if inspect.isawaitable(value):
                value = await value
            return str(value or "")
        except Exception:  # noqa: BLE001 - instruction projection is fail-closed
            return ""

    @staticmethod
    def _message_to_item(
        message: object | None,
        *,
        layer: ContextLayer,
        source: ContextSource,
        trust: ContextTrust,
        kind: ContextItemKind,
        priority: int,
        sequence: int,
        required: bool,
        workspace_id: str = "",
        generation: str | None = None,
    ) -> ContextItem | None:
        if message is None:
            return None
        content = str(getattr(message, "content", message) or "")
        if not content and kind not in {ContextItemKind.CONVERSATION, ContextItemKind.TOOL_RESULT}:
            return None
        metadata = getattr(message, "metadata", {}) or {}
        safe_metadata: dict[str, object] = {}
        if isinstance(metadata, Mapping):
            for key in (
                "context_engine",
                "context_layer",
                "trusted",
                "authority",
                "name",
                "success",
                "error_code",
                "role",
            ):
                if key in metadata and isinstance(metadata[key], (str, bool, int, float)):
                    safe_metadata[key] = metadata[key]
        role = str(getattr(message, "role", safe_metadata.get("role", "user")))
        safe_metadata["role"] = role if role in {"system", "user", "assistant", "tool"} else "user"
        tool_call_id = getattr(message, "tool_call_id", None)
        if tool_call_id:
            safe_metadata["tool_call_id"] = str(tool_call_id)[:256]
        event = getattr(message, "event", None)
        if event:
            safe_metadata["event"] = str(event)[:256]
        calls = getattr(message, "tool_calls", ()) or ()
        if calls:
            bounded_calls: list[dict[str, object]] = []
            for call in list(calls)[:16]:
                if isinstance(call, Mapping):
                    try:
                        encoded = json.dumps(call, ensure_ascii=False, sort_keys=True)
                    except (TypeError, ValueError):
                        continue
                    if len(encoded.encode("utf-8")) <= 16 * 1024:
                        bounded_calls.append(dict(call))
            if bounded_calls:
                safe_metadata["tool_calls"] = bounded_calls
        candidate_workspace = metadata.get("context_workspace_id")
        if isinstance(candidate_workspace, str):
            workspace_id = candidate_workspace
        candidate_generation = metadata.get(
            "context_generation",
            metadata.get("generation", metadata.get("repository_generation")),
        )
        if type(candidate_generation) in {str, int}:
            generation = str(candidate_generation)
        content = _strip_context_wrapper(content, trust)
        return ContextItem(
            kind=kind,
            payload=content,
            layer=layer,
            source=source,
            trust=trust,
            workspace_id=workspace_id,
            generation=generation,
            priority=max(0, min(1000, priority)),
            required=required,
            sequence=sequence,
            metadata=safe_metadata,
        )

    @staticmethod
    def _to_agent_message(message: ContextMessage) -> object:
        # Delayed import prevents the coding context package from entering
        # native launcher import paths at module import time.
        from khaos.agent.core import Message

        result = Message(
            role=message.role,
            content=message.content,
            tool_calls=[dict(call) for call in message.tool_calls],
            tool_call_id=message.tool_call_id,
            token_count=max(0, len(message.content.split())),
            event=message.event,
            metadata=dict(message.metadata),
        )
        # This in-memory marker is deliberately not serialized into prompt or
        # durable metadata.  It lets the same-process AgentLoop preserve the
        # engine's typed classification while a reloaded/provider-originated
        # message must be classified conservatively from role/event.
        setattr(result, "_context_engine_message", True)  # noqa: B010 - private provenance marker
        return result

    def _record_build(self, context: ModelContext, prefix_tokens: int, prefix_bytes: int) -> None:
        selection = context.selection
        self._inc("context_builds")
        self._inc("context_input_tokens", selection.total_tokens)
        self._inc("context_input_bytes", selection.total_bytes)
        self._inc("context_items_selected", len(selection.selected))
        self._inc("context_items_evicted", len(selection.evicted))
        self._inc("context_items_compressed", len(selection.compressed))
        self._inc("context_truncated_count", selection.truncated_count)
        self._inc("context_stable_prefix_tokens", prefix_tokens)
        self._inc("context_stable_prefix_bytes", prefix_bytes)
        for layer in ContextLayer:
            self._inc(f"context_{layer.value.casefold()}_tokens", selection.layer_tokens.get(layer.value, 0))
        self._inc("context_selected_file_count", sum(1 for item in selection.selected if item.path))
        self._inc("context_selected_symbol_count", sum(1 for item in selection.selected if item.kind is ContextItemKind.SYMBOL))
        self._inc("context_memory_items_selected", sum(1 for item in selection.selected if item.kind is ContextItemKind.MEMORY))
        self._inc("context_repo_items_selected", sum(1 for item in selection.selected if item.source is ContextSource.REPO_INTELLIGENCE))
        self._inc("context_diagnostics_selected", sum(1 for item in selection.selected if item.kind is ContextItemKind.DIAGNOSTIC))
        if context.partial:
            self._inc("context_partial_builds")

    def _lock_for(self, key: tuple[str, str, str]) -> asyncio.Lock:
        with self._locks_guard:
            return self._locks.setdefault(key, asyncio.Lock())

    async def _load_persisted_working_set(
        self, task_id: str, *, scope_id: str = "parent"
    ) -> TaskWorkingSet | None:
        manager = self.task_manager
        getter = getattr(manager, "get", None)
        if scope_id != "parent" or not task_id or not callable(getter):
            return None
        try:
            task = getter(task_id)
            if inspect.isawaitable(task):
                task = await task
            metadata = getattr(task, "metadata", {}) if task is not None else {}
            raw = metadata.get(WORKING_SET_METADATA_KEY) if isinstance(metadata, Mapping) else None
            if isinstance(raw, Mapping):
                return TaskWorkingSet.from_payload(raw)
        except Exception:  # noqa: BLE001 - corrupted optional projection is not authority
            return None
        return None

    async def _persist_working_set(self, value: TaskWorkingSet) -> None:
        manager = self.task_manager
        getter = getattr(manager, "get", None)
        updater = getattr(manager, "update_status", None)
        if not value.task_id or not callable(getter) or not callable(updater):
            return
        try:
            task = getter(value.task_id)
            if inspect.isawaitable(task):
                task = await task
            if task is None:
                return
            status = getattr(task, "status", None)
            awaitable = updater(
                value.task_id,
                status,
                **{WORKING_SET_METADATA_KEY: value.to_payload()},
            )
            if inspect.isawaitable(awaitable):
                await awaitable
        except Exception:  # noqa: BLE001 - observability persistence is non-fatal
            return

    def _inc(self, name: str, amount: int = 1) -> None:
        with self._metrics_guard():
            current = self._metrics.get(name)
            if current is None:
                return
            self._metrics[name] = current + amount

    def _set(self, name: str, value: int | None) -> None:
        with self._metrics_guard():
            self._metrics[name] = value

    def _metrics_guard(self) -> RLock:
        # The metrics dictionary is only mutated under the same lock used by
        # snapshots.  Keeping this helper makes the boundary obvious and
        # avoids exposing a mutable metrics object to callers.
        if not hasattr(self, "_metrics_lock"):
            self._metrics_lock = RLock()
        return self._metrics_lock


def _enum_from_value(
    enum_type: type[_ContextEnum], value: object
) -> _ContextEnum | None:
    """Parse a serialized enum without trusting arbitrary metadata."""

    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        return None
    try:
        return enum_type(value)
    except ValueError:
        try:
            return enum_type[value]
        except (KeyError, TypeError):
            return None


def _pending_generation_matches(
    observed_generation: str | None,
    repository_generation: str,
) -> bool:
    """Recognize only the post-edit epoch awaiting a fresh M8.1 digest."""

    if not observed_generation or ":" in observed_generation or ":" not in repository_generation:
        return False
    epoch, _separator, _manifest = repository_generation.partition(":")
    return bool(epoch) and observed_generation == epoch


def _strip_context_wrapper(content: str, trust: ContextTrust) -> str:
    """Make repeated AgentLoop rebalancing idempotent."""

    wrapper = {
        ContextTrust.UNTRUSTED_REPO: "untrusted_repo_context",
        ContextTrust.UNTRUSTED_TOOL: "untrusted_tool_output",
        ContextTrust.UNTRUSTED_MEMORY: "untrusted_memory",
        ContextTrust.UNTRUSTED_MODEL: "untrusted_model_observation",
    }.get(trust)
    if wrapper is None:
        if not content.startswith("<project_instructions "):
            return content
        wrapper = "project_instructions"
    opening_end = content.find("\n")
    closing = f"</{wrapper}>"
    if opening_end < 0 or not content.endswith(closing):
        return content
    return content[opening_end + 1 : -len(closing)].rstrip("\n")
