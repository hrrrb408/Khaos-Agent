"""Bounded, dependency-free proactive memory extraction rules."""

from __future__ import annotations

import re
from typing import Any

from khaos.memory.core.contracts import (
    EvidenceRef,
    MemoryAuthority,
    MemoryCandidate,
    MemoryEvent,
    MemoryEventType,
    MemoryType,
    Sensitivity,
    SourceType,
    UsagePolicy,
)
from khaos.memory.models import Memory, MemoryConfidence, MemoryScope

# Patterns are intentionally small and explicit.  They produce candidates only;
# conflict resolution and persistence remain the store's responsibility.
_EXTRACTION_RULES: tuple[tuple[re.Pattern[str], MemoryScope, str], ...] = (
    (
        re.compile(
            r"(?:我叫|我的名字是|我是)\s*([^\s,，。.!！?？]{1,30})",
            re.IGNORECASE,
        ),
        MemoryScope.GLOBAL,
        "user_name",
    ),
    (
        re.compile(r"my name is ([A-Za-z][\w\- ]{0,30})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "user_name",
    ),
    (
        re.compile(
            r"我(?:喜欢|偏好|倾向于)\s*([^\s,，。.!！?？]{1,40})",
            re.IGNORECASE,
        ),
        MemoryScope.GLOBAL,
        "preference",
    ),
    (
        re.compile(r"i (?:like|prefer) ([a-z0-9 \-]{2,40})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "preference",
    ),
    (
        re.compile(r"记住[：:\s]*([^\n]{2,80})"),
        MemoryScope.GLOBAL,
        "note",
    ),
    (
        re.compile(r"remember (?:that )?(.{2,80})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "note",
    ),
)


def extract_memories_from_text(
    text: str,
    scope: MemoryScope = MemoryScope.GLOBAL,
) -> list[Memory]:
    """Scan free text for declarative memory signals."""

    if not text:
        return []
    found: list[Memory] = []
    seen: set[tuple[MemoryScope, str]] = set()
    for pattern, rule_scope, key_base in _EXTRACTION_RULES:
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            if not value:
                continue
            key = (
                key_base
                if key_base in {"user_name", "note"}
                else f"{key_base}:{value.lower()}"
            )
            identity = (rule_scope, key)
            if identity in seen:
                continue
            seen.add(identity)
            found.append(
                Memory(
                    id=None,
                    scope=scope if scope != MemoryScope.GLOBAL else rule_scope,
                    key=key,
                    value=value,
                    confidence=MemoryConfidence.MEDIUM,
                )
            )
    return found


def extract_memories_from_messages(
    messages: list[Any],
    scope: MemoryScope = MemoryScope.GLOBAL,
) -> list[Memory]:
    """Extract candidates only from user-role messages."""

    extracted: list[Memory] = []
    for message in messages:
        if _get(message, "role") != "user":
            continue
        content = _get(message, "content") or ""
        extracted.extend(extract_memories_from_text(str(content), scope))
    return extracted


def extract_candidates_from_event(
    event: MemoryEvent,
    *,
    profile: Any = None,
) -> tuple[MemoryCandidate, ...]:
    """Create deterministic, evidence-bound candidates from durable events.

    This is intentionally conservative: the function never infers a system
    policy or a verification receipt.  A language-model extractor may add
    candidates later, but it cannot bypass the same Broker admission path.
    """

    payload = dict(event.payload)
    event_type = str(event.event_type.value if isinstance(event.event_type, MemoryEventType) else event.event_type)
    evidence_type = _event_source_type(event_type)
    evidence = EvidenceRef(evidence_type, f"event:{event.event_id}", event_id=event.event_id)
    mode = payload.get("mode")
    preconditions = {"mode": mode} if isinstance(mode, str) and mode else {}
    if event_type == MemoryEventType.USER_MESSAGE.value:
        if getattr(profile, "user_profile", "light") == "none":
            return ()
        content = str(payload.get("content", ""))
        memories = extract_memories_from_text(content)
        return tuple(
            MemoryCandidate(
                memory_type=MemoryType.USER_MEMORY,
                claim=memory.value,
                key=memory.key,
                scope=memory.scope.value,
                namespace="private",
                authority=MemoryAuthority.USER_STATED,
                confidence=memory.confidence.value / 3.0,
                source_event_ids=(event.event_id,),
                evidence_refs=(evidence,),
                preconditions=preconditions,
                sensitivity=Sensitivity.PERSONAL,
                usage_policy=UsagePolicy.PROJECT_ONLY,
            )
            for memory in memories
        )
    if event_type == MemoryEventType.TOOL_RESULT.value:
        if payload.get("success", payload.get("ok", True)) is not False:
            return ()
        error = str(payload.get("error", payload.get("message", "tool failure")))[:4096]
        if not error:
            return ()
        return (
            MemoryCandidate(
                memory_type=MemoryType.FAILURE_MEMORY,
                claim=f"Tool failure: {error}",
                key=f"failure:{payload.get('tool_name', 'tool')}",
                scope="coding",
                namespace="project",
                authority=MemoryAuthority.TOOL_OBSERVED,
                confidence=0.65,
                source_event_ids=(event.event_id,),
                evidence_refs=(evidence,),
                preconditions=preconditions,
                usage_policy=UsagePolicy.PROJECT_ONLY,
            ),
        ) if getattr(profile, "failure_memory", True) else ()
    if event_type in {
        MemoryEventType.TASK_TRANSITION.value,
        MemoryEventType.PLAN_CREATED.value,
    }:
        rationale = payload.get("rationale", payload.get("decision", payload.get("plan")))
        if not isinstance(rationale, str) or not rationale.strip():
            return ()
        if getattr(profile, "decision_memory", True) is False:
            return ()
        return (
            MemoryCandidate(
                memory_type=MemoryType.DECISION_MEMORY,
                claim=rationale[:64 * 1024],
                key=f"decision:{payload.get('task_id', event.task_id or 'task')}",
                scope="coding",
                namespace="project",
                authority=MemoryAuthority.TOOL_OBSERVED,
                confidence=0.6,
                source_event_ids=(event.event_id,),
                evidence_refs=(evidence,),
                preconditions=preconditions,
                usage_policy=UsagePolicy.PROJECT_ONLY,
            ),
        )
    if event_type == MemoryEventType.APPROVAL_DECIDED.value:
        decision = str(payload.get("decision", payload.get("status", "")))
        if not decision:
            return ()
        return (
            MemoryCandidate(
                memory_type=MemoryType.CONSTRAINT_MEMORY,
                claim=f"Approval decision: {decision[:2048]}",
                key=f"approval:{payload.get('tool_name', event.event_id)}",
                scope="coding",
                namespace="project",
                authority=MemoryAuthority.TOOL_OBSERVED,
                confidence=0.7,
                source_event_ids=(event.event_id,),
                evidence_refs=(evidence,),
                preconditions=preconditions,
                usage_policy=UsagePolicy.PROJECT_ONLY,
            ),
        ) if getattr(profile, "constraint_memory", True) else ()
    return ()


def _event_source_type(event_type: str) -> SourceType:
    if event_type == MemoryEventType.USER_MESSAGE.value:
        return SourceType.USER
    if event_type in {
        MemoryEventType.TOOL_RESULT.value,
        MemoryEventType.TOOL_CALL.value,
        MemoryEventType.TASK_TRANSITION.value,
        MemoryEventType.PLAN_CREATED.value,
        MemoryEventType.APPROVAL_DECIDED.value,
    }:
        return SourceType.TOOL
    if event_type == MemoryEventType.VERIFICATION_RESULT.value:
        return SourceType.VERIFICATION
    return SourceType.SYSTEM


def _get(obj: Any, attr: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr)
    return getattr(obj, attr, None)


__all__ = [
    "extract_candidates_from_event",
    "extract_memories_from_messages",
    "extract_memories_from_text",
]
