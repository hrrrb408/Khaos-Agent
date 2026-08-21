"""Bounded, dependency-free proactive memory extraction rules."""

from __future__ import annotations

import re
from typing import Any

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


def _get(obj: Any, attr: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr)
    return getattr(obj, attr, None)


__all__ = [
    "extract_memories_from_messages",
    "extract_memories_from_text",
]
