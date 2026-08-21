"""Immutable function-to-model routing table."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class RoutingRule:
    """Mapping from one function key to a primary and fallback chain."""

    function: str
    primary_model: str
    fallback_models: tuple[str, ...] = ()
    prefer_coding_model: bool = False

    def __post_init__(self) -> None:
        if not self.function:
            raise ValueError("routing rule function is required")
        if not self.primary_model:
            raise ValueError("routing rule primary model is required")
        object.__setattr__(self, "fallback_models", tuple(self.fallback_models))


@dataclass(frozen=True, slots=True)
class RoutingTable:
    """Atomically replaceable immutable routing state."""

    rules: Mapping[str, RoutingRule]

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", MappingProxyType(dict(self.rules)))

    @classmethod
    def empty(cls) -> RoutingTable:
        return cls({})

    def get(self, function: str) -> RoutingRule | None:
        return self.rules.get(function)

    def with_rule(self, function: str, rule: RoutingRule) -> RoutingTable:
        if function != rule.function:
            raise ValueError("routing rule function does not match its table key")
        updated = dict(self.rules)
        updated[function] = rule
        return RoutingTable(updated)


__all__ = ["RoutingRule", "RoutingTable"]
