"""Immutable traversal limits shared by planning and verification selection."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True, slots=True)
class PlanningLimits:
    """Named, validated limits for one deterministic planning request."""

    max_depth: int = 3
    max_nodes: int = 200
    max_files: int = 100
    max_symbols: int = 100
    max_edges: int = 500
    max_reverse_imports: int = 50
    max_test_candidates: int = 50

    def __post_init__(self) -> None:
        for name, value in self.as_dict().items():
            if type(value) is not int or value < 0:
                raise ValueError(f"planning limit {name} must be a non-negative integer")

    def override(self, **values: int | None) -> PlanningLimits:
        """Return a copy with only explicitly supplied limits replaced."""
        allowed = set(self.as_dict())
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unknown planning limits: {sorted(unknown)}")
        return replace(
            self,
            **{
                name: value
                for name, value in values.items()
                if value is not None
            },
        )

    def as_dict(self) -> dict[str, int]:
        """Return keyword arguments for ``ImpactTraversalBudget``."""
        return {
            "max_depth": self.max_depth,
            "max_nodes": self.max_nodes,
            "max_files": self.max_files,
            "max_symbols": self.max_symbols,
            "max_edges": self.max_edges,
            "max_reverse_imports": self.max_reverse_imports,
            "max_test_candidates": self.max_test_candidates,
        }


__all__ = ["PlanningLimits"]
