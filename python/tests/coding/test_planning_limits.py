"""Contract tests for the named planning budget boundary."""

from __future__ import annotations

import pytest
from khaos.coding.planning.limits import PlanningLimits


def test_planning_limits_are_named_and_override_only_explicit_values() -> None:
    limits = PlanningLimits(max_nodes=10)
    overridden = limits.override(max_depth=1, max_nodes=None)

    assert overridden.max_depth == 1
    assert overridden.max_nodes == 10
    assert overridden.max_edges == 500


def test_planning_limits_reject_unknown_or_negative_values() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        PlanningLimits(max_nodes=-1)
    with pytest.raises(ValueError, match="unknown"):
        PlanningLimits().override(max_budget=1)
