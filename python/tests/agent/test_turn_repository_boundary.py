"""Structural tests for the agent turn persistence boundary."""

from __future__ import annotations

import inspect

from khaos.agent.events import TurnCoordinator
from khaos.agent.turn_repository import DatabaseTurnRepository, TurnRepository


def test_turn_coordinator_accepts_repository_not_database():
    """The state machine must expose only its narrow persistence port."""
    parameters = inspect.signature(TurnCoordinator.start).parameters
    assert "repository" in parameters
    assert "db" not in parameters
    assert "repository" in inspect.signature(TurnCoordinator).parameters


def test_sqlite_adapter_is_the_only_database_bridge():
    """The concrete adapter implements every operation required by the port."""
    for name in (
        "start_agent_turn",
        "append_agent_turn_event",
        "recover_inflight_agent_turns",
    ):
        assert callable(getattr(DatabaseTurnRepository, name))
        assert callable(getattr(TurnRepository, name))
