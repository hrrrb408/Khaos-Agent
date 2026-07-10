"""Tests for cron tool definitions and schedule parsing."""

from __future__ import annotations

from khaos.tools.cron_tools import CRON_TOOLS, _parse_schedule
from khaos.tools.registry import create_runtime_registry


def test_cron_tools_definitions() -> None:
    """All 5 cron tools are declared and registered with handlers."""
    names = {spec["name"] for spec in CRON_TOOLS}
    assert names == {"cron_create", "cron_list", "cron_remove", "cron_pause", "cron_resume"}

    registry = create_runtime_registry()
    for name in names:
        tool = registry.get(name)
        assert tool.handler is not None, f"{name} has no handler"


def test_parse_schedule_cron() -> None:
    config = _parse_schedule("0 9")
    assert config.cron == "0 9"
    assert config.iso_time is None
    assert config.interval_seconds is None


def test_parse_schedule_interval_minutes() -> None:
    config = _parse_schedule("30m")
    assert config.interval_seconds == 30 * 60


def test_parse_schedule_interval_hours() -> None:
    config = _parse_schedule("2h")
    assert config.interval_seconds == 2 * 3600


def test_parse_schedule_interval_seconds() -> None:
    config = _parse_schedule("45s")
    assert config.interval_seconds == 45


def test_parse_schedule_iso() -> None:
    config = _parse_schedule("2099-01-01T08:00:00")
    assert config.iso_time == "2099-01-01T08:00:00"


def test_parse_schedule_unknown() -> None:
    """An unrecognised single token falls through to an empty config."""
    config = _parse_schedule("bogus")
    assert config.cron is None
    assert config.iso_time is None
    assert config.interval_seconds is None
