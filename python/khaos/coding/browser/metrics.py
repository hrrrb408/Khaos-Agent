"""Bounded, non-authoritative metrics for Browser Coding evaluation."""

from __future__ import annotations

from dataclasses import dataclass

_MAX_COUNTER = 1_000_000_000


@dataclass(frozen=True, slots=True)
class BrowserMetrics:
    """Black-box Browser Coding counters and first-event timings.

    ``browser_time_to_first_observation`` and ``browser_time_to_green`` are
    elapsed milliseconds from service construction. These values describe an
    experiment only; they are never used for permission, verification, or
    completion decisions.
    """

    browser_sessions: int = 0
    browser_actions: int = 0
    browser_observations: int = 0
    browser_verification_checks: int = 0
    browser_verification_failures: int = 0
    app_launches: int = 0
    app_restarts: int = 0
    app_launch_failures: int = 0
    browser_context_bytes: int = 0
    browser_evidence_bytes: int = 0
    screenshots_created: int = 0
    browser_prompt_injection_rejections: int = 0
    browser_policy_denials: int = 0
    browser_approval_requests: int = 0
    browser_time_to_first_observation: int = 0
    browser_time_to_green: int = 0
    browser_repairs: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= _MAX_COUNTER:
                raise ValueError(f"browser metric {name} is invalid")

    def to_payload(self) -> dict[str, int]:
        """Return a stable metrics payload without browser source content."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


__all__ = ["BrowserMetrics"]
