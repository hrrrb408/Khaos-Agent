"""Typed runtime lifecycle terminal states.

Review P2-1 (close false-success): when a safety-critical component fails to
shut down, the runtime must not let a later ``aclose()`` caller believe the
close succeeded. Previously a failed first close set ``_close_failed`` and the
next ``aclose()`` returned silently while ``_closed`` stayed ``False`` — i.e.
the runtime was quarantined but the API reported success to a second caller.

This module makes the terminal state machine explicit:

* ``OPEN``        — not closing yet.
* ``CLOSING``     — a close task is in flight.
* ``CLOSED``      — every safety-critical component reached a terminal state.
* ``QUARANTINED`` — a component failed terminally; resources may still be
                    live. A subsequent ``aclose()`` must re-raise, never
                    silently return.

Invariant E (close failure must not masquerade as success): the only
information-free return from ``aclose()`` is when the runtime is ``CLOSED``.
``QUARANTINED`` always surfaces a typed error.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CloseState(str, Enum):
    """Terminal state of a runtime's close lifecycle."""

    OPEN = "OPEN"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class CloseResult:
    """Outcome of an ``aclose()`` attempt.

    * ``clean`` is True only when the runtime reached ``CloseState.CLOSED``.
    * ``quarantined`` is True when the runtime reached
      ``CloseState.QUARANTINED`` — resources may still be live and a retry is
      the caller's responsibility (typically via the server-scoped cleanup
      authority).
    * ``error`` carries the typed failure when the close did not succeed.
    """

    clean: bool
    quarantined: bool = False
    error: Any = None

    @property
    def state(self) -> CloseState:
        """Derive the matching ``CloseState`` for observability."""
        if self.clean:
            return CloseState.CLOSED
        if self.quarantined:
            return CloseState.QUARANTINED
        return CloseState.OPEN
