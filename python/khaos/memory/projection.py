"""Deterministic Memory V2 projection reducer.

The event ledger is the authority. Providers only materialize this reducer's
state into searchable tables, so lifecycle replay has one implementation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from khaos.memory.core.contracts import MemoryAuthority, MemoryEventType, MemoryStatus


@dataclass(frozen=True, slots=True)
class ProjectionRecord:
    """Materialized lifecycle state for one deterministic memory id."""

    memory_id: str
    status: str
    authority: str
    superseded_by: str = ""
    valid_to: str | None = None


class MemoryProjectionReducer:
    """Apply the complete Memory V2 lifecycle state machine in event order."""

    def __init__(self) -> None:
        self._records: dict[str, ProjectionRecord] = {}
        self._deleted_ids: set[str] = set()
        self.invalid_event_ids: list[str] = []

    @property
    def records(self) -> tuple[ProjectionRecord, ...]:
        """Return deterministic surviving records."""

        return tuple(self._records[key] for key in sorted(self._records))

    @property
    def deleted_ids(self) -> frozenset[str]:
        """Return ids removed by hard/compliance revocation."""

        return frozenset(self._deleted_ids)

    def apply(self, event: Mapping[str, Any]) -> None:
        """Apply one database-shaped event without trusting provider fields."""

        event_id = str(event.get("event_id") or "")
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload")
        if payload is None:
            raw_payload = event.get("payload_json", "{}")
            try:
                payload = json.loads(str(raw_payload))
            except (TypeError, ValueError):
                self.invalid_event_ids.append(event_id)
                return
        if not isinstance(payload, Mapping):
            self.invalid_event_ids.append(event_id)
            return

        if event_type == MemoryEventType.MEMORY_CANDIDATE_CREATED.value:
            if event.get("payload_redacted") is True:
                # Compliance redaction intentionally removes the claim.  It
                # is a valid, content-free ledger state and must not make a
                # later rebuild fail; the corresponding tombstone removes
                # the derived node.
                return
            if "claim" not in payload:
                self.invalid_event_ids.append(event_id)
                return
            memory_id = stable_memory_id(event_id)
            status = str(payload.get("status") or MemoryStatus.CANDIDATE.value)
            authority = str(
                payload.get("admitted_authority") or MemoryAuthority.AGENT_INFERRED.value
            )
            if status not in {item.value for item in MemoryStatus}:
                self.invalid_event_ids.append(event_id)
                return
            self._records[memory_id] = ProjectionRecord(memory_id, status, authority)
            self._deleted_ids.discard(memory_id)
            return

        memory_id = str(payload.get("memory_id") or "")
        if event_type == MemoryEventType.MEMORY_PROMOTED.value:
            record = self._records.get(memory_id)
            if record is None:
                return
            promotion = str(payload.get("promotion") or "")
            authority = record.authority
            if promotion == "verification_authority":
                authority = MemoryAuthority.VERIFICATION_CONFIRMED.value
            elif promotion == "user_approved":
                authority = MemoryAuthority.USER_STATED.value
            self._records[memory_id] = ProjectionRecord(
                memory_id,
                MemoryStatus.VERIFIED.value if promotion else record.status,
                authority,
                record.superseded_by,
                record.valid_to,
            )
            return

        if event_type == MemoryEventType.MEMORY_SUPERSEDED.value:
            for related_id in _string_sequence(payload.get("related_ids")):
                record = self._records.get(related_id)
                if record is None:
                    continue
                self._records[related_id] = ProjectionRecord(
                    related_id,
                    MemoryStatus.SUPERSEDED.value,
                    record.authority,
                    memory_id,
                    str(event.get("occurred_at") or "") or record.valid_to,
                )
            return

        if event_type == MemoryEventType.MEMORY_REVOKED.value:
            record = self._records.get(memory_id)
            if record is None:
                return
            mode = str(payload.get("forget_mode") or "soft")
            if mode == "soft":
                self._records[memory_id] = ProjectionRecord(
                    memory_id,
                    MemoryStatus.REVOKED.value,
                    record.authority,
                    record.superseded_by,
                    str(event.get("occurred_at") or "") or record.valid_to,
                )
            else:
                self._records.pop(memory_id, None)
                self._deleted_ids.add(memory_id)

    def replay(self, events: Iterable[Mapping[str, Any]]) -> None:
        """Replay events with the ledger's stable recorded cursor ordering."""

        ordered = sorted(
            events,
            key=lambda event: (
                str(event.get("recorded_at") or ""),
                str(event.get("event_id") or ""),
            ),
        )
        for event in ordered:
            self.apply(event)


def stable_memory_id(candidate_event_id: str) -> str:
    """Return the provider-independent id for an admitted candidate event."""

    if not candidate_event_id:
        raise ValueError("candidate event id is required for projection identity")
    return hashlib.sha256(
        f"khaos-memory:{candidate_event_id}".encode()
    ).hexdigest()[:32]


def _string_sequence(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if str(item))


__all__ = ["MemoryProjectionReducer", "ProjectionRecord", "stable_memory_id"]
