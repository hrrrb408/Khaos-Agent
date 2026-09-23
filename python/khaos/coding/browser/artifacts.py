"""Bounded metadata-only browser artifact storage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from khaos.coding.browser.contracts import (
    BrowserArtifactRef,
    BrowserContractError,
)


@dataclass(frozen=True, slots=True)
class _Artifact:
    reference: BrowserArtifactRef
    payload: bytes


class BrowserArtifactStore:
    """Keep bounded, quarantined bytes behind metadata-only references.

    The model-facing browser contract only receives ``BrowserArtifactRef``.
    Raw bytes remain an internal implementation detail and are discarded on
    close.  Download artifacts are quarantined by construction and are never
    opened or executed by this store.
    """

    def __init__(
        self,
        *,
        max_artifacts: int = 32,
        max_total_bytes: int = 32 * 1024 * 1024,
        max_artifact_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if min(max_artifacts, max_total_bytes, max_artifact_bytes) <= 0:
            raise ValueError("artifact store limits must be positive")
        self.max_artifacts = max_artifacts
        self.max_total_bytes = max_total_bytes
        self.max_artifact_bytes = max_artifact_bytes
        self._items: dict[str, _Artifact] = {}
        self._total_bytes = 0
        self._closed = False

    def put(
        self,
        kind: str,
        payload: bytes,
        *,
        path: str = "",
        quarantine: bool = True,
    ) -> BrowserArtifactRef:
        if self._closed:
            raise BrowserContractError("browser artifact store is closed")
        if type(payload) is not bytes:
            raise BrowserContractError("browser artifact payload must be bytes")
        if len(payload) > self.max_artifact_bytes:
            raise BrowserContractError("browser artifact exceeds its byte bound")
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = f"browser-artifact-{digest[:24]}"
        existing = self._items.get(artifact_id)
        if existing is not None:
            return existing.reference
        if len(self._items) >= self.max_artifacts:
            raise BrowserContractError("browser artifact count limit exceeded")
        if self._total_bytes + len(payload) > self.max_total_bytes:
            raise BrowserContractError("browser artifact total-byte limit exceeded")
        reference = BrowserArtifactRef(
            artifact_id=artifact_id,
            kind=kind,
            size_bytes=len(payload),
            sha256=digest,
            path=path,
            quarantined=quarantine,
        )
        self._items[artifact_id] = _Artifact(reference, payload)
        self._total_bytes += len(payload)
        return reference

    def read_internal(self, artifact_id: str) -> bytes:
        """Read an artifact only for a composed internal consumer."""
        if self._closed:
            raise BrowserContractError("browser artifact store is closed")
        try:
            return self._items[artifact_id].payload
        except KeyError as exc:
            raise BrowserContractError("unknown browser artifact") from exc

    def get_reference(self, artifact_id: str) -> BrowserArtifactRef:
        if self._closed:
            raise BrowserContractError("browser artifact store is closed")
        try:
            return self._items[artifact_id].reference
        except KeyError as exc:
            raise BrowserContractError("unknown browser artifact") from exc

    def owned_resources(self) -> tuple[str, ...]:
        return tuple(f"artifact:{artifact_id}" for artifact_id in self._items)

    def terminal_postcondition(self) -> bool:
        return self._closed and not self._items

    @property
    def terminal_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._items.clear()
        self._total_bytes = 0
        self._closed = True


__all__ = ["BrowserArtifactStore"]
