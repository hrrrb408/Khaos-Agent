"""Bounded LRU+TTL evidence cache for short-lived LSP evidence.

The cache is strictly bounded by both entry count and byte size. Entries
are invalidated by any of these staleness conditions (per spec §8):

    - File generation changed (IndexStore re-indexed the file)
    - Content hash changed (file bytes differ)
    - LSP document version changed (server re-parsed the document)
    - Workspace changed or was cleaned
    - LSP server restarted (server identity changed)
    - Grammar/resolution generation changed
    - Target symbol was deleted or moved

Stale LSP responses NEVER overwrite newer repository resolution results —
the cache simply drops stale entries, and callers fall back to the
repository resolution.

The cache is in-memory only. It is never persisted to disk, never stores
source code bodies, never stores document text, and never stores the
workspace absolute path. Only the cache KEY binds these values (for
invalidation); the VALUE is a tuple of :class:`SemanticEvidence`.
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from threading import RLock

from khaos.coding.intelligence.lsp.evidence import EvidenceCacheEntry, EvidenceCacheKey, SemanticEvidence

logger = logging.getLogger(__name__)


class EvidenceCache:
    """Thread-safe bounded LRU+TTL cache for LSP evidence.

    Thread safety: all operations acquire a re-entrant lock. The cache is
    safe to share across threads, but LSP fusion is async — callers should
    not hold the lock across ``await`` points.
    """

    def __init__(
        self,
        *,
        max_entries: int = 2048,
        ttl_seconds: float = 300.0,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._max_bytes = max_bytes
        self._entries: OrderedDict[EvidenceCacheKey, EvidenceCacheEntry] = OrderedDict()
        self._total_bytes = 0
        self._lock = RLock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "expirations": 0}

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    def get(self, key: EvidenceCacheKey) -> tuple[SemanticEvidence, ...] | None:
        """Return cached evidence if present and not stale, else ``None``.

        Stale entries (TTL expired or server identity mismatch) are evicted
        on read. A miss increments the ``misses`` counter; a hit increments
        ``hits`` and moves the entry to the MRU position.
        """
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._stats["misses"] += 1
                return None
            # Server identity mismatch — treat as stale (server restarted).
            if entry.server_identity != key.server_identity:
                self._remove(key)
                self._stats["expirations"] += 1
                self._stats["misses"] += 1
                return None
            # TTL expiry.
            if now - entry.created_at > self._ttl_seconds:
                self._remove(key)
                self._stats["expirations"] += 1
                self._stats["misses"] += 1
                return None
            # Hit — move to MRU.
            self._entries.move_to_end(key)
            self._stats["hits"] += 1
            return entry.evidence

    def put(
        self,
        key: EvidenceCacheKey,
        evidence: tuple[SemanticEvidence, ...],
    ) -> None:
        """Insert or replace a cache entry, evicting LRU entries as needed."""
        now = time.monotonic()
        entry = EvidenceCacheEntry(
            evidence=evidence,
            created_at=now,
            server_identity=key.server_identity,
        )
        estimated_bytes = _estimate_bytes(evidence)
        with self._lock:
            # If key already exists, remove old entry first.
            if key in self._entries:
                self._remove(key)
            # Enforce byte budget before insertion.
            while self._total_bytes + estimated_bytes > self._max_bytes and self._entries:
                self._evict_lru()
            # Enforce entry count budget.
            while len(self._entries) >= self._max_entries and self._entries:
                self._evict_lru()
            self._entries[key] = entry
            self._total_bytes += estimated_bytes

    def invalidate_file(self, repository_id: str, file_path: str) -> int:
        """Drop all cache entries for a given file. Returns the count removed."""
        with self._lock:
            to_remove = [
                k for k in self._entries
                if k.repository_id == repository_id and k.file_path == file_path
            ]
            for k in to_remove:
                self._remove(k)
            return len(to_remove)

    def invalidate_repository(self, repository_id: str) -> int:
        """Drop all cache entries for a repository. Returns the count removed."""
        with self._lock:
            to_remove = [k for k in self._entries if k.repository_id == repository_id]
            for k in to_remove:
                self._remove(k)
            return len(to_remove)

    def invalidate_workspace(self, workspace_id: str) -> int:
        """Drop all cache entries for a workspace. Returns the count removed."""
        with self._lock:
            to_remove = [k for k in self._entries if k.workspace_id == workspace_id]
            for k in to_remove:
                self._remove(k)
            return len(to_remove)

    def clear(self) -> int:
        """Drop all cache entries. Returns the count removed."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._total_bytes = 0
            return count

    def _remove(self, key: EvidenceCacheKey) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._total_bytes -= _estimate_bytes(entry.evidence)
            if self._total_bytes < 0:
                self._total_bytes = 0

    def _evict_lru(self) -> None:
        if not self._entries:
            return
        key, entry = self._entries.popitem(last=False)
        self._total_bytes -= _estimate_bytes(entry.evidence)
        if self._total_bytes < 0:
            self._total_bytes = 0
        self._stats["evictions"] += 1


def _estimate_bytes(evidence: tuple[SemanticEvidence, ...]) -> int:
    """Rough byte estimate for cache budgeting.

    We do NOT serialize the evidence — we estimate from the target_file
    string lengths and a fixed per-entry overhead. This is intentionally
    conservative (overestimates) to prevent unbounded memory growth.
    """
    total = 64  # overhead per entry
    for e in evidence:
        total += 128  # fixed per-evidence overhead
        if e.target_file:
            total += len(e.target_file.encode("utf-8"))
        if e.target_symbol_id:
            total += len(e.target_symbol_id)
        if e.server_name:
            total += len(e.server_name)
        if e.metadata:
            import json
            try:
                total += len(json.dumps(e.metadata, ensure_ascii=False))
            except (TypeError, ValueError):
                total += 256
    return total
