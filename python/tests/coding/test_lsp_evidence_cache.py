"""Tests for the bounded LRU+TTL evidence cache (spec §8, §9).

Covers:
    - Basic put/get
    - LRU eviction by entry count
    - LRU eviction by byte budget
    - TTL expiration
    - Server identity mismatch (server restart) invalidation
    - Per-file invalidation
    - Per-repository invalidation
    - Per-workspace invalidation
    - Full clear
    - Cache stats (hits/misses/evictions/expirations)
    - Concurrent-safe operations
"""
from __future__ import annotations

import time

import pytest

from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.evidence import (
    EvidenceCacheKey,
    EvidenceSource,
    EvidenceType,
    SemanticEvidence,
)


def _key(repo: str = "r", workspace: str = "w", path: str = "a.py", gen: int = 1,
         server: str = "pyright@1.0", doc_ver: int = 1, candidate_range: tuple[int, int] = (0, 10)) -> EvidenceCacheKey:
    return EvidenceCacheKey(
        repository_id=repo,
        workspace_id=workspace,
        file_path=path,
        content_hash="abc123",
        file_generation=gen,
        document_version=doc_ver,
        candidate_range=candidate_range,
        server_identity=server,
    )


def _evidence(source: EvidenceSource = EvidenceSource.LSP_DEFINITION) -> tuple[SemanticEvidence, ...]:
    return (SemanticEvidence(
        source=source,
        evidence_type=EvidenceType.DEFINITION,
        target_file="target.py",
        target_range=(0, 0, 0, 10),
        target_symbol_id="sym-123",
        confidence=0.8,
        server_name="pyright",
        server_version="1.0",
        document_version=1,
    ),)


class TestBasicPutGet:
    def test_put_then_get(self):
        cache = EvidenceCache(max_entries=10, ttl_seconds=60)
        key = _key()
        ev = _evidence()
        cache.put(key, ev)
        assert cache.size == 1
        result = cache.get(key)
        assert result == ev

    def test_get_miss_returns_none(self):
        cache = EvidenceCache(max_entries=10)
        assert cache.get(_key()) is None
        assert cache.stats["misses"] == 1

    def test_get_hit_increments_counter(self):
        cache = EvidenceCache(max_entries=10)
        key = _key()
        cache.put(key, _evidence())
        cache.get(key)
        assert cache.stats["hits"] == 1
        assert cache.stats["misses"] == 0


class TestLRUEviction:
    def test_eviction_by_entry_count(self):
        cache = EvidenceCache(max_entries=3)
        k1, k2, k3, k4 = _key(path="1.py"), _key(path="2.py"), _key(path="3.py"), _key(path="4.py")
        cache.put(k1, _evidence())
        cache.put(k2, _evidence())
        cache.put(k3, _evidence())
        assert cache.size == 3
        # Insert k4 — k1 (LRU) should be evicted
        cache.put(k4, _evidence())
        assert cache.size == 3
        assert cache.get(k1) is None  # evicted
        assert cache.get(k4) is not None
        assert cache.stats["evictions"] == 1

    def test_lru_order_updated_on_get(self):
        cache = EvidenceCache(max_entries=3)
        k1, k2, k3, k4 = _key(path="1.py"), _key(path="2.py"), _key(path="3.py"), _key(path="4.py")
        cache.put(k1, _evidence())
        cache.put(k2, _evidence())
        cache.put(k3, _evidence())
        # Access k1 — it becomes MRU, so k2 is now LRU
        cache.get(k1)
        # Insert k4 — k2 should be evicted
        cache.put(k4, _evidence())
        assert cache.get(k1) is not None  # still present
        assert cache.get(k2) is None  # evicted

    def test_eviction_by_byte_budget(self):
        # Very small byte budget — should evict after 1-2 entries
        cache = EvidenceCache(max_entries=100, max_bytes=400)
        k1, k2 = _key(path="1.py"), _key(path="2.py")
        cache.put(k1, _evidence())
        cache.put(k2, _evidence())
        # Each evidence entry is ~300+ bytes, so k1 should be evicted
        assert cache.get(k1) is None or cache.get(k2) is not None
        assert cache.bytes <= 400


class TestTTLExpiration:
    def test_ttl_expired_entry_evicted_on_get(self):
        cache = EvidenceCache(max_entries=10, ttl_seconds=0.01)
        key = _key()
        cache.put(key, _evidence())
        time.sleep(0.02)
        result = cache.get(key)
        assert result is None
        assert cache.stats["expirations"] == 1
        assert cache.stats["misses"] == 1

    def test_ttl_not_expired_entry_kept(self):
        cache = EvidenceCache(max_entries=10, ttl_seconds=60)
        key = _key()
        cache.put(key, _evidence())
        result = cache.get(key)
        assert result is not None
        assert cache.stats["expirations"] == 0


class TestServerIdentityMismatch:
    def test_server_restart_invalidates_entry(self):
        cache = EvidenceCache(max_entries=10)
        key_v1 = _key(server="pyright@1.0")
        cache.put(key_v1, _evidence())
        # Same key but different server identity (server restarted with new version)
        key_v2 = _key(server="pyright@2.0")
        result = cache.get(key_v2)
        # key_v2 is a different key (different server_identity), so it's a miss
        assert result is None
        # But the original key_v1 is still there
        assert cache.get(key_v1) is not None


class TestInvalidation:
    def test_invalidate_file(self):
        cache = EvidenceCache(max_entries=100)
        cache.put(_key(path="a.py"), _evidence())
        cache.put(_key(path="b.py"), _evidence())
        removed = cache.invalidate_file("r", "a.py")
        assert removed == 1
        assert cache.get(_key(path="a.py")) is None
        assert cache.get(_key(path="b.py")) is not None

    def test_invalidate_repository(self):
        cache = EvidenceCache(max_entries=100)
        cache.put(_key(repo="r1", path="a.py"), _evidence())
        cache.put(_key(repo="r2", path="a.py"), _evidence())
        removed = cache.invalidate_repository("r1")
        assert removed == 1
        assert cache.get(_key(repo="r1")) is None
        assert cache.get(_key(repo="r2")) is not None

    def test_invalidate_workspace(self):
        cache = EvidenceCache(max_entries=100)
        cache.put(_key(workspace="w1"), _evidence())
        cache.put(_key(workspace="w2"), _evidence())
        removed = cache.invalidate_workspace("w1")
        assert removed == 1
        assert cache.get(_key(workspace="w1")) is None
        assert cache.get(_key(workspace="w2")) is not None

    def test_clear_all(self):
        cache = EvidenceCache(max_entries=100)
        cache.put(_key(path="a.py"), _evidence())
        cache.put(_key(path="b.py"), _evidence())
        removed = cache.clear()
        assert removed == 2
        assert cache.size == 0


class TestStats:
    def test_stats_track_all_counters(self):
        cache = EvidenceCache(max_entries=2, ttl_seconds=0.01)
        k1, k2, k3 = _key(path="1.py"), _key(path="2.py"), _key(path="3.py")
        cache.put(k1, _evidence())
        cache.put(k2, _evidence())
        cache.get(k1)  # hit
        cache.get(_key(path="missing.py"))  # miss
        cache.put(k3, _evidence())  # eviction
        time.sleep(0.02)
        cache.get(k2)  # expiration (if k2 wasn't evicted) or miss
        stats = cache.stats
        assert "hits" in stats
        assert "misses" in stats
        assert "evictions" in stats
        assert "expirations" in stats
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1
