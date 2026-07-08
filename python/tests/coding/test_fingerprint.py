"""Tests for FileFingerprintCache."""

from __future__ import annotations

from khaos.coding.fingerprint import FileFingerprintCache


def test_is_changed_returns_true_for_first_sighting():
    cache = FileFingerprintCache()
    assert cache.is_changed("/a.py", "print('hi')") is True


def test_is_changed_returns_false_for_unchanged_content():
    cache = FileFingerprintCache()
    cache.update("/a.py", "print('hi')")
    assert cache.is_changed("/a.py", "print('hi')") is False


def test_is_changed_returns_true_after_content_modification():
    cache = FileFingerprintCache()
    cache.update("/a.py", "print('hi')")
    assert cache.is_changed("/a.py", "print('bye')") is True


def test_get_hash_returns_cached_hash_or_none():
    cache = FileFingerprintCache()
    assert cache.get_hash("/a.py") is None
    cache.update("/a.py", "x")
    assert cache.get_hash("/a.py") is not None
    # The stored hash is the sha256 hex of the utf-8 encoded content.
    import hashlib

    assert cache.get_hash("/a.py") == hashlib.sha256(b"x").hexdigest()


def test_update_records_hash_for_path():
    cache = FileFingerprintCache()
    assert cache.is_changed("/a.py", "x")
    cache.update("/a.py", "x")
    # Same content now considered unchanged.
    assert cache.is_changed("/a.py", "x") is False


def test_invalidate_clears_single_entry():
    cache = FileFingerprintCache()
    cache.update("/a.py", "x")
    cache.update("/b.py", "y")
    cache.invalidate("/a.py")

    assert cache.get_hash("/a.py") is None
    assert cache.get_hash("/b.py") is not None
    # After invalidation the path is seen as changed again.
    assert cache.is_changed("/a.py", "x") is True


def test_invalidate_missing_path_is_silent():
    cache = FileFingerprintCache()
    cache.invalidate("/never-seen")  # must not raise
    assert cache.size == 0


def test_clear_empties_all_entries():
    cache = FileFingerprintCache()
    cache.update("/a.py", "x")
    cache.update("/b.py", "y")
    assert cache.size == 2

    cache.clear()
    assert cache.size == 0
    assert cache.is_changed("/a.py", "x") is True


def test_size_reflects_entry_count():
    cache = FileFingerprintCache()
    assert cache.size == 0
    cache.update("/a.py", "x")
    assert cache.size == 1
    cache.update("/b.py", "y")
    assert cache.size == 2
    cache.update("/a.py", "z")  # same key, no growth
    assert cache.size == 2


def test_max_entries_eviction_keeps_cache_within_bounds():
    cache = FileFingerprintCache(max_entries=4)
    # Fill to capacity.
    for i in range(4):
        cache.update(f"/f{i}.py", f"c{i}")
    assert cache.size == 4

    # Adding a 5th entry triggers eviction (clears half of the oldest).
    cache.update("/f4.py", "c4")
    # Capacity is 4; after eviction+insert the cache must not exceed it.
    assert cache.size <= 4
    # The newest entry is always present after eviction.
    assert cache.get_hash("/f4.py") is not None


def test_distinct_paths_with_same_content_are_both_tracked():
    """Two different paths sharing identical content are independent entries."""
    cache = FileFingerprintCache()
    cache.update("/a.py", "same")
    cache.update("/b.py", "same")

    assert cache.is_changed("/a.py", "same") is False
    assert cache.is_changed("/b.py", "same") is False
    assert cache.size == 2
