"""Repository-level parse orchestration with a bounded process-local state cache."""
from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.coding.indexer import EXCLUDED_DIRS
from khaos.coding.intelligence.index.store import IndexStore
from khaos.coding.intelligence.models import ParseState
from khaos.coding.intelligence.registry import LanguageRegistry

MAX_PARSE_STATE_ENTRIES = 256
MAX_PARSE_STATE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_STATE_BYTES = 4 * 1024 * 1024
PARSE_STATE_FIXED_OVERHEAD = 16 * 1024


@dataclass(frozen=True)
class CacheKey:
    repository_id: str
    root_identity: str
    relative_path: str
    language: str
    dialect: str
    adapter_source: str
    grammar_fingerprint: str


@dataclass
class CacheEntry:
    parse_state: ParseState = field(repr=False)
    content_hash: str
    file_size: int
    estimated_retained_bytes: int
    generation: int
    last_accessed: float
    parser_fingerprint: str


class RepositoryParseStateCache:
    def __init__(self) -> None:
        self._entries: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()
        self.hits = self.misses = self.evictions = 0

    def find(self, repository_id: str, root_identity: str, relative_path: str) -> CacheEntry | None:
        with self._lock:
            key = next((item for item in self._entries if item.repository_id == repository_id and item.root_identity == root_identity and item.relative_path == relative_path), None)
            if key is None:
                self.misses += 1; return None
            entry = self._entries.pop(key); entry.last_accessed = time.monotonic(); self._entries[key] = entry; self.hits += 1
            return entry

    def put(self, repository_id: str, root_identity: str, relative_path: str, state: ParseState, file_size: int, generation: int) -> None:
        opaque = state.opaque
        if opaque is None:
            return
        estimated = int(getattr(opaque, "content_length", file_size)) + PARSE_STATE_FIXED_OVERHEAD
        if estimated > MAX_SINGLE_STATE_BYTES:
            return
        key = CacheKey(repository_id, root_identity, relative_path, str(getattr(opaque, "language", "unknown")), str(getattr(opaque, "dialect", "unknown")), state.adapter_source, str(getattr(opaque, "grammar_fingerprint", "unknown")))
        entry = CacheEntry(state, state.content_hash, file_size, estimated, generation, time.monotonic(), key.grammar_fingerprint)
        with self._lock:
            old = self._entries.pop(key, None)
            if old: self._bytes -= old.estimated_retained_bytes
            self._entries[key] = entry; self._bytes += estimated
            while len(self._entries) > MAX_PARSE_STATE_ENTRIES or self._bytes > MAX_PARSE_STATE_BYTES:
                _, evicted = self._entries.popitem(last=False); self._bytes -= evicted.estimated_retained_bytes; self.evictions += 1

    def remove_path(self, repository_id: str, root_identity: str, relative_path: str) -> None:
        with self._lock:
            for key in [key for key in self._entries if key.repository_id == repository_id and key.root_identity == root_identity and key.relative_path == relative_path]:
                self._bytes -= self._entries.pop(key).estimated_retained_bytes

    def clear_repository(self, repository_id: str, root_identity: str) -> None:
        with self._lock:
            for key in [key for key in self._entries if key.repository_id == repository_id and key.root_identity == root_identity]:
                self._bytes -= self._entries.pop(key).estimated_retained_bytes

    def clear(self) -> None:
        with self._lock:
            self._entries.clear(); self._bytes = 0

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._entries), "estimated_bytes": self._bytes, "hits": self.hits, "misses": self.misses, "evictions": self.evictions}


class RepositoryIndexer:
    def __init__(self, store: IndexStore, *, registry: LanguageRegistry | None = None, ignored_dirs: set[str] | None = None, resolution_service: Any | None = None) -> None:
        self.store = store
        self.registry = registry or LanguageRegistry()
        self.cache = RepositoryParseStateCache()
        self.ignored_dirs = set(EXCLUDED_DIRS) | {"vendor", ".cache", "cache"} | set(ignored_dirs or ())
        self._file_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()
        self._closed = False
        self._resolution_service = resolution_service

    async def index(self, repository_id: str, root: Path, *, full_reindex: bool = False) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("RepositoryIndexer is closed")
        started = time.perf_counter(); root = root.expanduser().resolve(strict=True); root_identity = _root_identity(root)
        if full_reindex: self.cache.clear_repository(repository_id, root_identity)
        paths, rejected_paths = _enumerate_files(root, self.ignored_dirs)
        current = {path.relative_to(root).as_posix() for path in paths}
        indexed = await self.store.indexed_paths(repository_id)
        report: dict[str, Any] = {"scanned_files": len(paths), "parsed_files": 0, "incremental_files": 0, "full_fallback_files": 0, "unchanged_files": 0, "deleted_files": 0, "unsupported_files": 0, "failed_files": 0, "stale_read_files": 0, "statuses": {}, "rejected_paths": rejected_paths}
        deleted_paths: set[str] = set()
        changed_paths: set[str] = set()
        for relative in sorted(indexed - current):
            await self.store.remove(repository_id, relative); self.cache.remove_path(repository_id, root_identity, relative); report["deleted_files"] += 1; report["statuses"][relative] = "deleted"; deleted_paths.add(relative)
        results = await asyncio.gather(*(self._refresh_file(repository_id, root, root_identity, path, full_reindex) for path in paths))
        for relative, status in results:
            report["statuses"][relative] = status
            if status == "unchanged": report["unchanged_files"] += 1
            elif status == "unsupported": report["unsupported_files"] += 1
            elif status == "stale-read": report["stale_read_files"] += 1; report["failed_files"] += 1
            elif status == "parse-failed": report["failed_files"] += 1
            elif status.startswith("indexed-"):
                report["parsed_files"] += 1
                changed_paths.add(relative)
                if status == "indexed-incremental": report["incremental_files"] += 1
                if status == "indexed-full-fallback": report["full_fallback_files"] += 1
        report.update({f"cache_{key}": value for key, value in self.cache.stats().items()})
        # Run semantic resolution if a resolution service is configured
        if self._resolution_service is not None:
            try:
                resolution_report = self._resolution_service.resolve(
                    repository_id, root,
                    changed_paths=changed_paths,
                    deleted_paths=deleted_paths,
                    full_rebuild=full_reindex,
                )
                report["resolution"] = resolution_report.to_dict()
            except (RuntimeError, ValueError) as exc:
                report["resolution_error"] = str(exc)
        report["total_duration_ms"] = (time.perf_counter() - started) * 1000
        return report

    async def _refresh_file(self, repository_id: str, root: Path, root_identity: str, path: Path, force: bool) -> tuple[str, str]:
        relative = path.relative_to(root).as_posix(); lock_key = (repository_id, relative)
        async with self._locks_guard: lock = self._file_locks.setdefault(lock_key, asyncio.Lock())
        try:
            async with lock:
                if self._closed: raise RuntimeError("RepositoryIndexer is closed")
                resolution = self.registry.resolve(relative)
                if not resolution.supported: return relative, "unsupported"
                for attempt in range(2):
                    before = path.stat(); content = path.read_bytes(); digest = hashlib.sha256(content).hexdigest()
                    existing = await self.store.file_record(repository_id, relative)
                    if not force and existing and existing["content_hash"] == digest: return relative, "unchanged"
                    cached = None if force else self.cache.find(repository_id, root_identity, relative)
                    result = await asyncio.to_thread(self.registry.parse, file_path=str(path), content=content, previous_state=cached.parse_state if cached else None)
                    after = path.stat()
                    if (before.st_mtime_ns, before.st_size, getattr(before, "st_ino", 0)) != (after.st_mtime_ns, after.st_size, getattr(after, "st_ino", 0)):
                        if attempt == 0: continue
                        return relative, "stale-read"
                    if result.parser_source == "rejected":
                        status = "rejected-binary" if result.diagnostics[0].code == "binary-content" else "rejected-oversized"
                    else: status = f"indexed-{result.metadata.parse_mode}"
                    generation = int(existing["generation"] + 1) if existing else 1
                    try:
                        await self.store.write_parse_result(repository_id, relative, result, size=len(content), mtime_ns=after.st_mtime_ns, generation=generation)
                    except (RuntimeError, TypeError, ValueError, OSError, sqlite3.DatabaseError):
                        return relative, "parse-failed"
                    if result.parse_state is not None:
                        self.cache.remove_path(repository_id, root_identity, relative)
                        self.cache.put(repository_id, root_identity, relative, result.parse_state, len(content), generation)
                    return relative, status
                return relative, "stale-read"
        except (OSError, UnicodeError, RuntimeError, TypeError, ValueError):
            return relative, "parse-failed"
        finally:
            async with self._locks_guard:
                if not lock.locked(): self._file_locks.pop(lock_key, None)

    async def close(self) -> None:
        self._closed = True; self.cache.clear(); await self.store.close()


def _root_identity(root: Path) -> str:
    stat = root.stat(); return f"{root}:{getattr(stat, 'st_dev', 0)}:{getattr(stat, 'st_ino', 0)}"


def _enumerate_files(root: Path, ignored: set[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []; rejected: list[str] = []; seen: set[tuple[int, int]] = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in ignored and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            try:
                resolved = path.resolve(strict=True); resolved.relative_to(root); stat = resolved.stat()
            except (OSError, ValueError):
                rejected.append(path.relative_to(root).as_posix()); continue
            identity = (stat.st_dev, stat.st_ino)
            if identity in seen: continue
            seen.add(identity); files.append(resolved)
    return sorted(files), rejected
