"""Repository-level parse orchestration with a bounded process-local state cache."""
from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from pathlib import PurePosixPath
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
class RepositoryIndexLimits:
    """Explicit bounds for one repository index operation.

    The legacy indexer keeps generous defaults for existing callers.  The
    M8.1 facade supplies tighter workspace-specific limits and treats a
    bounded walk as a partial index rather than silently continuing.
    """

    max_files: int = 10_000
    max_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_depth: int = 32
    max_duration_seconds: float = 30.0

    def __post_init__(self) -> None:
        if type(self.max_files) is not int or self.max_files <= 0:
            raise ValueError("max_files must be positive")
        if type(self.max_bytes) is not int or self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if type(self.max_file_bytes) is not int or self.max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        if type(self.max_depth) is not int or self.max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        if type(self.max_duration_seconds) not in (int, float) or self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")


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


class SafeWorkspaceSourceAccess:
    """Bounded source adapter backed by ``SafeWorkspaceFS``.

    M3 remains usable with ordinary paths for its historical unit-test and
    maintenance callers.  M8.1 injects this adapter so repository indexing
    uses the same no-follow, owner-bound read/stat boundary as Coding file
    tools, without making the indexer import the workspace package at module
    load time.
    """

    def enumerate_files(
        self,
        root: Path,
        ignored_dirs: set[str],
        limits: RepositoryIndexLimits,
    ) -> tuple[list[Path], list[str], bool, list[str]]:
        from khaos.coding.workspace.boundary import (
            SafeWorkspaceFS,
            WorkspaceBoundaryError,
        )

        ignored = {name.casefold() for name in ignored_dirs}
        files: list[Path] = []
        rejected: list[str] = []
        truncation_reasons: list[str] = []
        truncated = False
        total_bytes = 0
        started = time.monotonic()
        try:
            with SafeWorkspaceFS(root) as filesystem:
                entries = filesystem.iter_entries(
                    ".",
                    max_entries=max(4096, limits.max_files * 4),
                    max_depth=limits.max_depth + 1,
                    ignored_dirs=ignored_dirs,
                    max_duration_seconds=limits.max_duration_seconds,
                )
                for relative, is_directory in entries:
                    parts = PurePosixPath(relative).parts
                    if any(part.casefold() in ignored for part in parts):
                        continue
                    if is_directory:
                        if len(parts) > limits.max_depth:
                            truncated = True
                            truncation_reasons.append("max-depth")
                        continue
                    if time.monotonic() - started > limits.max_duration_seconds:
                        truncated = True
                        truncation_reasons.append("max-duration")
                        break
                    if len(files) >= limits.max_files:
                        truncated = True
                        truncation_reasons.append("max-files")
                        break
                    info = filesystem.lstat(relative)
                    if info is None:
                        rejected.append(relative)
                        continue
                    if (
                        stat.S_ISLNK(info.st_mode)
                        or not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                    ):
                        rejected.append(relative)
                        continue
                    # Oversized files are retained as metadata-only candidates
                    # by the facade.  Charge only the bounded probe amount so
                    # one artifact cannot consume the indexing byte budget.
                    charge = min(int(info.st_size), limits.max_file_bytes)
                    if total_bytes + charge > limits.max_bytes:
                        truncated = True
                        truncation_reasons.append("max-bytes")
                        break
                    files.append(root / PurePosixPath(relative))
                    total_bytes += charge
        except (OSError, WorkspaceBoundaryError) as exc:
            truncated = True
            truncation_reasons.append(f"safe-enumeration:{type(exc).__name__}")
        return (
            sorted(files),
            sorted(set(rejected)),
            truncated,
            sorted(set(truncation_reasons)),
        )

    def stat(self, root: Path, relative: str) -> os.stat_result:
        from khaos.coding.workspace.boundary import SafeWorkspaceFS

        with SafeWorkspaceFS(root) as filesystem:
            info = filesystem.lstat(relative)
            if (
                info is None
                or not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
            ):
                raise OSError("source is not a safe regular file")
            return info

    def read_bytes(
        self,
        root: Path,
        relative: str,
        *,
        max_bytes: int,
    ) -> bytes:
        from khaos.coding.workspace.boundary import SafeWorkspaceFS

        with SafeWorkspaceFS(root) as filesystem:
            return filesystem.read_bytes(relative, max_bytes=max_bytes)

    def exists(self, root: Path, relative: str) -> bool:
        try:
            self.stat(root, relative)
        except OSError:
            return False
        return True


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
    def __init__(self, store: IndexStore, *, registry: LanguageRegistry | None = None, ignored_dirs: set[str] | None = None, resolution_service: Any | None = None, limits: RepositoryIndexLimits | None = None, source_access: Any | None = None) -> None:
        self.store = store
        self.registry = registry or LanguageRegistry()
        self.cache = RepositoryParseStateCache()
        self.ignored_dirs = set(EXCLUDED_DIRS) | {
            "vendor", ".cache", "cache", "coverage", "generated"
        } | set(ignored_dirs or ())
        self._file_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()
        self._closed = False
        self._resolution_service = resolution_service
        self.limits = limits or RepositoryIndexLimits()
        # M8.1 can provide the same no-follow workspace reader used by Coding
        # file tools.  The legacy M3 callers keep the pathlib adapter below;
        # the convergence facade always supplies a safe source access object.
        self._source_access = source_access
        # Batch 2.6 §5: optional per-workspace mutation fence. When set,
        # index() acquires the fence (owner="indexer:{repository_id}")
        # BEFORE writing parse results so generation updates are
        # serialized with active lease acquisition / Batch 3 execution.
        self._mutation_fence: Any = None
        self._fence_workspace_resolver: Any = None

    def set_mutation_fence(self, fence: Any, *, workspace_resolver: Any = None) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence.

        ``workspace_resolver`` is an optional callable that takes
        ``repository_id`` and returns the ``workspace_id`` whose fence
        should be acquired (or ``None`` if no workspace is active). When
        no resolver is provided, the fence is acquired with
        ``workspace_id=repository_id`` (repository-level serialization).
        """
        self._mutation_fence = fence
        self._fence_workspace_resolver = workspace_resolver

    async def index(
        self, repository_id: str, root: Path, *, workspace_id: str | None = None,
        full_reindex: bool = False,
    ) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("RepositoryIndexer is closed")
        # Batch 2.6 §5: acquire the mutation fence BEFORE writing parse
        # results so generation updates are serialized with active lease
        # acquisition / Batch 3 execution / cleanup. Falls back to
        # repository_id as the workspace key when no resolver is set.
        if self._mutation_fence is not None:
            if not workspace_id:
                raise RuntimeError("workspace_id is required for fenced repository indexing")
            if self._fence_workspace_resolver is None:
                raise RuntimeError("canonical repository/workspace resolver is required")
            resolved = self._fence_workspace_resolver(repository_id, workspace_id)
            if resolved != workspace_id:
                raise RuntimeError("repository/workspace mutation scope is invalid or ambiguous")
            async with self._mutation_fence.use(
                workspace_id, owner=f"indexer:{repository_id}",
            ):
                return await self._index_impl(repository_id, root, full_reindex=full_reindex)
        return await self._index_impl(repository_id, root, full_reindex=full_reindex)

    async def _index_impl(self, repository_id: str, root: Path, *, full_reindex: bool = False) -> dict[str, Any]:
        """Internal index — assumes fence (if any) is already held."""
        started = time.perf_counter(); root = root.expanduser().resolve(strict=True); root_identity = _root_identity(root)
        if full_reindex: self.cache.clear_repository(repository_id, root_identity)
        if self._source_access is None:
            paths, rejected_paths, truncated, truncation_reasons = _enumerate_files_bounded(
                root, self.ignored_dirs, self.limits
            )
        else:
            paths, rejected_paths, truncated, truncation_reasons = (
                self._source_access.enumerate_files(root, self.ignored_dirs, self.limits)
            )
        current = {path.relative_to(root).as_posix() for path in paths}
        indexed = await self.store.indexed_paths(repository_id)
        scanned_bytes = 0
        for path in paths:
            try:
                scanned_bytes += int(self._stat(root, path).st_size)
            except OSError:
                truncated = True
                truncation_reasons.append(f"stat-race:{path.relative_to(root).as_posix()}")
        report: dict[str, Any] = {"scanned_files": len(paths), "scanned_bytes": scanned_bytes, "parsed_files": 0, "incremental_files": 0, "full_fallback_files": 0, "unchanged_files": 0, "deleted_files": 0, "unsupported_files": 0, "failed_files": 0, "stale_read_files": 0, "statuses": {}, "rejected_paths": rejected_paths, "truncated": truncated, "truncation_reasons": truncation_reasons}
        deleted_paths: set[str] = set()
        changed_paths: set[str] = set()
        # A bounded walk cannot prove that an unseen path was deleted.  Keep
        # the prior row and mark the projection partial until a later complete
        # refresh can reconcile the manifest.
        if not truncated:
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
            elif status == "skipped-bound":
                report["truncated"] = True
                report["truncation_reasons"].append(f"file-limit:{relative}")
        report.update({f"cache_{key}": value for key, value in self.cache.stats().items()})
        # Run semantic resolution if a resolution service is configured
        if self._resolution_service is not None:
            try:
                resolution_kwargs = {
                    "changed_paths": changed_paths,
                    "deleted_paths": deleted_paths,
                    "full_rebuild": full_reindex,
                }
                if self._source_access is not None:
                    resolution_kwargs["source_reader"] = self._source_access
                resolution_report = self._resolution_service.resolve(
                    repository_id, root, **resolution_kwargs
                )
                report["resolution"] = resolution_report.to_dict()
            except (RuntimeError, ValueError) as exc:
                report["resolution_error"] = str(exc)
        report["total_duration_ms"] = (time.perf_counter() - started) * 1000
        return report

    async def refresh_paths(
        self,
        repository_id: str,
        root: Path,
        paths: tuple[str, ...] | list[str] | set[str],
        *,
        workspace_id: str | None = None,
        deleted_paths: tuple[str, ...] | list[str] | set[str] = (),
    ) -> dict[str, Any]:
        """Refresh an explicit bounded path set without walking the root.

        The caller owns mutation admission.  This method only updates the
        derived index and, when configured, the semantic graph for paths
        affected by those updates.
        """
        if self._closed:
            raise RuntimeError("RepositoryIndexer is closed")
        if self._mutation_fence is not None:
            if not workspace_id or self._fence_workspace_resolver is None:
                raise RuntimeError("workspace-scoped fenced refresh requires an owner")
            if self._fence_workspace_resolver(repository_id, workspace_id) != workspace_id:
                raise RuntimeError("repository/workspace mutation scope is invalid or ambiguous")
            async with self._mutation_fence.use(workspace_id, owner=f"indexer:{repository_id}"):
                return await self._refresh_paths_impl(repository_id, root, paths, deleted_paths=deleted_paths)
        return await self._refresh_paths_impl(repository_id, root, paths, deleted_paths=deleted_paths)

    async def _refresh_paths_impl(
        self,
        repository_id: str,
        root: Path,
        paths: tuple[str, ...] | list[str] | set[str],
        *,
        deleted_paths: tuple[str, ...] | list[str] | set[str] = (),
    ) -> dict[str, Any]:
        started = time.perf_counter()
        root = root.expanduser().resolve(strict=True)
        root_identity = _root_identity(root)
        requested = sorted({_normalize_index_path(path) for path in paths})
        deleted = sorted({_normalize_index_path(path) for path in deleted_paths})
        report: dict[str, Any] = {
            "scanned_files": len(requested),
            "scanned_bytes": 0,
            "parsed_files": 0,
            "incremental_files": 0,
            "full_fallback_files": 0,
            "unchanged_files": 0,
            "deleted_files": 0,
            "unsupported_files": 0,
            "failed_files": 0,
            "stale_read_files": 0,
            "statuses": {},
            "rejected_paths": [],
            "truncated": False,
            "truncation_reasons": [],
        }
        changed_paths: set[str] = set()
        deleted_seen: set[str] = set()
        for relative in deleted:
            # Rename/move observers may conservatively include the new path.
            # Only remove it eagerly when it is actually absent; an existing
            # path remains in the explicit refresh set below.
            if self._exists(root, relative):
                continue
            await self.store.remove(repository_id, relative)
            self.cache.remove_path(repository_id, root_identity, relative)
            report["statuses"][relative] = "deleted"
            report["deleted_files"] += 1
            deleted_seen.add(relative)
        # Persisted mutation events only carry bounded paths, not a separate
        # deleted-path column.  Re-check every requested path before parsing
        # so a DELETE/RENAME/MOVE observed before a process restart removes a
        # ghost row instead of recording a parse failure and leaving stale
        # symbols queryable.
        for relative in requested:
            if relative in deleted_seen or self._exists(root, relative):
                continue
            await self.store.remove(repository_id, relative)
            self.cache.remove_path(repository_id, root_identity, relative)
            report["statuses"][relative] = "deleted"
            report["deleted_files"] += 1
            deleted_seen.add(relative)
        work = [relative for relative in requested if relative not in deleted_seen]
        results = await asyncio.gather(
            *(
                self._refresh_file(
                    repository_id,
                    root,
                    root_identity,
                    root / Path(relative),
                    False,
                )
                for relative in work
            )
        )
        for relative, status in results:
            report["statuses"][relative] = status
            try:
                report["scanned_bytes"] += int(self._stat(root, root / Path(relative)).st_size)
            except OSError:
                pass
            if status == "unchanged":
                report["unchanged_files"] += 1
            elif status == "unsupported":
                report["unsupported_files"] += 1
            elif status == "stale-read":
                report["stale_read_files"] += 1
                report["failed_files"] += 1
            elif status == "parse-failed":
                report["failed_files"] += 1
            elif status.startswith("indexed-"):
                report["parsed_files"] += 1
                changed_paths.add(relative)
                if status == "indexed-incremental":
                    report["incremental_files"] += 1
                if status == "indexed-full-fallback":
                    report["full_fallback_files"] += 1
        if self._resolution_service is not None:
            try:
                resolution_kwargs = {
                    "changed_paths": changed_paths,
                    "deleted_paths": deleted_seen,
                    "full_rebuild": False,
                }
                if self._source_access is not None:
                    resolution_kwargs["source_reader"] = self._source_access
                resolution_report = self._resolution_service.resolve(
                    repository_id, root, **resolution_kwargs
                )
                report["resolution"] = resolution_report.to_dict()
            except (RuntimeError, ValueError) as exc:
                report["resolution_error"] = str(exc)
        report.update({f"cache_{key}": value for key, value in self.cache.stats().items()})
        report["total_duration_ms"] = (time.perf_counter() - started) * 1000
        return report

    async def _refresh_file(self, repository_id: str, root: Path, root_identity: str, path: Path, force: bool) -> tuple[str, str]:
        relative = path.relative_to(root).as_posix(); lock_key = (repository_id, relative)
        async with self._locks_guard: lock = self._file_locks.setdefault(lock_key, asyncio.Lock())
        try:
            async with lock:
                if self._closed: raise RuntimeError("RepositoryIndexer is closed")
                if self._source_access is None and path.is_symlink():
                    return relative, "parse-failed"
                resolution = self.registry.resolve(relative)
                if not resolution.supported: return relative, "unsupported"
                for attempt in range(2):
                    before = self._stat(root, path)
                    if before.st_size > self.limits.max_file_bytes:
                        return relative, "rejected-oversized"
                    content = self._read_bytes(root, relative, path)
                    if len(content) > self.limits.max_file_bytes:
                        return relative, "rejected-oversized"
                    digest = hashlib.sha256(content).hexdigest()
                    existing = await self.store.file_record(repository_id, relative)
                    if not force and existing and existing["content_hash"] == digest: return relative, "unchanged"
                    cached = None if force else self.cache.find(repository_id, root_identity, relative)
                    result = await asyncio.to_thread(self.registry.parse, file_path=str(path), content=content, previous_state=cached.parse_state if cached else None)
                    after = self._stat(root, path)
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

    def _stat(self, root: Path, path: Path) -> os.stat_result:
        if self._source_access is None:
            return path.stat()
        relative = path.relative_to(root).as_posix()
        return self._source_access.stat(root, relative)

    def _read_bytes(self, root: Path, relative: str, path: Path) -> bytes:
        if self._source_access is None:
            return path.read_bytes()
        return self._source_access.read_bytes(
            root,
            relative,
            max_bytes=self.limits.max_file_bytes,
        )

    def _exists(self, root: Path, relative: str) -> bool:
        if self._source_access is None:
            return (root / Path(relative)).exists()
        return self._source_access.exists(root, relative)

    async def close(self) -> None:
        self._closed = True; self.cache.clear(); await self.store.close()


def _root_identity(root: Path) -> str:
    stat = root.stat(); return f"{root}:{getattr(stat, 'st_dev', 0)}:{getattr(stat, 'st_ino', 0)}"


def _enumerate_files(root: Path, ignored: set[str]) -> tuple[list[Path], list[str]]:
    files, rejected, _, _ = _enumerate_files_bounded(root, ignored, RepositoryIndexLimits())
    return files, rejected


def _enumerate_files_bounded(
    root: Path,
    ignored: set[str],
    limits: RepositoryIndexLimits,
) -> tuple[list[Path], list[str], bool, list[str]]:
    files: list[Path] = []; rejected: list[str] = []; seen: set[tuple[int, int]] = set()
    truncated = False
    truncation_reasons: list[str] = []
    total_bytes = 0
    started = time.monotonic()
    for directory, dirs, names in os.walk(root, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        if len(relative_directory.parts) > limits.max_depth:
            truncated = True
            truncation_reasons.append(f"max-depth:{relative_directory.as_posix()}")
            dirs[:] = []
            continue
        dirs[:] = sorted(name for name in dirs if name not in ignored and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            if time.monotonic() - started > limits.max_duration_seconds:
                truncated = True
                truncation_reasons.append("max-duration")
                return sorted(files), rejected, truncated, sorted(set(truncation_reasons))
            if len(files) >= limits.max_files:
                truncated = True
                truncation_reasons.append("max-files")
                return sorted(files), rejected, truncated, sorted(set(truncation_reasons))
            path = Path(directory) / name
            try:
                if path.is_symlink():
                    raise OSError("symlink file is not indexable")
                resolved = path.resolve(strict=True); resolved.relative_to(root); stat = resolved.stat()
                if not os.path.isfile(resolved):
                    raise OSError("not a regular file")
            except (OSError, ValueError):
                rejected.append(path.relative_to(root).as_posix()); continue
            identity = (stat.st_dev, stat.st_ino)
            if identity in seen: continue
            if total_bytes + stat.st_size > limits.max_bytes:
                truncated = True
                truncation_reasons.append("max-bytes")
                return sorted(files), rejected, truncated, sorted(set(truncation_reasons))
            seen.add(identity); files.append(resolved)
            total_bytes += stat.st_size
    return sorted(files), rejected, truncated, sorted(set(truncation_reasons))


def _normalize_index_path(value: str) -> str:
    if type(value) is not str or not value:
        raise ValueError("indexed path must be a non-empty string")
    candidate = PurePosixPath(value.replace("\\", "/"))
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("indexed path must be normalized and workspace-relative")
    return candidate.as_posix()
