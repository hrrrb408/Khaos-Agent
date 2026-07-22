"""Bridge between Python and the Rust `_khaos_core` native extension.

The extension is built with PyO3 and lives at
``rust/khaos-core/target/<profile>/lib_khaos_core.{so,dylib}``. This module
loads it lazily and exposes thin Python wrappers. When the extension is not
built (e.g. in a clean checkout), ``load_rust_module`` returns ``None`` and the
public helpers fall back to the pure-Python ``SimpleTokenEngine``, so the rest
of Khaos keeps working without a Rust toolchain.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
from pathlib import Path
from typing import Any, Callable, Optional

from khaos.agent.core import SimpleTokenEngine

logger = logging.getLogger(__name__)

_MODULE_NAME = "_khaos_core"
_LIB_BASENAME = "lib_khaos_core"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # python/khaos/ -> python/ -> repo root
_TARGET_DIR = _PROJECT_ROOT / "rust" / "khaos-core" / "target"
_CANDIDATE_SUFFIXES = (".so", ".dylib")
_CANDIDATE_PROFILES = ("release", "debug")


def load_rust_module():
    """Load the compiled Rust extension, or return None if unavailable.

    Prefer the extension installed by Maturin, which carries the correct
    Python ABI filename and linker metadata. Fall back to release/debug
    artifacts for developer builds.
    """
    try:
        return importlib.import_module(_MODULE_NAME)
    except ImportError:
        pass
    for profile in _CANDIDATE_PROFILES:
        for suffix in _CANDIDATE_SUFFIXES:
            candidate = _TARGET_DIR / profile / f"{_LIB_BASENAME}{suffix}"
            if candidate.exists():
                return _load_from_path(candidate)
    return None


def _load_from_path(path: Path):
    """importlib-load a shared object as ``_khaos_core``.

    On macOS ``.dylib`` is rejected by ``spec_from_file_location``; we copy it
    to a sibling ``.so`` (once) and load that instead.
    """
    load_path = path
    if path.suffix == ".dylib":
        load_path = path.with_name(f"{_MODULE_NAME}.so")
        if not load_path.exists() or load_path.stat().st_mtime < path.stat().st_mtime:
            try:
                load_path.write_bytes(path.read_bytes())
            except OSError as exc:
                logger.debug("cannot stage %s -> %s: %s", path, load_path, exc)
                return None
    try:
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, load_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except ImportError as exc:
        logger.debug("Rust extension present but failed to import: %s", exc)
        return None


def rust_available() -> bool:
    """True when the native extension is loaded and functional."""
    return _cached_module() is not None


def _cached_module():
    """Cache the loaded module on this function to avoid repeated dlopen."""
    cached = getattr(_cached_module, "_module", None)
    if cached is None:
        cached = _sentinel = load_rust_module()
        if cached is None:
            return None
        _cached_module._module = cached  # type: ignore[attr-defined]
    return cached


class RustTokenizer(SimpleTokenEngine):
    """Token engine backed by the Rust heuristic counter."""

    def __init__(self, encoding: str = "cl100k_base"):
        module = _cached_module()
        if module is None:
            raise RuntimeError("Rust extension _khaos_core is not available")
        self._count = module.count_tokens
        self._count_batch = module.count_tokens_batch
        self.encoding = encoding

    def count_tokens(self, text: str) -> int:  # type: ignore[override]
        return int(self._count(text, self.encoding))

    def count_tokens_batch(self, texts: list[str]) -> list[int]:
        return list(self._count_batch(texts, self.encoding))


class RustToolExecutor:
    """Thin wrapper around the Rust parallel executor.

    Calls are JSON-encoded before crossing the FFI boundary; results come back
    as parsed dicts. See ``rust/khaos-core/src/executor.rs`` for the built-in
    handler kinds (echo / sleep / sum / fail).
    """

    def __init__(self):
        module = _cached_module()
        if module is None:
            raise RuntimeError("Rust extension _khaos_core is not available")
        self._run = module.run_parallel_json

    def run_parallel(self, calls: list[dict], timeout_ms: int) -> list[dict]:
        """Run ``calls`` (each ``{id, kind, payload}``) concurrently.

        Returns one result dict per input in input order, regardless of
        per-call success.
        """
        payload = json.dumps(calls, ensure_ascii=False)
        raw = self._run(payload, timeout_ms)
        return list(json.loads(raw))

    def run_one(self, call: dict, timeout_ms: int) -> dict:
        """Convenience: run a single call."""
        return self.run_parallel([call], timeout_ms)[0]

    # --- typed convenience wrappers for the built-in I/O handlers -----------

    def read_file(self, path: str, offset: int | None = None, limit: int | None = None,
                  timeout_ms: int = 5000) -> str:
        """Read a file via the Rust executor. Returns its contents."""
        payload: dict[str, Any] = {"path": path}
        if offset is not None:
            payload["offset"] = offset
        if limit is not None:
            payload["limit"] = limit
        result = self.run_one(
            {"id": "1", "kind": "read_file", "payload": json.dumps(payload)},
            timeout_ms,
        )
        if not result.get("success", False):
            raise OSError(result.get("error", "read_file failed"))
        return str(result.get("output", ""))

    def write_file(self, path: str, content: str, timeout_ms: int = 5000) -> str:
        """Write a file via the Rust executor. Creates parent dirs."""
        payload = json.dumps({"path": path, "content": content})
        result = self.run_one(
            {"id": "1", "kind": "write_file", "payload": payload}, timeout_ms
        )
        if not result.get("success", False):
            raise OSError(result.get("error", "write_file failed"))
        return str(result.get("output", ""))

    def exec_process(self, command: str, args: list[str] | None = None,
                     timeout_ms: int | None = None, workdir: str | None = None,
                     executor_timeout_ms: int = 10000) -> dict[str, Any]:
        """Run a subprocess via the Rust executor. Returns the parsed result.

        The returned dict has ``stdout``, ``stderr`` and ``exit_code``.
        """
        payload: dict[str, Any] = {"command": command, "args": args or []}
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        if workdir is not None:
            payload["workdir"] = workdir
        result = self.run_one(
            {"id": "1", "kind": "exec", "payload": json.dumps(payload)},
            executor_timeout_ms,
        )
        if not result.get("success", False):
            raise subprocess_error(result.get("error", "exec failed"))
        return json.loads(str(result.get("output", "{}")))


def get_token_engine(encoding: str = "cl100k_base") -> SimpleTokenEngine:
    """Factory: prefer Rust, fall back to the pure-Python SimpleTokenEngine.

    Use this anywhere token counting is needed so the runtime transparently
    upgrades when the Rust extension is present.
    """
    try:
        return RustTokenizer(encoding)
    except RuntimeError:
        return SimpleTokenEngine()


def execute_parallel(calls: list[dict], timeout_ms: int) -> Optional[list[dict]]:
    """Run calls on the Rust executor, or return None when unavailable."""
    try:
        return RustToolExecutor().run_parallel(calls, timeout_ms)
    except RuntimeError:
        return None


class subprocess_error(OSError):
    """Raised when the Rust exec handler reports a failure."""


def rust_read_file(path: str, offset: int | None = None, limit: int | None = None) -> str | None:
    """Read a file via Rust, or fall back to Python ``open`` when unbuilt."""
    try:
        return RustToolExecutor().read_file(path, offset, limit)
    except RuntimeError:
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError as exc:
            raise OSError(f"read {path}: {exc}") from exc
        start = (offset or 1) - 1
        if start < 0:
            start = 0
        if limit is not None:
            return "".join(lines[start : start + limit])
        return "".join(lines[start:])


def rust_write_file(path: str, content: str) -> str | None:
    """Write a file via Rust, or fall back to Python when unbuilt."""
    try:
        return RustToolExecutor().write_file(path, content)
    except RuntimeError:
        from pathlib import Path as _Path

        target = _Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {path}"


def rust_exec_process(
    command: str,
    args: list[str] | None = None,
    timeout_ms: int | None = None,
    workdir: str | None = None,
) -> dict[str, Any] | None:
    """Run a subprocess via Rust, or fall back to ``asyncio``-free subprocess."""
    try:
        return RustToolExecutor().exec_process(command, args, timeout_ms, workdir)
    except RuntimeError:
        import subprocess as _sp

        cmd = [command, *(args or [])]
        try:
            completed = _sp.run(
                cmd,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=(timeout_ms / 1000) if timeout_ms else None,
                check=False,
            )
        except _sp.TimeoutExpired as exc:
            raise subprocess_error(f"exec {command}: timeout after {timeout_ms}ms") from exc
        return {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
        }


__all__ = [
    "RustTokenizer",
    "RustToolExecutor",
    "rust_available",
    "load_rust_module",
    "get_token_engine",
    "execute_parallel",
    "rust_read_file",
    "rust_write_file",
    "rust_exec_process",
    "subprocess_error",
]
