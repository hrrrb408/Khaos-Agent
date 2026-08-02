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

    Round-14 §6: the historical ``read_file`` / ``write_file`` / ``exec``
    convenience methods were removed together with the corresponding Rust
    handlers.  They performed raw filesystem/process operations with no path
    authorization and no sandbox, so a single ``run_parallel_json`` call could
    bypass the entire Python security stack (Sandbox / PathGuard /
    CommandGuard / PermissionEngine).  Token counting — the only production
    consumer of the Rust extension — is unaffected.
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


def get_token_engine(encoding: str = "cl100k_base") -> SimpleTokenEngine:
    """Factory: prefer Rust, fall back to the pure-Python SimpleTokenEngine.

    Use this anywhere token counting is needed so the runtime transparently
    upgrades when the Rust extension is present.
    """
    try:
        return RustTokenizer(encoding)
    except RuntimeError:
        return SimpleTokenEngine()


def execute_parallel(calls: list[dict], timeout_ms: int) -> list[dict] | None:
    """Run calls on the Rust executor, or return None when unavailable.

    Only pure-compute handler kinds (echo / sleep / sum / fail) are accepted
    by the Rust side; the file/exec handlers were removed (Round-14 §6).
    """
    try:
        return RustToolExecutor().run_parallel(calls, timeout_ms)
    except RuntimeError:
        return None


__all__ = [
    "RustTokenizer",
    "RustToolExecutor",
    "execute_parallel",
    "get_token_engine",
    "load_rust_module",
    "rust_available",
]
