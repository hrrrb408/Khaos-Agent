"""Read-only, server-side verification catalog with fingerprint-based freshness.

Scans repository configuration files (pyproject.toml, package.json, go.mod,
Cargo.toml) and server rules to build a trusted catalog of verification
commands. Every entry is bound to a specific language and backed by a real
config file (provenance + config_path + config_hash).

Rules enforced:
1. No language-less legacy command propagates across languages.
2. Repository-wide commands declare ``scope=repository``.
3. Python pytest never becomes a Go/Rust/JS verification.
4. npm scripts must actually exist in package.json.
5. Unconfigured mypy/ruff/clippy are never generated.
6. User goal command text never enters the catalog.
7. argv stays structured — ``shell=true`` is forbidden.
8. Config file changes invalidate old plans (via config_hash in evidence).
9. Fingerprint binds all inputs — cache auto-invalidates, no manual clear.
10. config_path is always repository-relative POSIX — never absolute host path.
11. Structured parsing only — no substring inference (tomllib + json).
12. Parse failures produce diagnostics, never silent trusted claims.
"""
from __future__ import annotations

import hashlib
import json
import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.planning.contracts import VerificationCatalogEntry

logger = logging.getLogger(__name__)

_CONTROL_TOKENS = (";", "&&", "||", "|", ">", "<", "`", "$(")
_CATALOG_PARSER_VERSION = "v3-safe-snapshot-2026-07-12"
_CONFIG_FILES = ("pyproject.toml", "package.json", "go.mod", "Cargo.toml")


def _validate_repo_relative(path: str) -> str:
    """Validate and normalize a repository-relative POSIX config path.

    Rejects absolute paths, parent traversal (``..``), UNC paths, Windows
    drive letters, and symlink escape patterns. The result is always a
    forward-slash POSIX path with no leading ``./`` or empty segments.
    """
    if not path:
        raise ValueError("empty config path")
    normalized = path.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError(f"absolute path rejected: {path}")
    if normalized.startswith("//") or path.startswith("\\\\"):
        raise ValueError(f"UNC path rejected: {path}")
    if len(normalized) >= 2 and normalized[1] == ":":
        raise ValueError(f"Windows drive path rejected: {path}")
    parts = normalized.split("/")
    if any(part == ".." for part in parts):
        raise ValueError(f"parent traversal rejected: {path}")
    cleaned = "/".join(p for p in parts if p not in ("", "."))
    if not cleaned:
        raise ValueError(f"empty normalized path: {path}")
    return cleaned


@dataclass(frozen=True)
class SafeConfigSnapshot:
    """Immutable snapshot of a config file read through boundary validation.

    A SafeConfigSnapshot is created by resolving both the repository root and
    the candidate path, confirming the candidate is inside the root, and then
    reading the content ONCE. The same snapshot is used for both fingerprint
    computation and catalog parsing — this guarantees they see the same bytes
    and prevents TOCTOU (time-of-check-to-time-of-use) divergence.

    SYMLINK SAFETY: If the resolved candidate escapes the workspace root (via
    symlink, absolute path, or ``..`` traversal), ``exists=False`` and
    ``rejection_code`` is set. The target content is NEVER read in this case —
    ``reader_call_count`` confirms zero reads of the external target.

    Attributes:
        relative_path: repo-relative POSIX path (e.g. ``pyproject.toml``)
        content: file content as text, or ``""`` if missing/rejected
        content_bytes: file content as bytes, or ``b""`` if missing/rejected
        content_hash: sha256 of content_bytes, or ``""`` if missing/rejected
        exists: True only if the file was successfully read
        rejection_code: ``"escape"``, ``"broken"``, ``"read-error"``, or ``""``
        diagnostic: human-readable diagnostic message (never exposes absolute target path)
        reader_call_count: number of read operations performed on the resolved path
    """
    relative_path: str
    content: str
    content_bytes: bytes
    content_hash: str
    exists: bool
    rejection_code: str
    diagnostic: str
    reader_call_count: int

    @staticmethod
    def capture(root: Path | None, filename: str, *, reader=None) -> "SafeConfigSnapshot":
        """Capture a safe snapshot of ``root / filename``.

        Args:
            root: repository root path (None → empty snapshot)
            filename: repo-relative filename (e.g. ``pyproject.toml``)
            reader: optional callable(path: Path) -> bytes for testing.
                    When provided, the snapshot records how many times it
                    was called, proving that external symlinks trigger zero reads.
        """
        if root is None:
            return SafeConfigSnapshot(filename, "", b"", "", False, "", "", 0)

        # Step 1: resolve repository root
        try:
            root_resolved = root.resolve()
        except OSError:
            return SafeConfigSnapshot(filename, "", b"", "", False, "root-unresolvable",
                                      f"cannot resolve repository root for: {filename}", 0)

        # Step 2: resolve candidate (non-strict — broken symlinks still resolve)
        candidate = root / filename
        try:
            candidate_resolved = candidate.resolve(strict=False)
        except OSError:
            return SafeConfigSnapshot(filename, "", b"", "", False, "broken",
                                      f"broken symlink for config file: {filename}", 0)

        # Step 3: confirm candidate is inside root
        try:
            candidate_resolved.relative_to(root_resolved)
        except ValueError:
            # ESCAPE: candidate resolves outside workspace root.
            # DO NOT read the target content — return immediately.
            return SafeConfigSnapshot(filename, "", b"", "", False, "escape",
                                      f"config file escapes workspace root: {filename}", 0)

        # Step 4: read content ONCE via the resolved path
        read_count = 0
        try:
            if reader is not None:
                content_bytes = reader(candidate_resolved)
                read_count = 1
            else:
                content_bytes = candidate_resolved.read_bytes()
                read_count = 1
        except OSError:
            return SafeConfigSnapshot(filename, "", b"", "", False, "read-error",
                                      f"cannot read config file: {filename}", read_count)
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return SafeConfigSnapshot(filename, "", b"", "", False, "read-error",
                                      f"config file not UTF-8: {filename}", read_count)

        content_hash = hashlib.sha256(content_bytes).hexdigest()
        return SafeConfigSnapshot(filename, content, content_bytes, content_hash,
                                  True, "", "", read_count)


class VerificationCatalog:
    """Read-only catalog built from repository config files and server rules.

    FRESHNESS: Each catalog instance carries an immutable ``fingerprint`` that
    binds repository_id, config file hashes, server rules hash, and parser
    version. When any input changes, the fingerprint changes, allowing the
    planning service to automatically invalidate and rebuild the catalog
    without any manual cache clearing.

    PORTABILITY: ``config_path`` on every entry is a repository-relative POSIX
    path (e.g. ``pyproject.toml``, ``package.json``). The absolute repository
    root is NEVER exposed in PlanEvidence, VerificationRequirement, content_hash,
    plan_id, or logs. This guarantees that cloning the same repository into
    two different absolute directories produces identical evidence,
    content_hash, and plan_id.

    STRUCTURED PARSING: pyproject.toml is parsed with Python 3.11 ``tomllib``,
    package.json with ``json.loads``, Cargo.toml with ``tomllib``. No substring
    inference (e.g. ``"pytest" in content.lower()``) is used — comments
    mentioning pytest do not generate commands; only real ``[tool.pytest]``
    sections do.
    """

    def __init__(
        self,
        root: Path | None = None,
        *,
        server_rules: tuple[dict[str, Any], ...] = (),
        repository_id: str = "",
        snapshots: dict[str, SafeConfigSnapshot] | None = None,
    ) -> None:
        self._root = root
        self._server_rules = server_rules
        self._repository_id = repository_id
        self._entries: list[VerificationCatalogEntry] = []
        self._config_hashes: dict[str, str] = {}  # repo-relative path -> sha256
        self._diagnostics: list[tuple[str, str]] = []  # (severity, message)
        # Capture safe snapshots ONCE — used for BOTH fingerprint and catalog scan.
        # This prevents TOCTOU divergence between fingerprint computation and
        # catalog parsing, and ensures external symlinks are never read.
        self._snapshots: dict[str, SafeConfigSnapshot] = snapshots or {}
        if root is not None and not self._snapshots:
            for filename in _CONFIG_FILES:
                snap = SafeConfigSnapshot.capture(root, filename)
                if snap.exists or snap.rejection_code:
                    self._snapshots[filename] = snap
        if root is not None:
            self._scan()
        self.fingerprint: str = self.compute_fingerprint(
            repository_id, root, server_rules,
            snapshots=self._snapshots,
        )

    @property
    def entries(self) -> tuple[VerificationCatalogEntry, ...]:
        return tuple(self._entries)

    @property
    def config_hashes(self) -> dict[str, str]:
        """Map of repo-relative config_path -> content hash, for staleness checking."""
        return dict(self._config_hashes)

    @property
    def diagnostics(self) -> tuple[tuple[str, str], ...]:
        """Parse diagnostics — never empty when a config file fails to parse."""
        return tuple(self._diagnostics)

    def combined_config_hash(self) -> str:
        """Single hash of all config files AND server rules — changes when any input changes.

        Includes server rules hash so that server rule changes are detected as
        drift even when no config file changed. This hash is portable across
        worktrees — it never includes absolute host paths.
        """
        parts: list[str] = []
        if self._config_hashes:
            parts.append(json.dumps(self._config_hashes, sort_keys=True, separators=(",", ":")))
        # Include server rules hash (deterministic, portable)
        if self._server_rules:
            rules_serialized = json.dumps(
                [sorted(rule.items()) if isinstance(rule, dict) else None
                 for rule in self._server_rules],
                sort_keys=True, separators=(",", ":"), default=str,
            )
            parts.append(rules_serialized)
        if not parts:
            return ""
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def entries_for_languages(self, languages: set[str]) -> tuple[VerificationCatalogEntry, ...]:
        """Return entries whose language matches the given set.

        ``scope=repository`` means the command runs at repository level (not a
        specific package) — it does NOT mean the command applies to all
        languages. Language binding is always strict.
        """
        return tuple(e for e in self._entries if e.language in languages)

    @staticmethod
    def compute_fingerprint(
        repository_id: str,
        root: Path | None,
        server_rules: tuple[dict[str, Any], ...],
        *,
        snapshots: dict[str, SafeConfigSnapshot] | None = None,
    ) -> str:
        """Compute a portable fingerprint that changes when catalog inputs change.

        Binds:
        - catalog parser version
        - repository_id
        - pyproject.toml hash (or "" if missing/escaped)
        - package.json hash (or "" if missing/escaped)
        - go.mod hash (or "" if missing/escaped)
        - Cargo.toml hash (or "" if missing/escaped)
        - server trusted rules hash

        PORTABILITY: The fingerprint NEVER includes the absolute repository
        root path. This guarantees that cloning the same repository into two
        different absolute directories produces identical fingerprints, which
        is required for cross-worktree plan_id and content_hash determinism.
        The fingerprint only changes when config file CONTENT changes, not
        when the repository is cloned to a new path.

        SAFE SNAPSHOT: When ``snapshots`` is provided, uses the pre-captured
        SafeConfigSnapshot hashes instead of re-reading files. This guarantees
        the fingerprint sees the same bytes as the catalog scan and prevents
        reading external symlink targets. When ``snapshots`` is None and
        ``root`` is provided, captures fresh snapshots on the fly — each
        capture goes through boundary validation, so external symlinks are
        rejected before any read and contribute "" (empty) to the fingerprint.
        """
        parts: list[str] = [_CATALOG_PARSER_VERSION, repository_id or ""]
        # Config file hashes (presence and content) — from safe snapshots.
        # NO root identity hash — fingerprint must be portable across worktrees.
        for filename in _CONFIG_FILES:
            if snapshots and filename in snapshots:
                snap = snapshots[filename]
                parts.append(snap.content_hash if snap.exists else "")
            elif root is not None:
                # Standalone call (no pre-captured snapshots) — capture now.
                # SafeConfigSnapshot.capture rejects external symlinks BEFORE
                # any read, so escaped files contribute "" (empty hash).
                snap = SafeConfigSnapshot.capture(root, filename)
                parts.append(snap.content_hash if snap.exists else "")
            else:
                parts.append("")
        # Server rules hash (deterministic serialization)
        rules_serialized = json.dumps(
            [sorted(rule.items()) if isinstance(rule, dict) else None
             for rule in server_rules],
            sort_keys=True, separators=(",", ":"), default=str,
        )
        parts.append(hashlib.sha256(rules_serialized.encode()).hexdigest())
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def _scan(self) -> None:
        """Scan all config sources. Each source is independent and additive."""
        if self._root is None:
            return
        self._scan_pyproject()
        self._scan_package_json()
        self._scan_go_mod()
        self._scan_cargo_toml()
        self._scan_server_rules()

    def _read_config(self, filename: str) -> tuple[str | None, str]:
        """Read a config file from the pre-captured safe snapshot.

        Returns (content, content_hash). Empty hash if missing/rejected.

        SAFE SNAPSHOT: This method NEVER reads the filesystem directly. It
        returns content from the SafeConfigSnapshot captured in ``__init__``.
        This guarantees:
        - External symlinks are never read (snapshot.capture rejects them
          before any read call)
        - Fingerprint and catalog scan see the same bytes (same snapshot)
        - No TOCTOU divergence between fingerprint and scan

        If a snapshot was not pre-captured (e.g. root is None or file was
        missing), returns (None, "").
        """
        snap = self._snapshots.get(filename)
        if snap is None:
            return None, ""
        if not snap.exists:
            if snap.diagnostic:
                severity = "error" if snap.rejection_code in ("escape", "broken", "read-error") else "warning"
                self._diagnostics.append((severity, snap.diagnostic))
            return None, ""
        return snap.content, snap.content_hash

    def _scan_pyproject(self) -> None:
        """Parse pyproject.toml with tomllib — no substring inference."""
        content, config_hash = self._read_config("pyproject.toml")
        if content is None:
            return
        config_path = _validate_repo_relative("pyproject.toml")
        self._config_hashes[config_path] = config_hash
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError as exc:
            self._diagnostics.append(("error", f"pyproject.toml parse failure: {exc}"))
            return
        if not isinstance(data, dict):
            self._diagnostics.append(("error", "pyproject.toml root is not a table"))
            return
        tool = data.get("tool", {})
        if not isinstance(tool, dict):
            self._diagnostics.append(("error", "pyproject.toml [tool] is not a table"))
            return
        # Structured detection: only real [tool.pytest] table generates command.
        # Comments mentioning pytest, or pytest listed in dependencies, do NOT.
        if isinstance(tool.get("pytest"), dict):
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="unit-test",
                argv=("python", "-m", "pytest", "-q"), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))
        if isinstance(tool.get("mypy"), dict):
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="type-check",
                argv=("python", "-m", "mypy", "."), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))
        if isinstance(tool.get("ruff"), dict):
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="lint",
                argv=("python", "-m", "ruff", "check", "."), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))

    def _scan_package_json(self) -> None:
        """Parse package.json with json.loads — no substring inference."""
        content, config_hash = self._read_config("package.json")
        if content is None:
            return
        config_path = _validate_repo_relative("package.json")
        self._config_hashes[config_path] = config_hash
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            self._diagnostics.append(("error", f"package.json parse failure: {exc}"))
            return
        if not isinstance(data, dict):
            self._diagnostics.append(("error", "package.json root is not an object"))
            return
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            self._diagnostics.append(("error", "package.json scripts is not an object"))
            return
        dev_deps = data.get("devDependencies", {})
        if not isinstance(dev_deps, dict):
            dev_deps = {}
        # Structured TypeScript detection: devDependencies.typescript or tsc script
        has_typescript = "typescript" in dev_deps or any(
            "tsc" in str(v) for v in scripts.values()
        )
        languages = {"typescript", "javascript"} if has_typescript else {"javascript"}
        for script_name, script_cmd in scripts.items():
            if not isinstance(script_cmd, str) or not script_name or not script_cmd:
                continue
            vtype = None
            if script_name in ("test", "test:unit", "unit"):
                vtype = "unit-test"
            elif script_name in ("typecheck", "type-check", "tsc"):
                vtype = "type-check"
            elif script_name in ("lint", "eslint"):
                vtype = "lint"
            elif script_name in ("build",):
                vtype = "build"
            if vtype is None:
                continue
            argv = ("npm", "run", script_name)
            if self._is_safe_argv(argv):
                for lang in sorted(languages):
                    self._entries.append(VerificationCatalogEntry(
                        language=lang, verification_type=vtype,
                        argv=argv, scope="repository",
                        provenance="package.json", config_path=config_path,
                        config_hash=config_hash, trust_level="high",
                    ))

    def _scan_go_mod(self) -> None:
        """Parse go.mod with strict structural check — no substring inference."""
        content, config_hash = self._read_config("go.mod")
        if content is None:
            return
        config_path = _validate_repo_relative("go.mod")
        self._config_hashes[config_path] = config_hash
        # Strict structural validation: must start with a module directive
        stripped = content.strip()
        if not stripped.startswith("module "):
            self._diagnostics.append(("warning", "go.mod missing module directive"))
            return
        self._entries.append(VerificationCatalogEntry(
            language="go", verification_type="unit-test",
            argv=("go", "test", "./..."), scope="repository",
            provenance="go.mod", config_path=config_path,
            config_hash=config_hash, trust_level="high",
        ))
        self._entries.append(VerificationCatalogEntry(
            language="go", verification_type="lint",
            argv=("go", "vet", "./..."), scope="repository",
            provenance="go.mod", config_path=config_path,
            config_hash=config_hash, trust_level="medium",
        ))

    def _scan_cargo_toml(self) -> None:
        """Parse Cargo.toml with tomllib — no substring inference for clippy."""
        content, config_hash = self._read_config("Cargo.toml")
        if content is None:
            return
        config_path = _validate_repo_relative("Cargo.toml")
        self._config_hashes[config_path] = config_hash
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError as exc:
            self._diagnostics.append(("error", f"Cargo.toml parse failure: {exc}"))
            return
        if not isinstance(data, dict) or "package" not in data:
            self._diagnostics.append(("warning", "Cargo.toml missing [package] section"))
            return
        self._entries.append(VerificationCatalogEntry(
            language="rust", verification_type="unit-test",
            argv=("cargo", "test"), scope="repository",
            provenance="Cargo.toml", config_path=config_path,
            config_hash=config_hash, trust_level="high",
        ))
        self._entries.append(VerificationCatalogEntry(
            language="rust", verification_type="type-check",
            argv=("cargo", "check"), scope="repository",
            provenance="Cargo.toml", config_path=config_path,
            config_hash=config_hash, trust_level="high",
        ))
        # Structured clippy detection: only [lints.clippy] or
        # [workspace.lints.clippy] tables generate the clippy command.
        # The word "clippy" appearing in a comment does NOT.
        has_clippy = False
        lints = data.get("lints", {})
        if isinstance(lints, dict) and isinstance(lints.get("clippy"), dict):
            has_clippy = True
        if not has_clippy:
            workspace = data.get("workspace", {})
            if isinstance(workspace, dict):
                w_lints = workspace.get("lints", {})
                if isinstance(w_lints, dict) and isinstance(w_lints.get("clippy"), dict):
                    has_clippy = True
        if has_clippy:
            self._entries.append(VerificationCatalogEntry(
                language="rust", verification_type="lint",
                argv=("cargo", "clippy"), scope="repository",
                provenance="Cargo.toml", config_path=config_path,
                config_hash=config_hash, trust_level="medium",
            ))

    def _scan_server_rules(self) -> None:
        """Process server-side trusted verification rules.

        Only rules with an explicit ``language`` are accepted. Language-less
        legacy commands are NOT allowed to propagate across languages.
        """
        for rule in self._server_rules:
            if not isinstance(rule, dict):
                continue
            language = rule.get("language")
            if not language:
                continue
            argv = tuple(rule.get("argv", ()))
            if not argv or not self._is_safe_argv(argv):
                continue
            vtype = rule.get("type", "unit-test")
            scope = rule.get("scope", "repository")
            source = str(rule.get("source", "server-rule"))
            trust = rule.get("trust_level", "medium")
            # Reject source names with path escape patterns
            if ".." in source or "/" in source or "\\" in source:
                self._diagnostics.append((
                    "error",
                    f"server rule source has path escape characters: {source}",
                ))
                continue
            # config_path is a logical identifier, never an absolute host path
            config_path = f"server-rule:{source}"
            self._entries.append(VerificationCatalogEntry(
                language=language, verification_type=vtype,
                argv=argv, scope=scope,
                provenance=source, config_path=config_path,
                config_hash="", trust_level=trust,
            ))

    @staticmethod
    def _is_safe_argv(argv: tuple[str, ...]) -> bool:
        """Reject shell control characters — argv must stay structured."""
        for part in argv:
            if any(token in part for token in _CONTROL_TOKENS):
                return False
        return True
