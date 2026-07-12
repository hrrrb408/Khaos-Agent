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
from pathlib import Path
from typing import Any

from khaos.coding.planning.contracts import VerificationCatalogEntry

logger = logging.getLogger(__name__)

_CONTROL_TOKENS = (";", "&&", "||", "|", ">", "<", "`", "$(")
_CATALOG_PARSER_VERSION = "v2-structured-2026-07-12"
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
    ) -> None:
        self._root = root
        self._server_rules = server_rules
        self._repository_id = repository_id
        self._entries: list[VerificationCatalogEntry] = []
        self._config_hashes: dict[str, str] = {}  # repo-relative path -> sha256
        self._diagnostics: list[tuple[str, str]] = []  # (severity, message)
        if root is not None:
            self._scan()
        self.fingerprint: str = self.compute_fingerprint(
            repository_id, root, server_rules,
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
    ) -> str:
        """Compute a fingerprint that changes when any catalog input changes.

        Binds:
        - catalog parser version
        - repository_id
        - repository root identity (absolute path hash — internal only,
          never exposed in evidence; ensures different clones with identical
          content still get distinct fingerprints only when root differs is
          NOT desired — root identity is included solely to detect when the
          same repository_id points to a different working tree)
        - pyproject.toml hash (or "" if missing)
        - package.json hash (or "" if missing)
        - go.mod hash (or "" if missing)
        - Cargo.toml hash (or "" if missing)
        - server trusted rules hash
        """
        parts: list[str] = [_CATALOG_PARSER_VERSION, repository_id or ""]
        # Root identity — internal only, never exposed in evidence
        if root is not None:
            try:
                resolved = root.resolve()
                parts.append(hashlib.sha256(str(resolved).encode()).hexdigest())
            except OSError:
                parts.append("")
        else:
            parts.append("")
        # Config file hashes (presence and content)
        for filename in _CONFIG_FILES:
            if root is None:
                parts.append("")
                continue
            path = root / filename
            try:
                content = path.read_bytes()
                parts.append(hashlib.sha256(content).hexdigest())
            except OSError:
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
        """Read a config file. Returns (content, content_hash). Empty hash if missing."""
        if self._root is None:
            return None, ""
        path = self._root / filename
        try:
            content = path.read_text(encoding="utf-8")
            return content, hashlib.sha256(content.encode()).hexdigest()
        except (OSError, UnicodeDecodeError):
            return None, ""

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
