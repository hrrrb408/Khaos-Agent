"""Read-only, server-side verification catalog.

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
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from khaos.coding.planning.contracts import VerificationCatalogEntry

logger = logging.getLogger(__name__)

_CONTROL_TOKENS = (";", "&&", "||", "|", ">", "<", "`", "$(")


class VerificationCatalog:
    """Read-only catalog built from repository config files and server rules."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        server_rules: tuple[dict[str, Any], ...] = (),
    ) -> None:
        self._root = root
        self._server_rules = server_rules
        self._entries: list[VerificationCatalogEntry] = []
        self._config_hashes: dict[str, str] = {}  # config_path -> sha256
        if root is not None:
            self._scan()

    @property
    def entries(self) -> tuple[VerificationCatalogEntry, ...]:
        return tuple(self._entries)

    @property
    def config_hashes(self) -> dict[str, str]:
        """Map of config_path -> content hash, for staleness checking."""
        return dict(self._config_hashes)

    def combined_config_hash(self) -> str:
        """Single hash of all config files — changes when any config changes."""
        if not self._config_hashes:
            return ""
        combined = json.dumps(self._config_hashes, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(combined.encode()).hexdigest()

    def entries_for_languages(self, languages: set[str]) -> tuple[VerificationCatalogEntry, ...]:
        """Return entries whose language matches the given set.

        ``scope=repository`` means the command runs at repository level (not a
        specific package) — it does NOT mean the command applies to all
        languages. Language binding is always strict: Python pytest never
        becomes a Go/Rust/JS verification, even when scope=repository.
        """
        return tuple(
            e for e in self._entries
            if e.language in languages
        )

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
        """Read a config file, return (content, content_hash). Empty hash if missing."""
        path = self._root / filename  # type: ignore[union-attr]
        try:
            content = path.read_text(encoding="utf-8")
            return content, hashlib.sha256(content.encode()).hexdigest()
        except (OSError, UnicodeDecodeError):
            return None, ""

    def _scan_pyproject(self) -> None:
        content, config_hash = self._read_config("pyproject.toml")
        if content is None:
            return
        config_path = str(self._root / "pyproject.toml")  # type: ignore[union-attr]
        self._config_hashes["pyproject.toml"] = config_hash
        # Detect configured tools — only generate commands for tools that are
        # actually configured in the file.
        has_pytest = "[tool.pytest" in content or "pytest" in content.lower()
        has_mypy = "[tool.mypy" in content
        has_ruff = "[tool.ruff" in content
        if has_pytest:
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="unit-test",
                argv=("python", "-m", "pytest", "-q"), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))
        if has_mypy:
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="type-check",
                argv=("python", "-m", "mypy", "."), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))
        if has_ruff:
            self._entries.append(VerificationCatalogEntry(
                language="python", verification_type="lint",
                argv=("python", "-m", "ruff", "check", "."), scope="repository",
                provenance="pyproject.toml", config_path=config_path,
                config_hash=config_hash, trust_level="high",
            ))

    def _scan_package_json(self) -> None:
        content, config_hash = self._read_config("package.json")
        if content is None:
            return
        config_path = str(self._root / "package.json")  # type: ignore[union-attr]
        self._config_hashes["package.json"] = config_hash
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            return
        # Detect language from package.json
        dev_deps = data.get("devDependencies", {}) if isinstance(data, dict) else {}
        has_typescript = "typescript" in dev_deps or "tsc" in str(scripts.values())
        # JS/TS share package.json — generate for both if TypeScript is present
        languages = {"typescript", "javascript"} if has_typescript else {"javascript"}
        for script_name, script_cmd in scripts.items():
            if not isinstance(script_cmd, str):
                continue
            if not script_name or not script_cmd:
                continue
            # Map common script names to verification types
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
            # Use npm run <script> as structured argv (no shell=true)
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
        content, config_hash = self._read_config("go.mod")
        if content is None:
            return
        config_path = str(self._root / "go.mod")  # type: ignore[union-attr]
        self._config_hashes["go.mod"] = config_hash
        # go test for the module
        self._entries.append(VerificationCatalogEntry(
            language="go", verification_type="unit-test",
            argv=("go", "test", "./..."), scope="repository",
            provenance="go.mod", config_path=config_path,
            config_hash=config_hash, trust_level="high",
        ))
        # go vet for linting
        self._entries.append(VerificationCatalogEntry(
            language="go", verification_type="lint",
            argv=("go", "vet", "./..."), scope="repository",
            provenance="go.mod", config_path=config_path,
            config_hash=config_hash, trust_level="medium",
        ))

    def _scan_cargo_toml(self) -> None:
        content, config_hash = self._read_config("Cargo.toml")
        if content is None:
            return
        config_path = str(self._root / "Cargo.toml")  # type: ignore[union-attr]
        self._config_hashes["Cargo.toml"] = config_hash
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
        # clippy only if [lints.clippy] or clippy configuration exists
        if "[lints" in content or "clippy" in content.lower():
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
                # Rule 1: no language-less legacy command propagates.
                continue
            argv = tuple(rule.get("argv", ()))
            if not argv or not self._is_safe_argv(argv):
                continue
            vtype = rule.get("type", "unit-test")
            scope = rule.get("scope", "repository")
            source = rule.get("source", "server-rule")
            trust = rule.get("trust_level", "medium")
            self._entries.append(VerificationCatalogEntry(
                language=language, verification_type=vtype,
                argv=argv, scope=scope,
                provenance=source, config_path=f"server-rule:{source}",
                config_hash="", trust_level=trust,
            ))

    @staticmethod
    def _is_safe_argv(argv: tuple[str, ...]) -> bool:
        """Reject shell control characters — argv must stay structured."""
        for part in argv:
            if any(token in part for token in _CONTROL_TOKENS):
                return False
        return True
