"""Trusted project-profile discovery for autonomous verification.

Only repository manifests already understood by the M4 verification catalog
and bounded, server-owned metadata are used here.  README prose, arbitrary
model text, and package-script contents never become command arguments.  A
package script is represented as ``npm run <known-script>`` and is still
executed as repository code through the existing sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.planning.contracts import VerificationCatalogEntry
from khaos.coding.planning.verification_catalog import (
    SafeConfigSnapshot,
    VerificationCatalog,
)
from khaos.coding.verification.contracts import (
    VerificationCheckKind,
    VerificationContractError,
    _argv,
    _digest,
)
from khaos.security.protocol_boundary import canonical_digest

_MAX_PROFILE_FILES = 4096
_MAX_PACKAGE_ROOTS = 64
_KNOWN_MANIFESTS = (
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pytest.ini",
    "setup.cfg",
    "tox.ini",
    "tsconfig.json",
    "go.work",
)
_SOURCE_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
}


def _relative_path(value: str, *, allow_dot: bool = True) -> str:
    normalized = str(value).replace("\\", "/")
    if normalized in {".", "./"}:
        if allow_dot:
            return "."
        raise VerificationContractError("profile path must not be workspace root")
    if not normalized or normalized.startswith("/") or (
        len(normalized) >= 2 and normalized[1] == ":"
    ):
        raise VerificationContractError("profile path must be workspace-relative")
    path = PurePosixPath(normalized)
    if not path.parts or any(part in {"", ".."} for part in path.parts):
        raise VerificationContractError("profile path contains traversal")
    if not allow_dot and path.as_posix() == ".":
        raise VerificationContractError("profile path must not be workspace root")
    if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in path.parts):
        raise VerificationContractError("profile path reaches protected metadata")
    return path.as_posix()


def _prefix_path(package_root: str, path: str) -> str:
    path = _relative_path(path)
    if package_root == ".":
        return path
    return f"{package_root}/{path}"


@dataclass(frozen=True, slots=True)
class VerificationCommandSpec:
    """One command admitted from a trusted catalog entry."""

    command_id: str
    kind: VerificationCheckKind
    language: str
    argv: tuple[str, ...]
    cwd: str
    scope: str
    provenance: str
    config_path: str
    config_hash: str
    trust_level: str
    executes_project_code: bool = True

    def __post_init__(self) -> None:
        if type(self.command_id) is not str or not self.command_id:
            raise VerificationContractError("command_id must be non-empty")
        kind = self.kind
        if isinstance(kind, str):
            kind = VerificationCheckKind(kind)
            object.__setattr__(self, "kind", kind)
        if type(kind) is not VerificationCheckKind:
            raise VerificationContractError("command kind is invalid")
        for label, value in (
            ("language", self.language),
            ("scope", self.scope),
            ("provenance", self.provenance),
            ("config_path", self.config_path),
            ("config_hash", self.config_hash),
            ("trust_level", self.trust_level),
        ):
            if (
                type(value) is not str
                or (not value and label != "config_hash")
                or "\x00" in value
            ):
                raise VerificationContractError(f"{label} is invalid")
        object.__setattr__(self, "config_path", _relative_path(self.config_path))
        object.__setattr__(self, "cwd", _relative_path(self.cwd))
        object.__setattr__(self, "argv", _argv(self.argv))
        object.__setattr__(
            self,
            "config_hash",
            _digest(self.config_hash, label="config_hash", allow_empty=True),
        )
        if type(self.executes_project_code) is not bool:
            raise VerificationContractError("executes_project_code must be a bool")

    @property
    def digest(self) -> str:
        """Return a portable digest for the catalog command semantics."""
        return canonical_digest(
            {
                "command_id": self.command_id,
                "kind": self.kind.value,
                "language": self.language,
                "argv": self.argv,
                "cwd": self.cwd,
                "scope": self.scope,
                "provenance": self.provenance,
                "config_path": self.config_path,
                "config_hash": self.config_hash,
                "trust_level": self.trust_level,
                "executes_project_code": self.executes_project_code,
            }
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "kind": self.kind.value,
            "language": self.language,
            "argv": self.argv,
            "cwd": self.cwd,
            "scope": self.scope,
            "provenance": self.provenance,
            "config_path": self.config_path,
            "config_hash": self.config_hash,
            "trust_level": self.trust_level,
            "executes_project_code": self.executes_project_code,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class VerificationProfile:
    """Immutable multi-package project profile used by the planner."""

    profile_id: str
    languages: tuple[str, ...]
    package_roots: tuple[str, ...]
    test_roots: tuple[str, ...]
    build_files: tuple[str, ...]
    config_files: tuple[str, ...]
    commands: tuple[VerificationCommandSpec, ...]
    config_hashes: tuple[tuple[str, str], ...]
    diagnostics: tuple[str, ...] = ()
    profile_digest: str = ""

    def __post_init__(self) -> None:
        for label, value in (("profile_id", self.profile_id),):
            if type(value) is not str or not value or len(value) > 512 or "\x00" in value:
                raise VerificationContractError(f"{label} must be non-empty")
        for label in ("languages", "package_roots", "test_roots", "build_files", "config_files"):
            values = getattr(self, label)
            if type(values) is not tuple or any(type(item) is not str for item in values):
                raise VerificationContractError(f"{label} must be an immutable tuple")
            if label == "languages":
                if any(not item or len(item) > 128 or "\x00" in item for item in values):
                    raise VerificationContractError("languages contain an invalid value")
                normalized = tuple(sorted(set(values)))
            else:
                try:
                    normalized = tuple(sorted({_relative_path(item) for item in values}))
                except VerificationContractError as exc:
                    raise VerificationContractError(f"{label} contains an unsafe path") from exc
            bound = _MAX_PACKAGE_ROOTS if label == "package_roots" else _MAX_PROFILE_FILES
            if len(normalized) > bound:
                raise VerificationContractError(f"{label} exceeds its bound")
            object.__setattr__(self, label, normalized)
        if type(self.commands) is not tuple or any(
            type(item) is not VerificationCommandSpec for item in self.commands
        ):
            raise VerificationContractError("commands must contain command specs")
        if len({item.command_id for item in self.commands}) != len(self.commands):
            raise VerificationContractError("profile command IDs must be unique")
        if type(self.config_hashes) is not tuple or any(
            type(item) is not tuple or len(item) != 2 or any(type(part) is not str for part in item)
            for item in self.config_hashes
        ):
            raise VerificationContractError("config_hashes must be pairs")
        normalized_hashes: list[tuple[str, str]] = []
        for path, digest in self.config_hashes:
            try:
                normalized_path = _relative_path(path)
                normalized_digest = _digest(digest, label="config hash", allow_empty=True)
            except VerificationContractError as exc:
                raise VerificationContractError("config_hashes contain an invalid value") from exc
            normalized_hashes.append((normalized_path, normalized_digest))
        if len(normalized_hashes) != len(set(normalized_hashes)):
            raise VerificationContractError("config_hashes contain duplicates")
        object.__setattr__(self, "config_hashes", tuple(sorted(normalized_hashes)))
        if type(self.diagnostics) is not tuple or any(type(item) is not str for item in self.diagnostics):
            raise VerificationContractError("profile diagnostics must be strings")
        if len(self.diagnostics) > _MAX_PROFILE_FILES or any(
            not item or len(item) > 1024 or "\x00" in item for item in self.diagnostics
        ):
            raise VerificationContractError("profile diagnostics exceed their bound")
        computed = self._computed_digest()
        if self.profile_digest:
            if self.profile_digest != computed:
                raise VerificationContractError("profile_digest does not match profile semantics")
        else:
            object.__setattr__(self, "profile_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "languages": self.languages,
            "package_roots": self.package_roots,
            "test_roots": self.test_roots,
            "build_files": self.build_files,
            "config_files": self.config_files,
            "commands": tuple(item.to_payload() for item in self.commands),
            "config_hashes": self.config_hashes,
            "diagnostics": self.diagnostics,
        }

    def _computed_digest(self) -> str:
        return canonical_digest(self._payload_without_digest())

    def is_valid(self) -> bool:
        return self.profile_digest == self._computed_digest()

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload.update({"profile_id": self.profile_id, "profile_digest": self.profile_digest})
        return payload


class VerificationProfileDetector:
    """Build profiles from the existing trusted catalog and safe metadata."""

    def __init__(self, *, max_files: int = _MAX_PROFILE_FILES, max_depth: int = 8) -> None:
        if type(max_files) is not int or max_files <= 0:
            raise ValueError("max_files must be positive")
        if type(max_depth) is not int or max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        self.max_files = max_files
        self.max_depth = max_depth

    def detect(
        self,
        root: Path,
        *,
        repository_id: str = "",
        overview: Any | None = None,
        server_rules: tuple[dict[str, Any], ...] = (),
    ) -> VerificationProfile:
        """Detect a bounded profile without executing repository code."""
        canonical_root = Path(root).expanduser().resolve(strict=True)
        package_roots = self._package_roots(canonical_root, overview)
        catalogs: list[tuple[str, VerificationCatalog]] = []
        diagnostics: list[str] = []
        for package_root in package_roots:
            package_path = canonical_root if package_root == "." else canonical_root / package_root
            try:
                catalog = VerificationCatalog(
                    package_path,
                    server_rules=server_rules if package_root == "." else (),
                    repository_id=f"{repository_id}:{package_root}",
                )
            except (OSError, ValueError) as exc:
                diagnostics.append(f"profile catalog unavailable:{package_root}:{type(exc).__name__}")
                continue
            catalogs.append((package_root, catalog))
            diagnostics.extend(f"{package_root}:{message}" for _, message in catalog.diagnostics)

        files = self._safe_files(canonical_root)
        languages = {str(value) for value in getattr(overview, "languages", ()) or ()}
        languages.update(
            language
            for path in files
            if (language := _SOURCE_LANGUAGES.get(Path(path).suffix.casefold())) is not None
        )
        commands: list[VerificationCommandSpec] = []
        config_hashes: dict[str, str] = {}
        for package_root, catalog in catalogs:
            for entry in catalog.entries:
                try:
                    commands.append(self._command_from_entry(entry, package_root))
                except VerificationContractError:
                    # A catalog entry outside the autonomous check vocabulary
                    # is not executable evidence. Preserve a bounded profile
                    # diagnostic and continue with the safe entries.
                    diagnostics.append(
                        f"{package_root}:unsupported verification type:{str(entry.verification_type)[:128]}"
                    )
            for path, digest in catalog.config_hashes.items():
                config_hashes[_prefix_path(package_root, path)] = digest
                language = self._language_for_entry(path, catalog.entries)
                if language:
                    languages.add(language)

        # Extra project metadata is fingerprinted even when it does not define
        # a command.  This makes a later profile rebuild conservative.
        extra_config_files: set[str] = set()
        for path in files:
            name = Path(path).name
            if name in _KNOWN_MANIFESTS:
                extra_config_files.add(path)
        for relative in sorted(extra_config_files):
            snapshot = SafeConfigSnapshot.capture(canonical_root, relative)
            if snapshot.exists:
                config_hashes[relative] = snapshot.content_hash

        test_roots = self._portable_paths(getattr(overview, "test_roots", ()) or ())
        build_files = self._portable_paths(getattr(overview, "build_files", ()) or ())
        config_files = self._portable_paths(
            tuple(sorted(set(getattr(overview, "config_files", ()) or ()) | set(config_hashes)))
        )
        if not package_roots:
            package_roots = (".",)
        commands = sorted(commands, key=lambda item: (item.cwd, item.kind.value, item.language, item.command_id))
        # A typed catalog can identify a language before a source file of that
        # language exists (for example a fresh TypeScript package with only a
        # package.json script).  Keep the profile language set aligned with
        # the executable command inventory so cross-language selection does
        # not depend on a filename heuristic alone.
        languages.update(command.language for command in commands)
        config_hash_items = tuple(sorted(config_hashes.items()))
        diagnostic_items = tuple(sorted(set(diagnostics)))
        profile_digest = canonical_digest(
            {
                "languages": tuple(sorted(languages)),
                "package_roots": package_roots,
                "test_roots": test_roots,
                "build_files": build_files,
                "config_files": config_files,
                "commands": tuple(item.to_payload() for item in commands),
                "config_hashes": config_hash_items,
                "diagnostics": diagnostic_items,
            }
        )
        return VerificationProfile(
            profile_id=f"m83-profile-{profile_digest[:24]}",
            languages=tuple(sorted(languages)),
            package_roots=package_roots,
            test_roots=test_roots,
            build_files=build_files,
            config_files=config_files,
            commands=tuple(commands),
            config_hashes=config_hash_items,
            diagnostics=diagnostic_items,
            profile_digest=profile_digest,
        )

    def _package_roots(self, root: Path, overview: Any | None) -> tuple[str, ...]:
        candidates = {str(item) for item in (getattr(overview, "package_roots", ()) or ())}
        if not candidates:
            candidates.add(".")
            for relative in self._safe_files(root):
                if Path(relative).name in _KNOWN_MANIFESTS:
                    parent = PurePosixPath(relative).parent.as_posix()
                    candidates.add(parent if parent not in {"", "."} else ".")
        normalized: set[str] = set()
        for candidate in candidates:
            try:
                path = _relative_path(candidate)
                package_path = root if path == "." else root / path
                if package_path.is_dir():
                    normalized.add(path)
            except (OSError, ValueError, VerificationContractError):
                continue
        return tuple(sorted(normalized))[:_MAX_PACKAGE_ROOTS]

    def _safe_files(self, root: Path) -> tuple[str, ...]:
        try:
            from khaos.coding.workspace.boundary import SafeWorkspaceFS

            with SafeWorkspaceFS(root) as filesystem:
                return tuple(
                    filesystem.iter_files(
                        ".",
                        max_entries=self.max_files,
                        max_depth=self.max_depth,
                    )
                )
        except (OSError, ValueError, RuntimeError):
            return ()

    @staticmethod
    def _portable_paths(values: Any) -> tuple[str, ...]:
        result: set[str] = set()
        for value in values:
            try:
                result.add(_relative_path(str(value)))
            except VerificationContractError:
                continue
        return tuple(sorted(result))

    @staticmethod
    def _language_for_entry(path: str, entries: tuple[VerificationCatalogEntry, ...]) -> str:
        for entry in entries:
            if entry.config_path == path:
                return entry.language
        return ""

    @staticmethod
    def _command_from_entry(
        entry: VerificationCatalogEntry,
        package_root: str,
    ) -> VerificationCommandSpec:
        kind_map = {
            "unit-test": VerificationCheckKind.PACKAGE_TEST,
            "integration-test": VerificationCheckKind.INTEGRATION_TEST,
            "type-check": VerificationCheckKind.TYPECHECK,
            "lint": VerificationCheckKind.LINT,
            "format": VerificationCheckKind.FORMAT,
            "build": VerificationCheckKind.BUILD,
            "regression": VerificationCheckKind.REGRESSION,
            "custom-project-check": VerificationCheckKind.CUSTOM_PROJECT_CHECK,
            "custom_project_check": VerificationCheckKind.CUSTOM_PROJECT_CHECK,
            "custom": VerificationCheckKind.CUSTOM_PROJECT_CHECK,
        }
        kind = kind_map.get(entry.verification_type)
        if kind is None:
            raise VerificationContractError(
                f"unsupported catalog verification type: {entry.verification_type}"
            )
        command_id = canonical_digest(
            {
                "language": entry.language,
                "verification_type": entry.verification_type,
                "argv": entry.argv,
                "scope": entry.scope,
                "provenance": entry.provenance,
                "config_path": entry.config_path,
                "config_hash": entry.config_hash,
            }
        )
        return VerificationCommandSpec(
            command_id=f"catalog-{command_id[:24]}",
            kind=kind,
            language=entry.language,
            argv=entry.argv,
            cwd=package_root,
            scope=entry.scope,
            provenance=entry.provenance,
            config_path=_prefix_path(package_root, entry.config_path),
            config_hash=entry.config_hash,
            trust_level=entry.trust_level,
            executes_project_code=True,
        )


# Shorter vocabulary used by callers and tests.
ProfileDetector = VerificationProfileDetector
ProjectProfile = VerificationProfile
ProjectVerificationProfile = VerificationProfile


__all__ = [
    "ProfileDetector",
    "ProjectProfile",
    "ProjectVerificationProfile",
    "VerificationCommandSpec",
    "VerificationProfile",
    "VerificationProfileDetector",
]
