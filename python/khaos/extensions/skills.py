"""Declarative, provenance-aware Skill packages for the M8.7 plane."""

from __future__ import annotations

import hashlib
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from khaos.coding.context_engine.contracts import (
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextSource,
    ContextTrust,
)
from khaos.extensions.contracts import ExtensionProvenance
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.skills.loader import SkillLoader
from khaos.skills.skill import Skill, SkillParseError, SkillTrustTier

MAX_SKILL_PACKAGE_INSTRUCTION_BYTES = 512 * 1024
MAX_SKILL_PACKAGE_EXAMPLES = 32
MAX_SKILL_PACKAGE_EXAMPLE_BYTES = 16 * 1024
_SKILL_AUTHORITY_KEYS = frozenset(
    {
        "approval_granted",
        "approval_required",
        "completed",
        "completion_authority",
        "sandbox",
        "trusted",
        "verified",
        "verification_passed",
    }
)


class SkillPackageError(ValueError):
    """Raised when a declarative Skill package violates its boundary."""


class SkillActivationStatus(StrEnum):
    """Skill activation does not imply executable tool availability."""

    ACTIVE = "ACTIVE"
    PARTIALLY_AVAILABLE = "PARTIALLY_AVAILABLE"
    DENIED = "DENIED"
    STALE = "STALE"


def _provenance_for_skill(skill: Skill) -> ExtensionProvenance:
    return {
        SkillTrustTier.BUILTIN: ExtensionProvenance.BUILTIN,
        SkillTrustTier.USER: ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
        SkillTrustTier.PROJECT: ExtensionProvenance.PROJECT_DECLARED,
    }.get(skill.trust_tier, ExtensionProvenance.LOCAL_UNTRUSTED)


@dataclass(frozen=True, slots=True)
class SkillPackageManifest:
    """Bounded metadata required to select a Skill package."""

    skill_id: str
    name: str
    version: str
    provenance: ExtensionProvenance | str
    package_digest: str
    required_tools: tuple[str, ...] = ()
    optional_tools: tuple[str, ...] = ()
    applicable_paths: tuple[str, ...] = ()
    applicable_languages: tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in ("skill_id", "name", "version"):
            value = getattr(self, name)
            if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > 256:
                raise SkillPackageError(f"skill manifest {name} is invalid")
        object.__setattr__(self, "provenance", ExtensionProvenance(str(self.provenance)))
        if type(self.package_digest) is not str or len(self.package_digest) != 64 or any(char not in "0123456789abcdef" for char in self.package_digest):
            raise SkillPackageError("skill package digest is invalid")
        for name in ("required_tools", "optional_tools", "applicable_paths", "applicable_languages"):
            raw_values = tuple(getattr(self, name))
            if len(raw_values) > 64 or any(type(value) is not str or not value or len(value) > 512 for value in raw_values):
                raise SkillPackageError(f"skill manifest {name} is invalid")
            values = tuple(sorted(set(raw_values)))
            if name == "applicable_paths":
                for value in values:
                    _validate_relative_selector(value)
            object.__setattr__(self, name, values)
        metadata = dict(self.metadata)
        _validate_skill_metadata(metadata)
        if len(canonical_json_bytes(metadata)) > 16 * 1024:
            raise SkillPackageError("skill package metadata exceeds its bound")
        object.__setattr__(self, "metadata", _freeze_json(metadata))

    def to_payload(self) -> dict[str, object]:
        return {
            "skill_id": self.skill_id,
            "name": self.name,
            "version": self.version,
            "provenance": str(self.provenance),
            "package_digest": self.package_digest,
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "applicable_paths": list(self.applicable_paths),
            "applicable_languages": list(self.applicable_languages),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SkillPackage:
    """A declarative package; body is instruction data, never imported code."""

    manifest: SkillPackageManifest
    instructions: str
    examples: tuple[str, ...] = ()
    source_path: str = ""
    body_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.instructions) is not str or len(self.instructions.encode("utf-8")) > MAX_SKILL_PACKAGE_INSTRUCTION_BYTES:
            raise SkillPackageError("skill instructions exceed their bound")
        examples = tuple(self.examples)
        if len(examples) > MAX_SKILL_PACKAGE_EXAMPLES or any(type(value) is not str or len(value.encode("utf-8")) > MAX_SKILL_PACKAGE_EXAMPLE_BYTES for value in examples):
            raise SkillPackageError("skill examples exceed their bound")
        object.__setattr__(self, "examples", examples)
        if self.source_path and ("\x00" in self.source_path or len(self.source_path.encode("utf-8")) > 4096):
            raise SkillPackageError("skill source path is invalid")
        body_digest = self.body_digest or hashlib.sha256(self.instructions.encode("utf-8")).hexdigest()
        if len(body_digest) != 64 or any(char not in "0123456789abcdef" for char in body_digest):
            raise SkillPackageError("skill body digest is invalid")
        expected_body_digest = hashlib.sha256(self.instructions.encode("utf-8")).hexdigest()
        if body_digest != expected_body_digest:
            raise SkillPackageError("skill body digest does not match instructions")
        object.__setattr__(self, "body_digest", body_digest)
        expected_package_digest = canonical_digest(
            _package_digest_payload(self.manifest, body_digest, examples)
        )
        if self.manifest.package_digest != expected_package_digest:
            raise SkillPackageError("skill package digest does not match its included files")
        _reject_executable_or_remote_instructions(self.instructions)

    @property
    def package_digest(self) -> str:
        return self.manifest.package_digest

    def is_stale(self, *, current_body_digest: str | None = None) -> bool:
        return current_body_digest is not None and current_body_digest != self.body_digest

    def to_context_item(self, *, workspace_id: str = "", generation: str | None = None) -> ContextItem:
        rendered = (
            f'<extension_instruction provenance="{self.manifest.provenance!s}" '
            f'name="{self.manifest.name}" version="{self.manifest.version}" '
            f'digest="{self.package_digest}">\n{self.instructions}\n'
            "</extension_instruction>"
        )
        return ContextItem(
            kind=ContextItemKind.EXTENSION_INSTRUCTION,
            payload=rendered,
            layer=ContextLayer.L1,
            source=ContextSource.EXTENSION,
            trust=ContextTrust.UNTRUSTED_EXTENSION_INSTRUCTION,
            workspace_id=workspace_id,
            generation=generation,
            metadata={
                "extension_trust_label": "EXTENSION_INSTRUCTION",
                "skill_id": self.manifest.skill_id,
                "package_digest": self.package_digest,
            },
        )


@dataclass(frozen=True, slots=True)
class SkillActivation:
    """Durable-safe activation projection, without body or tool authority."""

    skill_id: str
    version: str
    package_digest: str
    task_id: str
    principal_id: str
    project_id: str
    status: SkillActivationStatus | str
    selection_reason: str
    missing_required_tools: tuple[str, ...] = ()
    stale: bool = False
    activation_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SkillActivationStatus(str(self.status)))
        if any(type(getattr(self, name)) is not str or not getattr(self, name) for name in ("skill_id", "version", "package_digest", "task_id", "principal_id", "project_id", "selection_reason")):
            raise SkillPackageError("skill activation identity is invalid")
        if len(self.selection_reason.encode("utf-8")) > 2048:
            raise SkillPackageError("skill activation selection reason exceeds its bound")
        if len(self.package_digest) != 64 or any(char not in "0123456789abcdef" for char in self.package_digest):
            raise SkillPackageError("skill activation package digest is invalid")
        raw_missing = tuple(self.missing_required_tools)
        if len(raw_missing) > 64 or any(type(value) is not str or not value or len(value) > 512 for value in raw_missing):
            raise SkillPackageError("skill activation missing-tool projection is invalid")
        missing = tuple(sorted(set(raw_missing)))
        object.__setattr__(self, "missing_required_tools", missing)
        if type(self.stale) is not bool:
            raise SkillPackageError("skill activation stale flag is invalid")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.activation_digest and self.activation_digest != expected:
            raise SkillPackageError("skill activation digest does not match")
        object.__setattr__(self, "activation_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "skill_id": self.skill_id,
            "version": self.version,
            "package_digest": self.package_digest,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "status": str(self.status),
            "selection_reason": self.selection_reason,
            "missing_required_tools": list(self.missing_required_tools),
            "stale": self.stale,
        }
        if include_digest:
            payload["activation_digest"] = self.activation_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


class SkillPackageLoader:
    """Load declarative packages through the existing secure SkillLoader."""

    def __init__(self, roots: Iterable[Path | str] = ()) -> None:
        self.roots = tuple(Path(root) for root in roots)

    def load_file(self, path: Path | str, *, provenance: ExtensionProvenance | None = None) -> SkillPackage:
        candidate = Path(path)
        if candidate.is_symlink():
            raise SkillPackageError("skill package symlink is rejected")
        root = self._root_for(candidate)
        if root is None:
            raise SkillPackageError("skill package is outside the declared roots")
        loader = SkillLoader([root])
        try:
            skill = loader.load_file(candidate, trust_tier=_trust_tier(provenance, candidate, root))
        except SkillParseError as exc:
            raise SkillPackageError(str(exc)) from exc
        return self.from_skill(skill, provenance=provenance)

    def load_all(self, root: Path | str, *, provenance: ExtensionProvenance | None = None) -> tuple[SkillPackage, ...]:
        root_path = Path(root)
        if self._root_for(root_path) is None:
            raise SkillPackageError("skill package root is missing, symlinked, or outside the declared roots")
        trust_tier = _trust_tier(provenance, root_path, root_path)
        packages: list[SkillPackage] = []
        for skill in SkillLoader([root_path]).load_all(trust_tier=trust_tier):
            try:
                packages.append(self.from_skill(skill, provenance=provenance))
            except SkillPackageError:
                continue
        return tuple(sorted(packages, key=lambda package: package.manifest.skill_id))

    @staticmethod
    def from_skill(skill: Skill, *, provenance: ExtensionProvenance | None = None) -> SkillPackage:
        if type(skill) is not Skill:
            raise TypeError("skill must be a Skill")
        resolved_provenance = provenance or _provenance_for_skill(skill)
        instructions = skill.body.strip()
        _reject_executable_or_remote_instructions(instructions)
        body_digest = hashlib.sha256(instructions.encode("utf-8")).hexdigest()
        manifest_without_digest = SkillPackageManifest(
            skill_id=skill.skill_id or skill.name,
            name=skill.name,
            version=skill.version,
            provenance=resolved_provenance,
            package_digest="0" * 64,
            required_tools=tuple(skill.required_tools),
            optional_tools=tuple(skill.optional_tools),
            applicable_paths=tuple(skill.applicable_paths),
            applicable_languages=tuple(skill.applicable_languages),
        )
        package_payload = _package_digest_payload(manifest_without_digest, body_digest, ())
        package_digest = canonical_digest(package_payload)
        manifest = SkillPackageManifest(
            skill_id=skill.skill_id or skill.name,
            name=skill.name,
            version=skill.version,
            provenance=resolved_provenance,
            package_digest=package_digest,
            required_tools=tuple(skill.required_tools),
            optional_tools=tuple(skill.optional_tools),
            applicable_paths=tuple(skill.applicable_paths),
            applicable_languages=tuple(skill.applicable_languages),
        )
        return SkillPackage(
            manifest=manifest,
            instructions=instructions,
            source_path=str(skill.path) if skill.path else "",
            body_digest=body_digest,
        )

    def _root_for(self, candidate: Path) -> Path | None:
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise SkillPackageError("skill package path cannot be resolved") from exc
        for root in self.roots:
            try:
                root_info = root.lstat()
                if root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
                    continue
                resolved_root = root.resolve()
                if resolved == resolved_root or resolved_root in resolved.parents:
                    return root
            except OSError:
                continue
        return None


class SkillActivationService:
    """Select Skills without auto-enabling MCP or any other capability."""

    def activate(
        self,
        package: SkillPackage,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
        available_tools: Iterable[str],
        selection_reason: str,
        current_body_digest: str | None = None,
    ) -> SkillActivation:
        available = {str(value) for value in available_tools}
        missing = tuple(sorted(set(package.manifest.required_tools) - available))
        stale = package.is_stale(current_body_digest=current_body_digest)
        if stale:
            status = SkillActivationStatus.STALE
        elif missing:
            status = SkillActivationStatus.PARTIALLY_AVAILABLE
        else:
            status = SkillActivationStatus.ACTIVE
        return SkillActivation(
            skill_id=package.manifest.skill_id,
            version=package.manifest.version,
            package_digest=package.package_digest,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            status=status,
            selection_reason=selection_reason,
            missing_required_tools=missing,
            stale=stale,
        )


def _trust_tier(provenance: ExtensionProvenance | None, path: Path, root: Path) -> SkillTrustTier:
    if provenance is ExtensionProvenance.BUILTIN:
        return SkillTrustTier.BUILTIN
    if provenance is ExtensionProvenance.LOCAL_TRUSTED_CONFIG:
        return SkillTrustTier.USER
    if provenance is ExtensionProvenance.PROJECT_DECLARED or path == root:
        return SkillTrustTier.PROJECT
    return SkillTrustTier.PROJECT


def _validate_relative_selector(value: str) -> None:
    """Keep applicability selectors relative and platform-unambiguous."""
    normalized = value.replace("\\", "/")
    if (
        normalized.startswith("/")
        or (len(normalized) >= 2 and normalized[1] == ":")
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise SkillPackageError("skill applicable path must stay within the declared workspace")


def _validate_skill_metadata(value: object, *, path: str = "metadata", depth: int = 0) -> None:
    """Reject authority-shaped metadata before it becomes selectable context."""
    if depth > 8:
        raise SkillPackageError("skill metadata nesting exceeds its bound")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str or not key or len(key) > 256:
                raise SkillPackageError(f"{path} contains an invalid key")
            if key.casefold() in _SKILL_AUTHORITY_KEYS:
                raise SkillPackageError(f"{path}.{key} attempts to declare authority")
            _validate_skill_metadata(child, path=f"{path}.{key}", depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 128:
            raise SkillPackageError(f"{path} contains too many entries")
        for index, child in enumerate(value):
            _validate_skill_metadata(child, path=f"{path}[{index}]", depth=depth + 1)


def _package_digest_payload(
    manifest: SkillPackageManifest,
    body_digest: str,
    examples: tuple[str, ...],
) -> dict[str, object]:
    """Bind the digest to all canonical package metadata and included files."""
    return {
        "skill_id": manifest.skill_id,
        "name": manifest.name,
        "version": manifest.version,
        "provenance": str(manifest.provenance),
        "body_digest": body_digest,
        "required_tools": list(manifest.required_tools),
        "optional_tools": list(manifest.optional_tools),
        "applicable_paths": list(manifest.applicable_paths),
        "applicable_languages": list(manifest.applicable_languages),
        "metadata": dict(manifest.metadata),
        "examples": [hashlib.sha256(example.encode("utf-8")).hexdigest() for example in examples],
    }


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _reject_executable_or_remote_instructions(body: str) -> None:
    lowered = body.casefold()
    forbidden_fragments = (
        "http://",
        "https://",
        "file://",
        "!include",
        "@include",
        "exec(",
        "eval(",
        "__import__",
        "importlib",
        "subprocess",
    )
    if any(fragment in lowered for fragment in forbidden_fragments):
        raise SkillPackageError("skill instructions contain a remote include or executable import directive")


__all__ = [
    "SkillActivation",
    "SkillActivationService",
    "SkillActivationStatus",
    "SkillPackage",
    "SkillPackageError",
    "SkillPackageLoader",
    "SkillPackageManifest",
]
