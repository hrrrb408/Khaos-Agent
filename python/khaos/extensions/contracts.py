"""Immutable contracts for the M8.7 extension plane.

These values describe capabilities and observations.  They do not grant
authority.  In particular, an extension descriptor cannot carry a trusted
boolean, suppress approval, disable sandboxing, mark a result verified, or
declare completion.  The existing ToolRegistry, Permission/Approval
services, ExecutionService/Sandbox, WorkspaceStorageAuthority, verification
owners, and CompletionGate remain the authoritative owners of those facts.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Self, SupportsIndex, TypeVar

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

EXTENSION_CONTRACT_VERSION = 1
MAX_EXTENSION_ID_BYTES = 256
MAX_EXTENSION_NAME_BYTES = 256
MAX_EXTENSION_VERSION_BYTES = 128
MAX_EXTENSION_SOURCE_BYTES = 4096
MAX_EXTENSION_CAPABILITIES = 512
MAX_EXTENSION_DESCRIPTION_BYTES = 4096
MAX_EXTENSION_METADATA_BYTES = 16 * 1024
MAX_EXTENSION_ARGUMENT_BYTES = 128 * 1024
MAX_EXTENSION_REASON_BYTES = 2048

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SENSITIVE_KEY_WORDS = frozenset(
    {
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "password",
        "passphrase",
        "private_key",
        "secret",
        "token",
    }
)
_AUTHORITY_KEYS = frozenset(
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


class _FrozenDict(dict[str, object]):
    """JSON-compatible mapping that cannot be changed after validation."""

    def __setitem__(self, key: str, value: object) -> None:
        raise TypeError("extension contract mappings are immutable")

    def __delitem__(self, key: str) -> None:
        raise TypeError("extension contract mappings are immutable")

    def clear(self) -> None:
        raise TypeError("extension contract mappings are immutable")

    def pop(self, *args: object, **kwargs: object) -> object:
        raise TypeError("extension contract mappings are immutable")

    def popitem(self) -> tuple[str, object]:
        raise TypeError("extension contract mappings are immutable")

    def setdefault(self, *args: object, **kwargs: object) -> object:
        raise TypeError("extension contract mappings are immutable")

    def update(self, *args: object, **kwargs: object) -> None:
        raise TypeError("extension contract mappings are immutable")

    def __ior__(self, value: object) -> Self:
        raise TypeError("extension contract mappings are immutable")


class _FrozenList(list[object]):
    """JSON-compatible sequence that cannot be changed after validation."""

    def __setitem__(self, index: object, value: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def __delitem__(self, index: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def append(self, value: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def clear(self) -> None:
        raise TypeError("extension contract sequences are immutable")

    def extend(self, values: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def insert(self, index: SupportsIndex, value: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def pop(self, index: SupportsIndex = -1) -> object:
        raise TypeError("extension contract sequences are immutable")

    def remove(self, value: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def reverse(self) -> None:
        raise TypeError("extension contract sequences are immutable")

    def sort(self, *args: object, **kwargs: object) -> None:
        raise TypeError("extension contract sequences are immutable")

    def __iadd__(self, values: object) -> Self:
        raise TypeError("extension contract sequences are immutable")

    def __imul__(self, value: SupportsIndex) -> Self:
        raise TypeError("extension contract sequences are immutable")


def _freeze_json(value: object) -> object:
    """Deep-freeze JSON data while preserving normal ``json.dumps`` support."""
    if isinstance(value, Mapping):
        return _FrozenDict({str(key): _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return _FrozenList(_freeze_json(child) for child in value)
    if value is None or type(value) in {str, int, float, bool}:
        return value
    return value


class ExtensionContractError(ValueError):
    """Raised when an extension value is malformed or exceeds its bound."""


class ExtensionType(StrEnum):
    """Supported extension families."""

    MCP_SERVER = "MCP_SERVER"
    HOOK_PROVIDER = "HOOK_PROVIDER"
    SKILL_PACKAGE = "SKILL_PACKAGE"


class ExtensionSourceKind(StrEnum):
    """How a descriptor entered the candidate set."""

    BUILTIN = "BUILTIN"
    CONFIG = "CONFIG"
    FILESYSTEM = "FILESYSTEM"
    PROJECT = "PROJECT"
    REMOTE = "REMOTE"


class ExtensionProvenance(StrEnum):
    """Provenance is an input to policy, never an implicit trust grant."""

    BUILTIN = "BUILTIN"
    LOCAL_TRUSTED_CONFIG = "LOCAL_TRUSTED_CONFIG"
    LOCAL_UNTRUSTED = "LOCAL_UNTRUSTED"
    REMOTE_CONFIGURED = "REMOTE_CONFIGURED"
    PROJECT_DECLARED = "PROJECT_DECLARED"


class ExtensionLifecycleState(StrEnum):
    """Registry and runtime states visible to supervision."""

    DISCOVERED = "DISCOVERED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    DISABLED = "DISABLED"
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    DRAINING = "DRAINING"


class CapabilityKind(StrEnum):
    """A deliberately separate MCP capability namespace."""

    TOOL = "TOOL"
    RESOURCE = "RESOURCE"
    PROMPT = "PROMPT"
    HOOK = "HOOK"
    SKILL = "SKILL"


class EffectKind(StrEnum):
    """Effects used by policy and admission; claims do not override them."""

    READ_WORKSPACE = "READ_WORKSPACE"
    WRITE_WORKSPACE = "WRITE_WORKSPACE"
    EXECUTE_PROCESS = "EXECUTE_PROCESS"
    NETWORK = "NETWORK"
    READ_CREDENTIAL = "READ_CREDENTIAL"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    EXTERNAL_DELETE = "EXTERNAL_DELETE"


class AdmissionStatus(StrEnum):
    """Typed capability admission outcomes."""

    ADMITTED = "ADMITTED"
    DENIED = "DENIED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    UNAVAILABLE = "UNAVAILABLE"
    QUARANTINED = "QUARANTINED"
    STALE = "STALE"


class InvocationStatus(StrEnum):
    """Terminal vocabulary for extension invocation audit rows."""

    ADMITTED = "ADMITTED"
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    STALE = "STALE"
    QUARANTINED = "QUARANTINED"


class McpTransportKind(StrEnum):
    """MCP transports understood by the boundary."""

    NONE = "NONE"
    STDIO = "STDIO"
    HTTP = "HTTP"
    SSE = "SSE"


_EnumT = TypeVar("_EnumT", bound=StrEnum)


def _enum(value: object, enum_type: type[_EnumT], label: str) -> _EnumT:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError as exc:
            raise ExtensionContractError(f"{label} is invalid") from exc


def _enum_value(value: object, enum_type: type[_EnumT], label: str) -> str:
    """Return a validated enum value from a str-compatible public field."""
    return _enum(value, enum_type, label).value


def _text(value: object, label: str, maximum: int) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ExtensionContractError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ExtensionContractError(f"{label} exceeds its bound")
    return value


def _optional_text(value: object, label: str, maximum: int) -> str | None:
    if value is None:
        return None
    if type(value) is not str or "\x00" in value:
        raise ExtensionContractError(f"{label} must be text or null")
    if len(value.encode("utf-8")) > maximum:
        raise ExtensionContractError(f"{label} exceeds its bound")
    return value


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, MAX_EXTENSION_ID_BYTES)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ExtensionContractError(f"{label} is not a stable identifier")
    return result


def _digest(value: object, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise ExtensionContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _mapping(value: object, label: str, maximum: int) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExtensionContractError(f"{label} must be an object")
    result = dict(value)
    if any(type(key) is not str or not key or "\x00" in key for key in result):
        raise ExtensionContractError(f"{label} has an invalid key")
    try:
        encoded = canonical_json_bytes(result)
    except Exception as exc:
        raise ExtensionContractError(f"{label} is not JSON-safe") from exc
    if len(encoded) > maximum:
        raise ExtensionContractError(f"{label} exceeds its bound")
    return _freeze_json(result)  # type: ignore[return-value]


def _contains_key(value: object, forbidden: frozenset[str], *, path: str = "value") -> str | None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                return f"{path} has a non-text key"
            normalized = key.casefold().replace("-", "_")
            if normalized in forbidden:
                return f"{path}.{key} is not allowed at this boundary"
            nested = _contains_key(child, forbidden, path=f"{path}.{key}")
            if nested:
                return nested
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            nested = _contains_key(child, forbidden, path=f"{path}[{index}]")
            if nested:
                return nested
    return None


@dataclass(frozen=True, slots=True)
class ExtensionSource:
    """Bounded source identity; it is not an executable import instruction."""

    locator: str
    kind: ExtensionSourceKind | str = ExtensionSourceKind.CONFIG
    declared_by: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "locator", _text(self.locator, "source.locator", MAX_EXTENSION_SOURCE_BYTES))
        object.__setattr__(self, "kind", _enum(self.kind, ExtensionSourceKind, "source.kind"))
        declared_by = _optional_text(self.declared_by, "source.declared_by", MAX_EXTENSION_ID_BYTES)
        object.__setattr__(self, "declared_by", declared_by or "")

    def to_payload(self) -> dict[str, str]:
        return {
            "kind": _enum_value(self.kind, ExtensionSourceKind, "source.kind"),
            "locator": self.locator,
            "declared_by": self.declared_by,
        }


@dataclass(frozen=True, slots=True)
class ExtensionDescriptor:
    """Immutable identity and provenance for one extension candidate."""

    extension_id: str
    name: str
    version: str
    extension_type: ExtensionType | str
    source: ExtensionSource | str
    provenance: ExtensionProvenance | str
    transport: McpTransportKind | str = McpTransportKind.NONE
    transport_identity: str = ""
    artifact_digest: str = ""
    config_digest: str = ""
    config: Mapping[str, object] = field(default_factory=dict, repr=False)
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)
    enabled: bool = True
    descriptor_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "extension_id", _identifier(self.extension_id, "extension_id"))
        object.__setattr__(self, "name", _text(self.name, "extension.name", MAX_EXTENSION_NAME_BYTES))
        object.__setattr__(self, "version", _text(self.version, "extension.version", MAX_EXTENSION_VERSION_BYTES))
        object.__setattr__(self, "extension_type", _enum(self.extension_type, ExtensionType, "extension_type"))
        source = self.source if isinstance(self.source, ExtensionSource) else ExtensionSource(str(self.source))
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "provenance", _enum(self.provenance, ExtensionProvenance, "provenance"))
        object.__setattr__(self, "transport", _enum(self.transport, McpTransportKind, "transport"))
        transport_identity = _optional_text(
            self.transport_identity,
            "transport_identity",
            MAX_EXTENSION_SOURCE_BYTES,
        ) or ""
        object.__setattr__(self, "transport_identity", transport_identity)
        config = _mapping(self.config, "extension.config", MAX_EXTENSION_METADATA_BYTES)
        config_error = _contains_key(config, _SENSITIVE_KEY_WORDS, path="extension.config")
        if config_error:
            raise ExtensionContractError(config_error)
        object.__setattr__(self, "config", config)
        metadata = _mapping(self.metadata, "extension.metadata", MAX_EXTENSION_METADATA_BYTES)
        metadata_error = _contains_key(metadata, _AUTHORITY_KEYS, path="extension.metadata")
        if metadata_error:
            raise ExtensionContractError(metadata_error)
        object.__setattr__(self, "metadata", metadata)
        artifact_digest = self.artifact_digest
        if artifact_digest == "":
            artifact_digest = canonical_digest(
                {
                    "source": source.to_payload(),
                    "name": self.name,
                    "version": self.version,
                }
            )
        object.__setattr__(self, "artifact_digest", _digest(artifact_digest, "artifact_digest"))
        config_digest = self.config_digest
        if config_digest == "":
            config_digest = canonical_digest(dict(config))
        object.__setattr__(self, "config_digest", _digest(config_digest, "config_digest"))
        if type(self.enabled) is not bool:
            raise ExtensionContractError("extension.enabled must be boolean")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.descriptor_digest:
            _digest(self.descriptor_digest, "descriptor_digest")
            if self.descriptor_digest != expected:
                raise ExtensionContractError("descriptor_digest does not match descriptor")
        object.__setattr__(self, "descriptor_digest", expected)
        if len(canonical_json_bytes(self.to_payload())) > MAX_EXTENSION_METADATA_BYTES:
            raise ExtensionContractError("extension descriptor exceeds its bound")

    @property
    def identity_digest(self) -> str:
        """Digest of identity fields that affect executable meaning."""
        source = self.source if isinstance(self.source, ExtensionSource) else ExtensionSource(str(self.source))
        return canonical_digest(
            {
                "extension_id": self.extension_id,
                "name": self.name,
                "version": self.version,
                "source": source.to_payload(),
                "artifact_digest": self.artifact_digest,
                "config_digest": self.config_digest,
                "transport": _enum_value(self.transport, McpTransportKind, "transport"),
                "transport_identity": self.transport_identity,
            }
        )

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": EXTENSION_CONTRACT_VERSION,
            "extension_id": self.extension_id,
            "name": self.name,
            "version": self.version,
            "extension_type": _enum_value(self.extension_type, ExtensionType, "extension_type"),
            "source": (self.source if isinstance(self.source, ExtensionSource) else ExtensionSource(str(self.source))).to_payload(),
            "provenance": _enum_value(self.provenance, ExtensionProvenance, "provenance"),
            "transport": _enum_value(self.transport, McpTransportKind, "transport"),
            "transport_identity": self.transport_identity,
            "artifact_digest": self.artifact_digest,
            "config_digest": self.config_digest,
            "config_keys": sorted(self.config),
            "metadata": dict(self.metadata),
            "enabled": self.enabled,
        }
        if include_digest:
            payload["descriptor_digest"] = self.descriptor_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        """Return a persistence/audit-safe descriptor projection."""
        return self._payload(include_digest=True)


_DEFAULT_INPUT_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    """One separately namespaced tool/resource/prompt/hook/skill capability."""

    capability_id: str
    extension_id: str
    kind: CapabilityKind | str
    name: str
    description: str = ""
    input_schema: Mapping[str, object] = field(default_factory=lambda: dict(_DEFAULT_INPUT_SCHEMA))
    output_schema: Mapping[str, object] | None = None
    effects: tuple[EffectKind | str, ...] = ()
    resource_uri: str | None = None
    prompt_name: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict, repr=False)
    capability_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "capability_id", _identifier(self.capability_id, "capability_id"))
        object.__setattr__(self, "extension_id", _identifier(self.extension_id, "capability.extension_id"))
        object.__setattr__(self, "kind", _enum(self.kind, CapabilityKind, "capability.kind"))
        object.__setattr__(self, "name", _text(self.name, "capability.name", MAX_EXTENSION_NAME_BYTES))
        description = self.description or ""
        if type(description) is not str or "\x00" in description:
            raise ExtensionContractError("capability.description is invalid")
        if len(description.encode("utf-8")) > MAX_EXTENSION_DESCRIPTION_BYTES:
            raise ExtensionContractError("capability.description exceeds its bound")
        object.__setattr__(self, "description", description)
        from khaos.extensions.schema import validate_external_schema

        input_schema = dict(_mapping(self.input_schema, "capability.input_schema", MAX_EXTENSION_METADATA_BYTES))
        validate_external_schema(input_schema, path="capability.input_schema")
        object.__setattr__(self, "input_schema", _freeze_json(input_schema))
        if self.output_schema is not None:
            output_schema = dict(_mapping(self.output_schema, "capability.output_schema", MAX_EXTENSION_METADATA_BYTES))
            validate_external_schema(output_schema, path="capability.output_schema")
            object.__setattr__(self, "output_schema", _freeze_json(output_schema))
        normalized_effects: list[EffectKind] = []
        for effect in self.effects:
            normalized = _enum(effect, EffectKind, "capability.effect")
            if normalized not in normalized_effects:
                normalized_effects.append(normalized)
        object.__setattr__(self, "effects", tuple(normalized_effects))
        object.__setattr__(self, "resource_uri", _optional_text(self.resource_uri, "resource_uri", MAX_EXTENSION_SOURCE_BYTES))
        object.__setattr__(self, "prompt_name", _optional_text(self.prompt_name, "prompt_name", MAX_EXTENSION_NAME_BYTES))
        metadata = _mapping(self.metadata, "capability.metadata", MAX_EXTENSION_METADATA_BYTES)
        metadata_error = _contains_key(metadata, _AUTHORITY_KEYS, path="capability.metadata")
        if metadata_error:
            raise ExtensionContractError(metadata_error)
        object.__setattr__(self, "metadata", metadata)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.capability_digest:
            _digest(self.capability_digest, "capability_digest")
            if self.capability_digest != expected:
                raise ExtensionContractError("capability_digest does not match capability")
        object.__setattr__(self, "capability_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": EXTENSION_CONTRACT_VERSION,
            "capability_id": self.capability_id,
            "extension_id": self.extension_id,
            "kind": _enum_value(self.kind, CapabilityKind, "capability.kind"),
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema) if self.output_schema is not None else None,
            "effects": [_enum_value(effect, EffectKind, "capability.effect") for effect in self.effects],
            "resource_uri": self.resource_uri,
            "prompt_name": self.prompt_name,
            "metadata": dict(self.metadata),
        }
        if include_digest:
            payload["capability_digest"] = self.capability_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


def structural_effects(descriptor: ExtensionDescriptor) -> frozenset[EffectKind]:
    """Return effects implied by transport, independent of claims."""
    effects: set[EffectKind] = set()
    if descriptor.extension_type is ExtensionType.MCP_SERVER:
        if descriptor.transport is McpTransportKind.STDIO:
            effects.add(EffectKind.EXECUTE_PROCESS)
        elif descriptor.transport in {McpTransportKind.HTTP, McpTransportKind.SSE}:
            effects.add(EffectKind.NETWORK)
    return frozenset(effects)


@dataclass(frozen=True, slots=True)
class ExtensionRecord:
    """Immutable registry snapshot for one extension."""

    descriptor: ExtensionDescriptor
    capabilities: tuple[CapabilityDescriptor, ...] = ()
    state: ExtensionLifecycleState | str = ExtensionLifecycleState.DISCOVERED
    reason: str = ""
    state_generation: int = 0

    def __post_init__(self) -> None:
        if type(self.descriptor) is not ExtensionDescriptor:
            raise ExtensionContractError("extension record descriptor is invalid")
        state = _enum(self.state, ExtensionLifecycleState, "extension.state")
        object.__setattr__(self, "state", state)
        reason = self.reason or ""
        if type(reason) is not str or "\x00" in reason or len(reason.encode("utf-8")) > MAX_EXTENSION_REASON_BYTES:
            raise ExtensionContractError("extension state reason is invalid")
        object.__setattr__(self, "reason", reason)
        if type(self.state_generation) is not int or self.state_generation < 0:
            raise ExtensionContractError("extension state generation is invalid")
        if len(self.capabilities) > MAX_EXTENSION_CAPABILITIES:
            raise ExtensionContractError("extension capability count exceeds its bound")
        capabilities = tuple(self.capabilities)
        if any(type(item) is not CapabilityDescriptor for item in capabilities):
            raise ExtensionContractError("extension capabilities are malformed")
        if any(item.extension_id != self.descriptor.extension_id for item in capabilities):
            raise ExtensionContractError("capability is bound to another extension")
        capability_ids = tuple(item.capability_id for item in capabilities)
        if len(set(capability_ids)) != len(capability_ids):
            raise ExtensionContractError("extension capability identities collide")
        object.__setattr__(self, "capabilities", tuple(sorted(capabilities, key=lambda item: item.capability_id)))

    def to_payload(self) -> dict[str, object]:
        return {
            "descriptor": self.descriptor.to_payload(),
            "capabilities": [item.to_payload() for item in self.capabilities],
            "state": _enum_value(self.state, ExtensionLifecycleState, "extension.state"),
            "reason": self.reason,
            "state_generation": self.state_generation,
        }


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    """Owner-bound input to the unified extension admission service."""

    capability_id: str
    task_id: str
    principal_id: str
    project_id: str
    workspace_id: str = ""
    workspace_generation: int = 0
    policy_digest: str = ""
    arguments: Mapping[str, object] = field(default_factory=dict, repr=False)
    extension_id: str | None = None
    capability_digest: str | None = None
    extension_digest: str | None = None
    session_id: str = ""
    approval_digest: str | None = None
    child_scope_digest: str | None = None
    requested_effects: tuple[EffectKind | str, ...] = ()
    network_host: str | None = None
    credential_name: str | None = None

    def __post_init__(self) -> None:
        for name in ("capability_id", "task_id", "principal_id", "project_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"request.{name}"))
        object.__setattr__(self, "workspace_id", _optional_text(self.workspace_id, "request.workspace_id", MAX_EXTENSION_ID_BYTES) or "")
        object.__setattr__(self, "session_id", _optional_text(self.session_id, "request.session_id", MAX_EXTENSION_ID_BYTES) or "")
        if type(self.workspace_generation) is not int or self.workspace_generation < 0:
            raise ExtensionContractError("request.workspace_generation is invalid")
        if self.policy_digest:
            object.__setattr__(self, "policy_digest", _digest(self.policy_digest, "request.policy_digest"))
        args = _mapping(self.arguments, "request.arguments", MAX_EXTENSION_ARGUMENT_BYTES)
        authority_error = _contains_key(args, _AUTHORITY_KEYS, path="request.arguments")
        if authority_error:
            raise ExtensionContractError(authority_error)
        object.__setattr__(self, "arguments", args)
        for name in ("extension_id",):
            value = getattr(self, name)
            object.__setattr__(self, name, _identifier(value, f"request.{name}") if value else None)
        for name in ("capability_digest", "extension_digest", "approval_digest", "child_scope_digest"):
            value = getattr(self, name)
            object.__setattr__(self, name, _digest(value, f"request.{name}") if value else None)
        effects = tuple(dict.fromkeys(_enum(effect, EffectKind, "request.effect") for effect in self.requested_effects))
        object.__setattr__(self, "requested_effects", effects)
        object.__setattr__(self, "network_host", _optional_text(self.network_host, "request.network_host", MAX_EXTENSION_SOURCE_BYTES))
        object.__setattr__(self, "credential_name", _optional_text(self.credential_name, "request.credential_name", MAX_EXTENSION_NAME_BYTES))

    @property
    def arguments_digest(self) -> str:
        return canonical_digest(dict(self.arguments))

    def to_payload(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "extension_id": self.extension_id,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "policy_digest": self.policy_digest,
            "arguments_digest": self.arguments_digest,
            "capability_digest": self.capability_digest,
            "extension_digest": self.extension_digest,
            "session_id": self.session_id,
            "approval_digest": self.approval_digest,
            "child_scope_digest": self.child_scope_digest,
            "requested_effects": [_enum_value(effect, EffectKind, "request.effect") for effect in self.requested_effects],
            "network_host": self.network_host,
            "credential_name": self.credential_name,
        }


@dataclass(frozen=True, slots=True)
class EffectiveCapability:
    """Policy-narrowed capability; it is not a substitute for execution authority."""

    capability_id: str
    extension_id: str
    capability_digest: str
    extension_digest: str
    task_id: str
    principal_id: str
    project_id: str
    workspace_id: str
    workspace_generation: int
    policy_digest: str
    effects: tuple[EffectKind, ...]
    approval_required: bool
    sandbox_required: bool = True
    network_host: str | None = None
    credential_name: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "capability_id", "extension_id", "task_id", "principal_id", "project_id",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"effective.{name}"))
        for name in ("capability_digest", "extension_digest", "policy_digest"):
            object.__setattr__(self, name, _digest(getattr(self, name), f"effective.{name}"))
        object.__setattr__(self, "workspace_id", _optional_text(self.workspace_id, "effective.workspace_id", MAX_EXTENSION_ID_BYTES) or "")
        if type(self.workspace_generation) is not int or self.workspace_generation < 0:
            raise ExtensionContractError("effective.workspace_generation is invalid")
        for name in ("approval_required", "sandbox_required"):
            if type(getattr(self, name)) is not bool:
                raise ExtensionContractError(f"effective.{name} must be boolean")
        if not self.sandbox_required:
            raise ExtensionContractError("effective capability cannot disable the sandbox")
        normalized = tuple(dict.fromkeys(_enum(effect, EffectKind, "effective.effect") for effect in self.effects))
        object.__setattr__(self, "effects", normalized)
        object.__setattr__(self, "network_host", _optional_text(self.network_host, "effective.network_host", MAX_EXTENSION_SOURCE_BYTES))
        object.__setattr__(self, "credential_name", _optional_text(self.credential_name, "effective.credential_name", MAX_EXTENSION_NAME_BYTES))

    def to_payload(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "extension_id": self.extension_id,
            "capability_digest": self.capability_digest,
            "extension_digest": self.extension_digest,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "policy_digest": self.policy_digest,
            "effects": [_enum_value(effect, EffectKind, "effective.effect") for effect in self.effects],
            "approval_required": self.approval_required,
            "sandbox_required": self.sandbox_required,
            "network_host": self.network_host,
            "credential_name": self.credential_name,
        }


@dataclass(frozen=True, slots=True)
class InvocationBinding:
    """Digest-bound invocation fence checked immediately before dispatch."""

    invocation_id: str
    effective: EffectiveCapability
    arguments_digest: str
    binding_digest: str = ""
    approval_digest: str | None = None
    network_reservation_digest: str | None = None
    credential_lease_id: str | None = None
    request_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "invocation_id", _identifier(self.invocation_id, "invocation_id"))
        object.__setattr__(self, "arguments_digest", _digest(self.arguments_digest, "arguments_digest"))
        for name in ("approval_digest", "network_reservation_digest"):
            value = getattr(self, name)
            object.__setattr__(self, name, _digest(value, name) if value else None)
        if self.credential_lease_id is not None:
            object.__setattr__(self, "credential_lease_id", _identifier(self.credential_lease_id, "credential_lease_id"))
        if self.request_digest is not None:
            object.__setattr__(self, "request_digest", _digest(self.request_digest, "request_digest"))
        expected = canonical_digest(self._payload(include_digest=False))
        if self.binding_digest:
            object.__setattr__(self, "binding_digest", _digest(self.binding_digest, "binding_digest"))
            if self.binding_digest != expected:
                raise ExtensionContractError("binding_digest does not match invocation fence")
        else:
            object.__setattr__(self, "binding_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "invocation_id": self.invocation_id,
            "effective": self.effective.to_payload(),
            "arguments_digest": self.arguments_digest,
            "approval_digest": self.approval_digest,
            "network_reservation_digest": self.network_reservation_digest,
            "credential_lease_id": self.credential_lease_id,
            "request_digest": self.request_digest,
        }
        if include_digest:
            payload["binding_digest"] = self.binding_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class CapabilityAdmissionResult:
    """Machine-readable admission decision with no authority-shaped claims."""

    status: AdmissionStatus | str
    reason_code: str
    reason: str
    request_digest: str
    effective: EffectiveCapability | None = None
    binding: InvocationBinding | None = None
    required_effects: tuple[EffectKind, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _enum(self.status, AdmissionStatus, "admission.status"))
        object.__setattr__(self, "reason_code", _identifier(self.reason_code, "admission.reason_code"))
        object.__setattr__(self, "reason", _text(self.reason, "admission.reason", MAX_EXTENSION_REASON_BYTES))
        object.__setattr__(self, "request_digest", _digest(self.request_digest, "admission.request_digest"))
        if self.binding is not None and self.effective is not None and self.binding.effective != self.effective:
            raise ExtensionContractError("admission binding and effective capability disagree")
        normalized = tuple(dict.fromkeys(_enum(effect, EffectKind, "admission.effect") for effect in self.required_effects))
        object.__setattr__(self, "required_effects", normalized)

    @property
    def admitted(self) -> bool:
        return self.status is AdmissionStatus.ADMITTED and self.binding is not None

    def to_payload(self) -> dict[str, object]:
        return {
            "status": _enum_value(self.status, AdmissionStatus, "admission.status"),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "request_digest": self.request_digest,
            "effective": self.effective.to_payload() if self.effective else None,
            "binding": self.binding.to_payload() if self.binding else None,
            "required_effects": [_enum_value(effect, EffectKind, "admission.effect") for effect in self.required_effects],
        }


# Explicit aliases make the contract discoverable under the names used by
# integrators and the milestone document without introducing duplicate types.
CapabilityAdmissionRequest = CapabilityRequest
AdmissionResult = CapabilityAdmissionResult


__all__ = [
    "AdmissionResult",
    "AdmissionStatus",
    "CapabilityAdmissionRequest",
    "CapabilityAdmissionResult",
    "CapabilityDescriptor",
    "CapabilityKind",
    "CapabilityRequest",
    "EffectKind",
    "EffectiveCapability",
    "ExtensionContractError",
    "ExtensionDescriptor",
    "ExtensionLifecycleState",
    "ExtensionProvenance",
    "ExtensionRecord",
    "ExtensionSource",
    "ExtensionSourceKind",
    "ExtensionType",
    "InvocationBinding",
    "InvocationStatus",
    "McpTransportKind",
    "structural_effects",
]
