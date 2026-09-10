"""Typed, bounded contracts for Coding-mode browser and app automation.

The browser is an observation and effect adapter.  None of the values in
this module are completion, permission, or process authority.  In
particular, page text, accessibility data, console messages, URLs, and
network summaries remain untrusted observations and are always bounded and
redacted before they cross the Coding tool boundary.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from khaos.security.protocol_boundary import canonical_digest

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = ("\x00", "\r", "\n", ";", "&&", "||", "|", "`", "$(")
_MAX_ID = 256
_MAX_TEXT = 4096
_MAX_SELECTOR = 1024
_MAX_ITEMS = 128
_MAX_ARTIFACTS = 32
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_SECRET_WORDS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
    }
)
_SHELL_LAUNCHERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
)


class BrowserContractError(ValueError):
    """Raised when a browser/app contract is malformed or stale."""


class BrowserSessionState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    STALE = "stale"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class AppInstanceState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    STOPPING = "stopping"
    STOPPED = "stopped"
    STALE = "stale"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class AppHealth(str, Enum):
    UNKNOWN = "unknown"
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STALE = "stale"


class BrowserActionKind(str, Enum):
    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    PRESS_KEY = "press_key"
    SCROLL = "scroll"
    WAIT_FOR = "wait_for"
    READ = "read"
    SCREENSHOT = "screenshot"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    CLOSE = "close"
    OPEN_NEW_PAGE = "open_new_page"


class BrowserEffectClass(str, Enum):
    READ_ONLY = "read-only"
    LOCAL_NAVIGATION = "local-navigation"
    UI_INPUT = "ui-input"
    FORM_SUBMIT = "form-submit"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    EXTERNAL_WRITE = "external-write"
    DESTRUCTIVE_WRITE = "destructive-write"
    UNKNOWN = "unknown"


class BrowserResultStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    STALE = "stale"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    INFRASTRUCTURE_ERROR = "infrastructure-error"
    ENVIRONMENT_BLOCKED = "environment-blocked"
    UNKNOWN = "unknown"


class BrowserEffectStatus(str, Enum):
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    UNKNOWN = "unknown"


def _text(value: object, *, label: str, limit: int = _MAX_TEXT, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise BrowserContractError(f"{label} must be a string")
    if len(value) > limit or any(token in value for token in _CONTROL[:3]):
        raise BrowserContractError(f"{label} is malformed or exceeds its bound")
    return value


def _id(value: object, label: str) -> str:
    return _text(value, label=label, limit=_MAX_ID)


def _digest(value: object, *, label: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise BrowserContractError(f"{label} must be a SHA-256 digest")
    return value


def _bounded_items(value: object, *, label: str, limit: int = _MAX_ITEMS) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > limit:
        raise BrowserContractError(f"{label} must be a bounded tuple")
    result = tuple(_text(item, label=label) for item in value)
    if len(result) != len(set(result)):
        raise BrowserContractError(f"{label} contains duplicates")
    return result


def _relative_path(value: object, *, label: str, allow_dot: bool = True) -> str:
    text = _text(value, label=label, limit=2048)
    normalized = text.replace("\\", "/")
    if normalized in {".", "./"}:
        if allow_dot:
            return "."
        raise BrowserContractError(f"{label} must not be the workspace root")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise BrowserContractError(f"{label} must be workspace-relative")
    path = PurePosixPath(normalized)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BrowserContractError(f"{label} contains traversal")
    if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in path.parts):
        raise BrowserContractError(f"{label} reaches protected metadata")
    return path.as_posix()


def _origin(value: object, *, label: str = "origin") -> str:
    text = _text(value, label=label, limit=2048)
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise BrowserContractError(f"{label} must be a plain HTTP(S) origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise BrowserContractError(f"{label} must not contain a path or credentials")
    hostname = parsed.hostname
    if hostname is None or hostname.casefold() not in {"127.0.0.1", "localhost"}:
        raise BrowserContractError(f"{label} must be loopback")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BrowserContractError(f"{label} has an invalid port") from exc
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise BrowserContractError(f"{label} port is invalid")
    host = "127.0.0.1" if hostname.casefold() == "localhost" else hostname.casefold()
    # Keep the explicit port in the canonical origin, including default HTTP
    # ports.  BrowserManager and the app instance bind exact host:port pairs;
    # dropping ``:80``/``:443`` here would make those pairs compare
    # inconsistently at the session boundary.
    authority = f"{host}:{port}"
    return urlunsplit((parsed.scheme, authority, "", "", ""))


def _selector(value: object) -> str:
    selector = _text(value, label="selector", limit=_MAX_SELECTOR)
    lowered = selector.casefold()
    if "xpath=" in lowered or "javascript:" in lowered or "evaluate" in lowered:
        raise BrowserContractError("selector must be semantic and cannot execute code")
    if selector.startswith("(") or re.search(r"\b(?:x|y)\s*[:=]\s*\d+", selector):
        raise BrowserContractError("coordinate or expression selectors are not allowed")
    return selector


def _secret_key(key: str) -> bool:
    folded = key.casefold().replace("-", "_")
    return any(word in folded for word in _SECRET_WORDS)


def redact_untrusted(value: object, *, limit: int = _MAX_TEXT) -> str:
    """Return bounded observation text with common credential material masked."""
    text = str(value) if value is not None else ""
    text = text.replace("\x00", "")[:limit]
    # Do not preserve bearer/API-key/cookie values in DOM, console, or URL
    # observations.  The key/value shapes are intentionally conservative.
    text = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)((?:api[_-]?key|token|password|secret|cookie)\s*[:=]\s*)[^\s,;]+", r"\1<redacted>", text)
    text = re.sub(
        r"(?i)(https?://[^\s/?#]+/[^?\s#]*)\?[^\s#]*",
        r"\1?<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)(https?://[^\s/?#]+)\?[^\s#]*",
        r"\1?<redacted>",
        text,
    )
    return text


@dataclass(frozen=True, slots=True)
class BrowserArtifactRef:
    """Metadata-only reference to a quarantined browser artifact."""

    artifact_id: str
    kind: str
    size_bytes: int
    sha256: str
    path: str = ""
    quarantined: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _id(self.artifact_id, "artifact_id"))
        object.__setattr__(self, "kind", _text(self.kind, label="artifact kind", limit=64))
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= _MAX_ARTIFACT_BYTES:
            raise BrowserContractError("artifact size is invalid")
        object.__setattr__(self, "sha256", _digest(self.sha256, label="artifact sha256"))
        if self.path:
            object.__setattr__(self, "path", _relative_path(self.path, label="artifact path"))
        if type(self.quarantined) is not bool:
            raise BrowserContractError("artifact quarantine flag is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "path": self.path,
            "quarantined": self.quarantined,
        }


@dataclass(frozen=True, slots=True)
class AppLaunchProfile:
    """Trusted, model-independent recipe for one local development app."""

    profile_id: str
    argv: tuple[str, ...]
    cwd: str = "."
    readiness_path: str = "/"
    expected_statuses: tuple[int, ...] = (200,)
    port_range: tuple[int, int] = (3000, 3999)
    environment: tuple[tuple[str, str], ...] = ()
    provenance: str = "trusted:operator"
    listen_address: str = "127.0.0.1"
    profile_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _id(self.profile_id, "profile_id"))
        if type(self.argv) is not tuple or not self.argv or len(self.argv) > 64:
            raise BrowserContractError("app argv must be a non-empty immutable tuple")
        for index, token in enumerate(self.argv):
            item = _text(token, label="app argv", limit=2048)
            if any(control in item for control in _CONTROL[3:]):
                raise BrowserContractError("app argv contains shell control syntax")
            if item.casefold() in {"-c", "--command", "--eval", "-e", "--shell"}:
                raise BrowserContractError("app profiles cannot use inline evaluation")
            if index == 0 and PurePosixPath(item).name.casefold() in _SHELL_LAUNCHERS:
                raise BrowserContractError("app profiles cannot launch a shell")
        if not PurePosixPath(self.argv[0]).is_absolute():
            raise BrowserContractError("trusted app argv[0] must be an absolute executable path")
        if self.argv.count("{port}") != 1:
            raise BrowserContractError("app argv must contain exactly one {port} placeholder")
        object.__setattr__(self, "cwd", _relative_path(self.cwd, label="app cwd"))
        readiness = _text(self.readiness_path, label="readiness path", limit=512)
        if not readiness.startswith("/") or ".." in PurePosixPath(readiness).parts:
            raise BrowserContractError("readiness path must be an absolute URL path without traversal")
        object.__setattr__(self, "readiness_path", readiness)
        if type(self.expected_statuses) is not tuple or not self.expected_statuses or any(
            type(status) is not int or not 100 <= status <= 599 for status in self.expected_statuses
        ):
            raise BrowserContractError("expected HTTP statuses are invalid")
        if type(self.port_range) is not tuple or len(self.port_range) != 2:
            raise BrowserContractError("port range must contain two integers")
        low, high = self.port_range
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
            raise BrowserContractError("port range is invalid")
        normalized_env: list[tuple[str, str]] = []
        if type(self.environment) is not tuple or len(self.environment) > 32:
            raise BrowserContractError("app environment is invalid")
        for item in self.environment:
            if type(item) is not tuple or len(item) != 2:
                raise BrowserContractError("app environment entries must be pairs")
            key = _text(item[0], label="app environment key", limit=128)
            value = _text(item[1], label="app environment value", limit=1024, allow_empty=True)
            if key == "PORT" or _secret_key(key) or any(control in value for control in _CONTROL[:3]):
                raise BrowserContractError("app profile cannot contain credential material")
            normalized_env.append((key, value))
        if len({key for key, _ in normalized_env}) != len(normalized_env):
            raise BrowserContractError("app environment contains duplicate keys")
        object.__setattr__(self, "environment", tuple(sorted(normalized_env)))
        provenance = _text(self.provenance, label="app profile provenance", limit=256)
        if not provenance.casefold().startswith("trusted:"):
            raise BrowserContractError("app profile provenance must be trusted and explicit")
        object.__setattr__(self, "provenance", provenance)
        if self.listen_address != "127.0.0.1":
            raise BrowserContractError("app listeners must bind exactly to 127.0.0.1")
        computed = canonical_digest(self._payload_without_digest())
        if self.profile_digest:
            object.__setattr__(self, "profile_digest", _digest(self.profile_digest, label="profile digest"))
            if self.profile_digest != computed:
                raise BrowserContractError("profile digest does not match profile semantics")
        else:
            object.__setattr__(self, "profile_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "argv": self.argv,
            "cwd": self.cwd,
            "readiness_path": self.readiness_path,
            "expected_statuses": self.expected_statuses,
            "port_range": self.port_range,
            "environment": self.environment,
            "provenance": self.provenance,
            "listen_address": self.listen_address,
        }

    def launch_argv(self, port: int) -> tuple[str, ...]:
        if type(port) is not int or not 1 <= port <= 65535:
            raise BrowserContractError("launch port is invalid")
        return tuple(token.replace("{port}", str(port)) for token in self.argv)

    def origin(self, port: int) -> str:
        self.launch_argv(port)
        return f"http://127.0.0.1:{port}"

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["profile_digest"] = self.profile_digest
        return payload


@dataclass(frozen=True, slots=True)
class AppInstance:
    instance_id: str
    profile_id: str
    profile_digest: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    principal_id: str
    project_id: str
    execution_id: str
    listen_address: str
    port: int
    origin: str
    state: AppInstanceState = AppInstanceState.STARTING
    health: AppHealth = AppHealth.STARTING
    instance_digest: str = ""

    def __post_init__(self) -> None:
        for label in (
            "instance_id",
            "profile_id",
            "task_id",
            "workspace_id",
            "principal_id",
            "project_id",
            "execution_id",
        ):
            object.__setattr__(self, label, _id(getattr(self, label), label))
        object.__setattr__(self, "profile_digest", _digest(self.profile_digest, label="profile digest"))
        if type(self.workspace_generation) is not int or self.workspace_generation <= 0:
            raise BrowserContractError("app workspace generation is invalid")
        if self.listen_address != "127.0.0.1":
            raise BrowserContractError("app listen address is invalid")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise BrowserContractError("app port is invalid")
        expected_origin = f"http://127.0.0.1:{self.port}"
        if _origin(self.origin, label="app origin") != expected_origin:
            raise BrowserContractError("app origin is not bound to its exact port")
        state = self.state if isinstance(self.state, AppInstanceState) else AppInstanceState(self.state)
        health = self.health if isinstance(self.health, AppHealth) else AppHealth(self.health)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "health", health)
        computed = canonical_digest(self._payload_without_digest())
        if self.instance_digest:
            object.__setattr__(self, "instance_digest", _digest(self.instance_digest, label="instance digest"))
            if self.instance_digest != computed:
                raise BrowserContractError("instance digest does not match app identity")
        else:
            object.__setattr__(self, "instance_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "instance_id": self.instance_id,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "execution_id": self.execution_id,
            "listen_address": self.listen_address,
            "port": self.port,
            "origin": self.origin,
            "state": self.state.value,
            "health": self.health.value,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["instance_digest"] = self.instance_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserSessionBinding:
    principal_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    session_id: str
    runtime_id: str
    browser_runtime_id: str
    browser_context_id: str
    app_instance_id: str
    app_instance_digest: str
    allowed_origins: tuple[str, ...]
    policy_digest: str
    state: BrowserSessionState = BrowserSessionState.READY
    binding_digest: str = ""
    repository_generation: int = 0

    def __post_init__(self) -> None:
        for label in (
            "principal_id",
            "project_id",
            "task_id",
            "workspace_id",
            "session_id",
            "runtime_id",
            "browser_runtime_id",
            "browser_context_id",
            "app_instance_id",
        ):
            object.__setattr__(self, label, _id(getattr(self, label), label))
        if type(self.workspace_generation) is not int or self.workspace_generation <= 0:
            raise BrowserContractError("session workspace generation is invalid")
        if self.repository_generation == 0:
            object.__setattr__(self, "repository_generation", self.workspace_generation)
        if type(self.repository_generation) is not int or self.repository_generation < 0:
            raise BrowserContractError("session repository generation is invalid")
        object.__setattr__(self, "app_instance_digest", _digest(self.app_instance_digest, label="app instance digest"))
        object.__setattr__(self, "policy_digest", _digest(self.policy_digest, label="policy digest", allow_empty=True))
        if type(self.allowed_origins) is not tuple or not self.allowed_origins or len(self.allowed_origins) > 8:
            raise BrowserContractError("session origins are invalid")
        origins = tuple(sorted({_origin(origin, label="allowed origin") for origin in self.allowed_origins}))
        object.__setattr__(self, "allowed_origins", origins)
        state = self.state if isinstance(self.state, BrowserSessionState) else BrowserSessionState(self.state)
        object.__setattr__(self, "state", state)
        computed = canonical_digest(self._payload_without_digest())
        if self.binding_digest:
            object.__setattr__(self, "binding_digest", _digest(self.binding_digest, label="binding digest"))
            if self.binding_digest != computed:
                raise BrowserContractError("binding digest does not match session identity")
        else:
            object.__setattr__(self, "binding_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "session_id": self.session_id,
            "runtime_id": self.runtime_id,
            "browser_runtime_id": self.browser_runtime_id,
            "browser_context_id": self.browser_context_id,
            "app_instance_id": self.app_instance_id,
            "app_instance_digest": self.app_instance_digest,
            "allowed_origins": self.allowed_origins,
            "policy_digest": self.policy_digest,
            "state": self.state.value,
            "repository_generation": self.repository_generation,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["binding_digest"] = self.binding_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserAction:
    action_id: str
    session_id: str
    sequence: int
    kind: BrowserActionKind
    effect_class: BrowserEffectClass
    selector: str = ""
    value: str = ""
    target_url: str = ""
    key: str = ""
    wait_for: str = ""
    file_path: str = ""
    precondition_digest: str = ""
    approval_digest: str = ""
    action_digest: str = ""
    # A model may name an operator-authorized credential, but the opaque lease
    # and its secret material are injected by the trusted tool context.
    credential_name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_id", _id(self.action_id, "action_id"))
        object.__setattr__(self, "session_id", _id(self.session_id, "session_id"))
        if type(self.sequence) is not int or self.sequence <= 0 or self.sequence > 10000:
            raise BrowserContractError("action sequence is invalid")
        kind = self.kind if isinstance(self.kind, BrowserActionKind) else BrowserActionKind(self.kind)
        effect = self.effect_class if isinstance(self.effect_class, BrowserEffectClass) else BrowserEffectClass(self.effect_class)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "effect_class", effect)
        if self.selector:
            object.__setattr__(self, "selector", _selector(self.selector))
        for label in ("value", "key", "wait_for"):
            object.__setattr__(self, label, _text(getattr(self, label), label=label, limit=_MAX_TEXT, allow_empty=True))
        if self.target_url:
            object.__setattr__(self, "target_url", _text(self.target_url, label="target URL", limit=2048))
        if self.file_path:
            object.__setattr__(self, "file_path", _relative_path(self.file_path, label="file path", allow_dot=False))
        if self.credential_name:
            object.__setattr__(self, "credential_name", _id(self.credential_name, "credential name"))
        if self.credential_name and (kind is not BrowserActionKind.TYPE or self.value):
            raise BrowserContractError(
                "credential actions must be type actions without a model value"
            )
        object.__setattr__(self, "precondition_digest", _digest(self.precondition_digest, label="precondition digest", allow_empty=True))
        object.__setattr__(self, "approval_digest", _digest(self.approval_digest, label="approval digest", allow_empty=True))
        computed = canonical_digest(self._payload_without_digest())
        if self.action_digest:
            object.__setattr__(self, "action_digest", _digest(self.action_digest, label="action digest"))
            if self.action_digest != computed:
                raise BrowserContractError("action digest does not match action arguments")
        else:
            object.__setattr__(self, "action_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "kind": self.kind.value,
            "effect_class": self.effect_class.value,
            "selector": self.selector,
            # Store a digest for potentially sensitive typed values.  The
            # service still receives the value in-memory but never emits it
            # in an observation, result, or audit payload.
            "value_digest": canonical_digest(self.value) if self.value else "",
            "target_url": self.target_url,
            "key": self.key,
            "wait_for": self.wait_for,
            "file_path": self.file_path,
            "precondition_digest": self.precondition_digest,
            "approval_digest": self.approval_digest,
            "credential_name": self.credential_name,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        target_url = payload.pop("target_url", "")
        payload["target_url_digest"] = canonical_digest(target_url) if target_url else ""
        payload["action_digest"] = self.action_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserCheckAction:
    kind: BrowserActionKind
    selector: str = ""
    value: str = ""
    target_url: str = ""
    key: str = ""
    wait_for: str = ""
    file_path: str = ""

    def __post_init__(self) -> None:
        kind = self.kind if isinstance(self.kind, BrowserActionKind) else BrowserActionKind(self.kind)
        object.__setattr__(self, "kind", kind)
        if self.selector:
            object.__setattr__(self, "selector", _selector(self.selector))
        for label in ("value", "target_url", "key", "wait_for", "file_path"):
            value = getattr(self, label)
            if label == "file_path" and value:
                value = _relative_path(value, label=label, allow_dot=False)
            else:
                value = _text(value, label=label, limit=2048, allow_empty=True)
            object.__setattr__(self, label, value)

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "selector": self.selector,
            "value_digest": canonical_digest(self.value) if self.value else "",
            "target_url_digest": canonical_digest(self.target_url) if self.target_url else "",
            "key": self.key,
            "wait_for": self.wait_for,
            "file_path": self.file_path,
        }


@dataclass(frozen=True, slots=True)
class BrowserAssertion:
    kind: str
    expected: str
    selector: str = ""
    assertion_digest: str = ""

    def __post_init__(self) -> None:
        kind = _text(self.kind, label="assertion kind", limit=64).casefold()
        if kind not in {"text-present", "url-origin", "title-contains", "selector-visible"}:
            raise BrowserContractError("assertion kind is not supported")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "expected", _text(self.expected, label="assertion expected", limit=2048))
        if self.selector:
            object.__setattr__(self, "selector", _selector(self.selector))
        if kind == "selector-visible" and not self.selector:
            raise BrowserContractError("selector-visible assertion requires a selector")
        computed = canonical_digest({"kind": kind, "expected": self.expected, "selector": self.selector})
        if self.assertion_digest:
            object.__setattr__(self, "assertion_digest", _digest(self.assertion_digest, label="assertion digest"))
            if self.assertion_digest != computed:
                raise BrowserContractError("assertion digest does not match assertion")
        else:
            object.__setattr__(self, "assertion_digest", computed)

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "expected": self.expected,
            "selector": self.selector,
            "assertion_digest": self.assertion_digest,
        }


@dataclass(frozen=True, slots=True)
class BrowserVerificationSpec:
    spec_id: str
    app_profile_id: str
    start_path: str = "/"
    actions: tuple[BrowserCheckAction, ...] = ()
    assertions: tuple[BrowserAssertion, ...] = ()
    expected_origin: str = ""
    profile_digest: str = ""
    spec_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "spec_id", _id(self.spec_id, "browser spec id"))
        object.__setattr__(self, "app_profile_id", _id(self.app_profile_id, "browser app profile id"))
        path = _text(self.start_path, label="browser start path", limit=512)
        if not path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise BrowserContractError("browser start path is unsafe")
        object.__setattr__(self, "start_path", path)
        if type(self.actions) is not tuple or len(self.actions) > 64 or any(type(item) is not BrowserCheckAction for item in self.actions):
            raise BrowserContractError("browser spec actions are invalid")
        if type(self.assertions) is not tuple or len(self.assertions) > 64 or any(type(item) is not BrowserAssertion for item in self.assertions):
            raise BrowserContractError("browser spec assertions are invalid")
        if self.expected_origin:
            object.__setattr__(self, "expected_origin", _origin(self.expected_origin, label="expected browser origin"))
        object.__setattr__(self, "profile_digest", _digest(self.profile_digest, label="browser profile digest", allow_empty=True))
        computed = canonical_digest(self._payload_without_digest())
        if self.spec_digest:
            object.__setattr__(self, "spec_digest", _digest(self.spec_digest, label="browser spec digest"))
            if self.spec_digest != computed:
                raise BrowserContractError("browser spec digest does not match spec")
        else:
            object.__setattr__(self, "spec_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "spec_id": self.spec_id,
            "app_profile_id": self.app_profile_id,
            "start_path": self.start_path,
            "actions": tuple(item.to_payload() for item in self.actions),
            "assertions": tuple(item.to_payload() for item in self.assertions),
            "expected_origin": self.expected_origin,
            "profile_digest": self.profile_digest,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["spec_digest"] = self.spec_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserObservation:
    binding_digest: str
    action_id: str
    sequence: int
    url: str
    origin: str
    title: str = ""
    semantic_text: tuple[str, ...] = ()
    accessibility: tuple[str, ...] = ()
    console: tuple[str, ...] = ()
    network: tuple[str, ...] = ()
    artifacts: tuple[BrowserArtifactRef, ...] = ()
    trust_label: str = "untrusted-observation"
    observation_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "binding_digest", _digest(self.binding_digest, label="observation binding digest"))
        object.__setattr__(self, "action_id", _id(self.action_id, "observation action id"))
        if type(self.sequence) is not int or self.sequence < 0:
            raise BrowserContractError("observation sequence is invalid")
        object.__setattr__(self, "url", _text(self.url, label="observation URL", limit=4096, allow_empty=True))
        normalized_origin = _origin(self.origin, label="observation origin")
        object.__setattr__(self, "origin", normalized_origin)
        object.__setattr__(self, "title", redact_untrusted(self.title, limit=512))
        for label in ("semantic_text", "accessibility", "console", "network"):
            values = getattr(self, label)
            if type(values) is not tuple or len(values) > _MAX_ITEMS:
                raise BrowserContractError(f"{label} observation is unbounded")
            object.__setattr__(self, label, tuple(redact_untrusted(item, limit=1024) for item in values))
        if type(self.artifacts) is not tuple or len(self.artifacts) > _MAX_ARTIFACTS or any(type(item) is not BrowserArtifactRef for item in self.artifacts):
            raise BrowserContractError("observation artifacts are invalid")
        object.__setattr__(self, "trust_label", "untrusted-observation")
        computed = canonical_digest(self._payload_without_digest())
        if self.observation_digest:
            object.__setattr__(self, "observation_digest", _digest(self.observation_digest, label="observation digest"))
            if self.observation_digest != computed:
                raise BrowserContractError("observation digest does not match observation")
        else:
            object.__setattr__(self, "observation_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "action_id": self.action_id,
            "sequence": self.sequence,
            "url": redact_untrusted(self.url, limit=4096),
            "origin": self.origin,
            "title": self.title,
            "semantic_text": self.semantic_text,
            "accessibility": self.accessibility,
            "console": self.console,
            "network": self.network,
            "artifacts": tuple(item.to_payload() for item in self.artifacts),
            "trust_label": self.trust_label,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["observation_digest"] = self.observation_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserActionResult:
    action: BrowserAction
    status: BrowserResultStatus
    effect_status: BrowserEffectStatus
    observation: BrowserObservation | None = None
    error_category: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if type(self.action) is not BrowserAction:
            raise BrowserContractError("action result action is invalid")
        status = self.status if isinstance(self.status, BrowserResultStatus) else BrowserResultStatus(self.status)
        effect = self.effect_status if isinstance(self.effect_status, BrowserEffectStatus) else BrowserEffectStatus(self.effect_status)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "effect_status", effect)
        if self.observation is not None and type(self.observation) is not BrowserObservation:
            raise BrowserContractError("action result observation is invalid")
        if self.error_category:
            object.__setattr__(self, "error_category", _text(self.error_category, label="error category", limit=64))
        if self.error:
            object.__setattr__(self, "error", redact_untrusted(self.error, limit=512))


@dataclass(frozen=True, slots=True)
class BrowserVerificationEvidence:
    run_id: str
    plan_id: str
    check_id: str
    workspace_id: str
    workspace_generation: int
    repository_generation: int
    session_id: str
    app_instance_digest: str
    binding_digest: str
    observation_digest: str
    action_digests: tuple[str, ...]
    assertion_digests: tuple[str, ...]
    status: BrowserResultStatus
    artifact_refs: tuple[str, ...] = ()
    created_at: float = 0.0
    evidence_digest: str = ""

    def __post_init__(self) -> None:
        for label in ("run_id", "plan_id", "check_id", "workspace_id", "session_id"):
            object.__setattr__(self, label, _id(getattr(self, label), label))
        for label, value in (
            ("app_instance_digest", self.app_instance_digest),
            ("binding_digest", self.binding_digest),
            ("observation_digest", self.observation_digest),
        ):
            _digest(value, label=label)
        if type(self.workspace_generation) is not int or self.workspace_generation < 0:
            raise BrowserContractError("evidence workspace generation is invalid")
        if type(self.repository_generation) is not int or self.repository_generation < 0:
            raise BrowserContractError("evidence repository generation is invalid")
        if type(self.action_digests) is not tuple or any(_DIGEST.fullmatch(item or "") is None for item in self.action_digests):
            raise BrowserContractError("evidence action digests are invalid")
        if type(self.assertion_digests) is not tuple or any(_DIGEST.fullmatch(item or "") is None for item in self.assertion_digests):
            raise BrowserContractError("evidence assertion digests are invalid")
        if type(self.artifact_refs) is not tuple or len(self.artifact_refs) > _MAX_ARTIFACTS or any(type(item) is not str for item in self.artifact_refs):
            raise BrowserContractError("evidence artifact refs are invalid")
        if type(self.created_at) not in (int, float) or not math.isfinite(float(self.created_at)) or self.created_at < 0:
            raise BrowserContractError("evidence timestamp is invalid")
        status = self.status if isinstance(self.status, BrowserResultStatus) else BrowserResultStatus(self.status)
        object.__setattr__(self, "status", status)
        computed = canonical_digest(self._payload_without_digest())
        if self.evidence_digest:
            object.__setattr__(self, "evidence_digest", _digest(self.evidence_digest, label="browser evidence digest"))
            if self.evidence_digest != computed:
                raise BrowserContractError("browser evidence digest does not match evidence")
        else:
            object.__setattr__(self, "evidence_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "repository_generation": self.repository_generation,
            "session_id": self.session_id,
            "app_instance_digest": self.app_instance_digest,
            "binding_digest": self.binding_digest,
            "observation_digest": self.observation_digest,
            "action_digests": self.action_digests,
            "assertion_digests": self.assertion_digests,
            "status": self.status.value,
            "artifact_refs": self.artifact_refs,
            "created_at": self.created_at,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["evidence_digest"] = self.evidence_digest
        return payload


@dataclass(frozen=True, slots=True)
class BrowserRunResult:
    status: BrowserResultStatus
    session: BrowserSessionBinding | None = None
    action_results: tuple[BrowserActionResult, ...] = ()
    observation: BrowserObservation | None = None
    evidence: BrowserVerificationEvidence | None = None
    error_category: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        status = self.status if isinstance(self.status, BrowserResultStatus) else BrowserResultStatus(self.status)
        object.__setattr__(self, "status", status)
        if type(self.action_results) is not tuple or len(self.action_results) > 64 or any(type(item) is not BrowserActionResult for item in self.action_results):
            raise BrowserContractError("browser run action results are invalid")
        if self.session is not None and type(self.session) is not BrowserSessionBinding:
            raise BrowserContractError("browser run session is invalid")
        if self.observation is not None and type(self.observation) is not BrowserObservation:
            raise BrowserContractError("browser run observation is invalid")
        if self.evidence is not None and type(self.evidence) is not BrowserVerificationEvidence:
            raise BrowserContractError("browser run evidence is invalid")
        if self.error_category:
            object.__setattr__(self, "error_category", _text(self.error_category, label="run error category", limit=64))
        if self.error:
            object.__setattr__(self, "error", redact_untrusted(self.error, limit=512))


__all__ = [
    "AppHealth",
    "AppInstance",
    "AppInstanceState",
    "AppLaunchProfile",
    "BrowserAction",
    "BrowserActionKind",
    "BrowserActionResult",
    "BrowserArtifactRef",
    "BrowserAssertion",
    "BrowserCheckAction",
    "BrowserContractError",
    "BrowserEffectClass",
    "BrowserEffectStatus",
    "BrowserObservation",
    "BrowserResultStatus",
    "BrowserRunResult",
    "BrowserSessionBinding",
    "BrowserSessionState",
    "BrowserVerificationEvidence",
    "BrowserVerificationSpec",
    "redact_untrusted",
]
