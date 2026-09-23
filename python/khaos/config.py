"""Configuration loading and environment placeholder expansion."""

from __future__ import annotations

import asyncio
import copy
import getpass
import logging
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from khaos.exceptions import KhaosError
from khaos.security.credential_broker import CredentialBroker, CredentialBrokerError
from khaos.security.credentials import (
    CredentialAccessMode,
    CredentialRef,
    SecretValue,
    build_platform_credential_store,
    credential_store_backend_audit,
    provider_config_digest,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from khaos.routing.provider import DiscoveredModel


class ConfigError(KhaosError):
    """Raised when config.yaml cannot be resolved safely."""


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
USER_CONFIG_PATH = Path("~/.khaos/config.yaml")
PROJECT_CONFIG_PATH = Path("config.yaml")


def _user_config_path() -> Path:
    """Resolve the user config using the current process environment.

    ``Path('~').expanduser()`` follows ``USERPROFILE`` on Windows and does
    not honor a deployment/test-provided ``HOME`` override. Khaos treats
    HOME as its portable configuration root, so use it explicitly and fall
    back to the platform's normal home lookup.
    """
    home = os.environ.get("HOME") or str(Path.home())
    return Path(home) / ".khaos" / "config.yaml"


def _is_trusted_user_config_path(path: Path) -> bool:
    """Recognize only the canonical user-config pathname as trusted.

    Use normalized absolute path strings without resolving symlinks.  A
    repository-controlled symlink that happens to point at the user config
    must not promote an explicitly supplied project path into the trusted
    user layer.
    """
    return os.path.abspath(os.fspath(path)) == os.path.abspath(
        os.fspath(_user_config_path())
    )


class ConfigAuthority(Enum):
    """Authorities that may contribute effective configuration fields."""

    MANAGED_REQUIREMENT = "managed-requirement"
    USER_GRANT = "user-grant"
    PROJECT_RESTRICTION = "project-restriction"
    RUNTIME_OVERRIDE = "runtime-override"


@dataclass(frozen=True)
class ConfigProvenance:
    """Source metadata for one effective dotted configuration field."""

    authority: ConfigAuthority
    source: str


class EffectiveConfig(dict[str, Any]):
    """Dictionary-compatible effective config with field provenance."""

    def __init__(
        self,
        value: dict[str, Any],
        provenance: dict[str, ConfigProvenance],
    ) -> None:
        super().__init__(value)
        self.provenance = dict(provenance)


# Project repositories are untrusted input.  These paths control host-side
# credential destinations or host integrations and therefore may only come
# from a user/managed/runtime authority.  Prefix matching intentionally makes
# the entire provider object trusted-only: allowing selected children would
# make future credential/header fields fail open when the schema grows.
_PROJECT_FORBIDDEN_PREFIXES = (
    "models.providers",
    # A repository must not be able to install or redirect a memory provider
    # to a host/network endpoint.  Memory profiles may remain project-scoped,
    # but provider manifests and their endpoint/credential selectors are
    # trusted user/managed configuration only.
    "memory.providers",
    "gateway",
    "agent.socket",
)

PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "nvidia": {
        "label": "NVIDIA NIM (免费额度，推荐)",
        "type": "openai_compatible",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model": "qwen/qwen3.5-122b-a10b",
    },
    "anthropic": {
        "label": "Anthropic Claude",
        "type": "anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-20250514",
    },
    "openai": {
        "label": "OpenAI",
        "type": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
    },
    "zhipu": {
        "label": "智谱 API",
        "type": "openai_compatible",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-5.3-flash",
    },
    "zhipu-coding": {
        "label": "智谱 Coding Plan",
        "type": "openai_compatible",
        "base_url": "https://open.bigmodel.cn/api/coding/paas/v4",
        "model": "glm-5.3-flash",
    },
    "siliconflow": {
        "label": "硅基流动 SiliconFlow",
        "type": "openai_compatible",
        "base_url": "https://api.siliconflow.cn/v1",
        "model": "deepseek-ai/DeepSeek-V4-Flash",
    },
}
_PROVIDER_ENV_KEYS = {
    "nvidia": "NVIDIA_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "zhipu": "ZAI_API_KEY",
    "zhipu-coding": "ZAI_CODING_API_KEY",
    "siliconflow": "SILICONFLOW_API_KEY",
}
MODEL_DISCOVERY_TIMEOUT_SECONDS = 30


def expand_env_placeholders(value: str, *, source: str = "config.yaml", strict: bool = True) -> str:
    """Expand ${ENV_VAR} placeholders inside one config string.

    Plain strings without placeholders are returned unchanged. Nested strings
    such as ``${HOME}/.khaos/config.yaml`` are supported.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in os.environ:
            return os.environ[name]
        if strict:
            raise ConfigError(
                f"Missing environment variable {name!r} referenced by {source}. "
                f"Export {name} before starting Khaos, or replace the placeholder with a literal value."
            )
        return match.group(0)

    return _ENV_PATTERN.sub(replace, value)


def expand_config_placeholders(value: Any, *, source: str = "config.yaml", strict: bool = True) -> Any:
    """Recursively expand environment placeholders in parsed config data."""
    if isinstance(value, str):
        return expand_env_placeholders(value, source=source, strict=strict)
    if isinstance(value, list):
        return [
            expand_config_placeholders(item, source=f"{source}[{index}]", strict=strict)
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            key: expand_config_placeholders(item, source=f"{source}.{key}", strict=strict)
            for key, item in value.items()
        }
    return value


def load_config(
    path: str | Path | None = None,
    *,
    strict_env: bool = True,
    project_path: str | Path | None = None,
) -> dict[str, Any]:
    """Load the effective configuration with source-derived authority.

    With no explicit path, the project template is loaded first and
    ``~/.khaos/config.yaml`` is merged on top so user config wins.

    An explicit project file path is still file-backed, untrusted input.  It
    is never promoted to a runtime override merely because a caller supplied
    its name.  The one explicit-path exception is the canonical user config
    path: callers may pass it to select the trusted user layer, but it still
    receives the normal untrusted-project-plus-user merge.  Runtime overrides
    must be parsed structured values from an authenticated caller; this API
    deliberately has no file-backed runtime override path.
    """
    if path is not None:
        config_path = Path(path).expanduser()
        if not _is_trusted_user_config_path(config_path):
            project = _read_yaml_file(config_path)
            _validate_project_config(project, source=str(config_path))
            _reject_plaintext_provider_credentials(
                project, source=str(config_path)
            )
            user_path = user_config_path()
            user = _read_yaml_file(user_path) if user_path.exists() else {}
            _reject_plaintext_provider_credentials(user, source=str(user_path))
            expanded_user = expand_config_placeholders(
                user, source=str(user_path), strict=strict_env
            )
            managed = _managed_provider_config()
            merged = deep_merge(managed, project)
            merged = deep_merge(merged, expanded_user)
            provenance = _field_provenance(
                managed, ConfigAuthority.MANAGED_REQUIREMENT,
                "trusted environment",
            )
            provenance.update(
                _field_provenance(
                    project, ConfigAuthority.PROJECT_RESTRICTION, str(config_path)
                )
            )
            provenance.update(
                _field_provenance(
                    expanded_user, ConfigAuthority.USER_GRANT, str(user_path)
                )
            )
            return EffectiveConfig(merged, provenance)

    project_path = Path(project_path or PROJECT_CONFIG_PATH).expanduser().resolve()
    user_path = (
        Path(path).expanduser()
        if path is not None
        else user_config_path()
    )
    project = _read_yaml_file(project_path) if project_path.exists() else {}
    _validate_project_config(project, source=str(project_path))
    _reject_plaintext_provider_credentials(project, source=str(project_path))
    user = _read_yaml_file(user_path) if user_path.exists() else {}
    _reject_plaintext_provider_credentials(user, source=str(user_path))

    # Environment expansion is deliberately performed only on the trusted
    # user layer.  A repository must never be able to name a host secret even
    # when the merged destination field would otherwise come from the user.
    expanded_user = expand_config_placeholders(
        user, source=str(user_path), strict=strict_env
    )
    managed = _managed_provider_config()
    merged = deep_merge(managed, project)
    merged = deep_merge(merged, expanded_user)
    provenance = _field_provenance(
        managed, ConfigAuthority.MANAGED_REQUIREMENT, "trusted environment"
    )
    provenance.update(
        _field_provenance(
            project, ConfigAuthority.PROJECT_RESTRICTION, str(project_path)
        )
    )
    provenance.update(
        _field_provenance(
            expanded_user, ConfigAuthority.USER_GRANT, str(user_path)
        )
    )
    return EffectiveConfig(merged, provenance)


def _managed_provider_config() -> dict[str, Any]:
    """Reject legacy provider environment credentials instead of importing them."""
    for env_name in _PROVIDER_ENV_KEYS.values():
        if os.environ.get(env_name, "").strip():
            raise ConfigError(
                f"provider credential environment variable {env_name!r} is unsupported; "
                "store the credential in the platform credential store and use credential_ref"
            )
    return {}


_PROVIDER_SECRET_FIELDS = frozenset(
    {
        "api_key",
        "apikey",
        "api_key_env",
        "access_token",
        "access_token_env",
        "secret",
        "secret_env",
        "password",
        "password_env",
        "token",
        "token_env",
        "authorization",
        "authorization_env",
        "credential",
        "credentials",
    }
)


def _reject_plaintext_provider_credentials(
    config: Mapping[str, Any], *, source: str
) -> None:
    """Reject provider secret fields before they can enter effective config."""
    for dotted_path, value in _walk_config(dict(config)):
        parts = [
            part.casefold()
            for part in dotted_path.replace("[", ".").replace("]", "").split(".")
            if part
        ]
        in_provider = "models" in parts and "providers" in parts
        if not in_provider:
            continue
        field = parts[-1].split(".")[-1]
        if field in _PROVIDER_SECRET_FIELDS:
            raise ConfigError(
                f"plaintext provider credential field {dotted_path!r} from {source} "
                "is unsupported; use credential_ref"
            )
        if field == "credential_ref" and isinstance(value, str) and _ENV_PATTERN.search(value):
            raise ConfigError(
                f"provider credential_ref {dotted_path!r} from {source} "
                "cannot reference an environment variable"
            )
        if in_provider and isinstance(value, str) and _ENV_PATTERN.search(value):
            raise ConfigError(
                f"provider field {dotted_path!r} from {source} cannot reference "
                "an environment variable"
            )


def config_field_provenance(
    config: dict[str, Any], dotted_path: str
) -> ConfigProvenance | None:
    """Return the authority/source for an effective config field."""
    provenance = getattr(config, "provenance", {})
    return provenance.get(dotted_path)


def _validate_project_config(config: dict[str, Any], *, source: str) -> None:
    """Reject project fields that can grant host authority or read secrets."""
    for dotted_path, value in _walk_config(config):
        if any(
            dotted_path == prefix or dotted_path.startswith(f"{prefix}.")
            for prefix in _PROJECT_FORBIDDEN_PREFIXES
        ):
            logger.error(
                "security.config_rejected source=%s field=%s reason=trusted-only",
                source,
                dotted_path,
            )
            raise ConfigError(
                f"Project config field {dotted_path!r} from {source} is "
                "trusted-only and must be moved to ~/.khaos/config.yaml; "
                "provider credentials must use credential_ref"
            )
        if isinstance(value, str) and _ENV_PATTERN.search(value):
            logger.error(
                "security.config_rejected source=%s field=%s reason=project-env",
                source,
                dotted_path,
            )
            raise ConfigError(
                f"Project config field {dotted_path!r} from {source} cannot "
                "reference host environment variables"
            )


def _walk_config(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_config(child, path)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_config(child, f"{prefix}[{index}]")
        return
    yield prefix, value


def _field_provenance(
    config: dict[str, Any], authority: ConfigAuthority, source: str
) -> dict[str, ConfigProvenance]:
    return {
        path: ConfigProvenance(authority=authority, source=source)
        for path, _value in _walk_config(config)
    }


def check_needs_setup(
    config: dict[str, Any] | None = None,
    *,
    credential_broker: CredentialBroker | None = None,
) -> bool:
    """Return True when no configured provider has a usable stored credential."""
    data = config if config is not None else load_config(strict_env=False)
    if isinstance(data, dict):
        _reject_plaintext_provider_credentials(data, source="provided config")
    providers = ((data.get("models") or {}).get("providers") or {})
    if not isinstance(providers, dict) or not providers:
        return True
    for provider_name, provider_data in providers.items():
        if not isinstance(provider_data, dict):
            continue
        raw_ref = provider_data.get("credential_ref")
        try:
            ref = CredentialRef.from_config(provider_name, raw_ref)
            broker = credential_broker
            owns_broker = broker is None
            if broker is None:
                broker = CredentialBroker()
                store = build_platform_credential_store()
                broker.register_credential_store(ref, store, provider=provider_name)
            status = broker.provider_credential_status(ref, provider=provider_name)
            if status["credential_present"] is True:
                return False
        except (ConfigError, CredentialBrokerError, OSError, ValueError):
            continue
        finally:
            if credential_broker is None and "broker" in locals() and owns_broker:
                broker.close()
    return True


async def discover_provider_models(
    provider: str,
    credential_ref: CredentialRef,
    credential_broker: CredentialBroker,
    access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
) -> list[DiscoveredModel]:
    """Discover models through the configured provider abstraction.

    Only providers using the OpenAI-compatible wire format currently expose
    a portable ``/models`` catalog.  The provider adapter owns the HTTP
    request so setup does not create a second network or authentication path.
    """
    provider_name = _normalize_provider(provider)
    defaults = PROVIDER_DEFAULTS[provider_name]
    if defaults["type"] not in {"openai_compatible", "openai"}:
        raise ConfigError(
            f"provider {provider_name!r} does not support model discovery"
        )

    # Local imports avoid a config -> routing -> config import cycle while
    # keeping discovery on the canonical provider abstraction.
    from khaos.routing.provider import ProviderConfig
    from khaos.routing.providers import build_provider

    if not isinstance(credential_ref, CredentialRef) or not isinstance(
        credential_broker, CredentialBroker
    ):
        raise ConfigError("secure provider discovery requires CredentialRef and CredentialBroker")
    adapter = build_provider(
        ProviderConfig(
            name=provider_name,
            type=defaults["type"],
            base_url=defaults["base_url"],
            credential_ref=credential_ref,
            timeout=MODEL_DISCOVERY_TIMEOUT_SECONDS,
        ),
        credential_broker=credential_broker,
    )
    return await adapter.list_models(access_mode=access_mode)


def provider_supports_model_discovery(provider: str) -> bool:
    """Return whether setup can query a provider model catalog."""
    provider_name = _normalize_provider(provider)
    return PROVIDER_DEFAULTS[provider_name]["type"] in {
        "openai_compatible",
        "openai",
    }


def parse_model_selection(value: str, model_count: int) -> list[int] | None:
    """Parse one-based model selections into zero-based indexes.

    An empty value selects the first model, while ``all`` selects every
    model.  Invalid, duplicated, or out-of-range indexes return ``None``.
    """
    if model_count <= 0:
        return None
    raw = value.strip().lower()
    if not raw:
        return [0]
    if raw == "all":
        return list(range(model_count))

    indexes: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token.isdigit():
            return None
        index = int(token) - 1
        if index < 0 or index >= model_count or index in indexes:
            return None
        indexes.append(index)
    return indexes or None


def _setup_model_options(
    models: Sequence[DiscoveredModel],
) -> tuple[list[DiscoveredModel], str]:
    """Prompt for enabled models and the default model in CLI setup."""
    print("发现可用模型：")
    for index, model in enumerate(models, start=1):
        details: list[str] = []
        if model.max_context_tokens is not None:
            details.append(f"context={model.max_context_tokens}")
        if model.supports_tools is not None:
            details.append(f"tools={'yes' if model.supports_tools else 'no'}")
        suffix = f" ({', '.join(details)})" if details else ""
        print(f"  {index}. {model.model}{suffix}")

    while True:
        raw = input(
            "选择要启用的模型（编号逗号分隔，all=全部，直接回车=第一个）： "
        )
        indexes = parse_model_selection(raw, len(models))
        if indexes is not None:
            selected = [models[index] for index in indexes]
            break
        print("请输入有效的模型编号，例如 1,3 或 all。")

    if len(selected) == 1:
        return selected, selected[0].model

    print("已选择：")
    for index, model in enumerate(selected, start=1):
        print(f"  {index}. {model.model}")
    while True:
        raw_default = input("选择默认模型编号 [1]: ").strip()
        if not raw_default:
            return selected, selected[0].model
        default_indexes = parse_model_selection(raw_default, len(selected))
        if default_indexes is not None and len(default_indexes) == 1:
            return selected, selected[default_indexes[0]].model
        print("请输入一个有效的默认模型编号。")


def _discover_models_for_setup(
    provider: str,
    credential_ref: CredentialRef,
    credential_broker: CredentialBroker,
) -> list[DiscoveredModel] | None:
    """Run bounded discovery for the synchronous CLI wizard.

    Failure diagnostics deliberately expose only a stable category.  The
    exception text and provider response body are not printed because either
    could contain credential material.
    """
    try:
        models = asyncio.run(
            discover_provider_models(
                provider,
                credential_ref,
                credential_broker,
                CredentialAccessMode.PROVISIONING,
            )
        )
    except Exception as exc:  # noqa: BLE001 - setup must remain redaction-safe
        logger.warning(
            "provider model discovery failed provider=%s error_type=%s",
            provider,
            type(exc).__name__,
        )
        print(
            "模型列表获取失败，未保存 API Key。请检查 provider、Key 或网络后重试。",
            file=sys.stderr,
        )
        return None
    if not models:
        print("Provider 未返回可用模型，未保存 API Key。", file=sys.stderr)
        return None
    return models


def run_setup_wizard(config_path: str | Path | None = None) -> Path | None:
    """Run the terminal first-run provider setup wizard."""
    target = Path(config_path).expanduser() if config_path is not None else user_config_path()
    print("╭──────────────────────────────────╮")
    print("│  Khaos 首次启动配置               │")
    print("│                                  │")
    print("│  检测到未配置模型 API Key         │")
    print("╰──────────────────────────────────╯")
    print("支持的 Provider：")
    print("  1. NVIDIA NIM (免费额度，推荐)")
    print("  2. Anthropic Claude")
    print("  3. OpenAI")
    print("  4. 智谱 API")
    print("  5. 智谱 Coding Plan")
    print("  6. 硅基流动 SiliconFlow")
    provider = _prompt_provider()
    secret = SecretValue(_prompt_api_key(provider))
    credential_ref = CredentialRef.for_provider(provider)
    discovery_ref = CredentialRef.for_provider(
        provider, name=f"setup-{secrets.token_hex(8)}"
    )
    broker = CredentialBroker()
    store = build_platform_credential_store()
    try:
        broker.register_credential_store(discovery_ref, store, provider=provider)
        broker.provision_provider_credential(discovery_ref, secret, provider=provider)
    except CredentialBrokerError as exc:
        logger.warning(
            "provider credential store unavailable provider=%s error_type=%s",
            provider,
            type(exc).__name__,
        )
        print("安全凭据存储不可用，未保存 API Key。", file=sys.stderr)
        broker.close()
        return None

    models: list[DiscoveredModel] | None = None
    default_model: str | None = None
    previous_secret: SecretValue | None = None
    canonical_stored = False
    try:
        if provider_supports_model_discovery(provider):
            models = _discover_models_for_setup(provider, discovery_ref, broker)
            if models is None:
                return None
            models, default_model = _setup_model_options(models)
        broker.register_credential_store(credential_ref, store, provider=provider)
        previous_secret = broker.snapshot_provisioned_provider_credential(
            credential_ref, provider=provider
        )
        broker.provision_provider_credential(credential_ref, secret, provider=provider)
        canonical_stored = True
        broker.delete_provisioned_provider_credential(discovery_ref, provider=provider)
        write_provider_config(
            provider,
            credential_ref,
            target,
            models=models,
            default_model=default_model,
        )
    except Exception as exc:  # noqa: BLE001 - do not expose setup secrets
        logger.warning(
            "provider config write failed provider=%s error_type=%s",
            provider,
            type(exc).__name__,
        )
        if canonical_stored:
            try:
                if previous_secret is None:
                    broker.delete_provisioned_provider_credential(
                        credential_ref, provider=provider
                    )
                else:
                    broker.provision_provider_credential(
                        credential_ref, previous_secret, provider=provider
                    )
            except CredentialBrokerError:
                logger.error(
                    "provider credential rollback failed provider=%s",
                    provider,
                )
        print("配置保存失败，API Key 未写入。", file=sys.stderr)
        return None
    finally:
        # The platform store owns the durable value; the broker only retains
        # the process-local capability and is closed after config publication.
        try:
            broker.delete_provisioned_provider_credential(discovery_ref, provider=provider)
        except CredentialBrokerError:
            # Best effort cleanup is still surfaced in logs without exposing
            # the credential or provider error body.
            logger.error(
                "temporary provider credential cleanup failed provider=%s",
                provider,
            )
        broker.close()
    print(f"✓ 已保存到 {target}")
    return target


def write_provider_config(
    provider: str,
    credential_ref: CredentialRef | str,
    path: str | Path | None = None,
    *,
    models: Sequence[DiscoveredModel] | Sequence[Mapping[str, Any]] | None = None,
    default_model: str | None = None,
) -> Path:
    """Write only a provider reference and safe model metadata to config."""
    provider_name = _normalize_provider(provider)
    ref = (
        credential_ref
        if isinstance(credential_ref, CredentialRef)
        else CredentialRef.from_config(provider_name, credential_ref)
    )
    if ref.provider != provider_name:
        raise ConfigError("credential reference belongs to another provider")
    target = Path(path).expanduser() if path is not None else user_config_path()
    defaults = PROVIDER_DEFAULTS[provider_name]
    config = _read_yaml_file(target) if target.exists() else {}
    _reject_plaintext_provider_credentials(config, source=str(target))
    model_entries = _model_config_entries(provider_name, models)
    selected_default = default_model or str(model_entries[0]["name"])
    if selected_default not in {str(entry["name"]) for entry in model_entries}:
        raise ConfigError("default model must be one of the selected models")
    set_nested_value(config, f"models.providers.{provider_name}.type", defaults["type"])
    set_nested_value(config, f"models.providers.{provider_name}.base_url", defaults["base_url"])
    set_nested_value(
        config,
        f"models.providers.{provider_name}.credential_ref",
        ref.to_config(),
    )
    set_nested_value(config, f"models.providers.{provider_name}.models", model_entries)
    set_nested_value(config, "models.default_model", selected_default)
    _write_yaml_file(target, config)
    return target


def set_provider_credential(
    provider: str,
    secret: str,
    path: str | Path | None = None,
    *,
    store=None,
    models: Sequence[DiscoveredModel] | Sequence[Mapping[str, Any]] | None = None,
    default_model: str | None = None,
) -> Path:
    """Store an operator-supplied secret and publish its opaque config ref.

    This is the narrow CLI/service-facing write operation.  Callers must pass
    the secret directly from a hidden prompt; it is never accepted as a CLI
    argument and is never written to YAML.  ``store`` is injectable only for
    deterministic tests; production uses the native platform store.
    """
    provider_name = _normalize_provider(provider)
    secret_value = SecretValue(secret)
    ref = CredentialRef.for_provider(provider_name)
    broker = CredentialBroker()
    backend = store or build_platform_credential_store()
    stored = False
    previous_secret: SecretValue | None = None
    try:
        broker.register_credential_store(ref, backend, provider=provider_name)
        previous_secret = broker.snapshot_provisioned_provider_credential(
            ref, provider=provider_name
        )
        broker.provision_provider_credential(
            ref, secret_value, provider=provider_name
        )
        stored = True
        return write_provider_config(
            provider_name,
            ref,
            path,
            models=models,
            default_model=default_model,
        )
    except (CredentialBrokerError, ConfigError, OSError, ValueError) as exc:
        if stored:
            try:
                if previous_secret is None:
                    broker.delete_provisioned_provider_credential(
                        ref, provider=provider_name
                    )
                else:
                    broker.provision_provider_credential(
                        ref, previous_secret, provider=provider_name
                    )
            except CredentialBrokerError:
                logger.error(
                    "provider credential rollback failed provider=%s",
                    provider_name,
                )
        raise ConfigError("secure provider credential write failed") from exc
    finally:
        broker.close()


def delete_provider_credential(
    provider: str,
    *,
    store=None,
) -> None:
    """Delete one provider credential from the explicit operator path.

    This helper is intentionally separate from runtime reads.  A missing or
    interaction-required runtime credential never reaches this operation.
    ``store`` is injectable only for deterministic tests.
    """
    provider_name = _normalize_provider(provider)
    ref = CredentialRef.for_provider(provider_name)
    broker = CredentialBroker()
    backend = store or build_platform_credential_store()
    try:
        broker.register_credential_store(ref, backend, provider=provider_name)
        broker.delete_provisioned_provider_credential(
            ref, provider=provider_name
        )
    except (CredentialBrokerError, OSError, ValueError) as exc:
        raise ConfigError("secure provider credential deletion failed") from exc
    finally:
        broker.close()


def _model_config_entries(
    provider_name: str,
    models: Sequence[DiscoveredModel] | Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Convert selected model metadata into the trusted config schema."""
    from khaos.routing.provider import (
        DEFAULT_MAX_OUTPUT_TOKENS,
        provider_default_max_output_tokens,
    )

    if models is None:
        entry = {
            "name": PROVIDER_DEFAULTS[provider_name]["model"],
            "max_context_tokens": 128000,
        }
        default_output_tokens = provider_default_max_output_tokens(provider_name)
        if default_output_tokens != DEFAULT_MAX_OUTPUT_TOKENS:
            entry["max_output_tokens"] = default_output_tokens
        return [entry]

    from khaos.routing.provider import DiscoveredModel

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model in models:
        if isinstance(model, DiscoveredModel):
            if model.provider != provider_name:
                raise ConfigError("discovered model belongs to another provider")
            model_name = model.model
            max_context_tokens = model.max_context_tokens
            max_output_tokens = None
            supports_tools = model.supports_tools
        elif isinstance(model, Mapping):
            model_name = model.get("name", model.get("model"))
            max_context_tokens = model.get("max_context_tokens")
            max_output_tokens = model.get("max_output_tokens")
            supports_tools = model.get("supports_tools")
        else:
            model_name = model
            max_context_tokens = None
            max_output_tokens = None
            supports_tools = None

        normalized_name = _validated_model_name(model_name)
        if normalized_name is None:
            raise ConfigError("model identifier is invalid")
        if normalized_name in seen:
            raise ConfigError("model selection contains duplicates")
        seen.add(normalized_name)
        entry: dict[str, Any] = {"name": normalized_name}
        if (
            isinstance(max_context_tokens, int)
            and not isinstance(max_context_tokens, bool)
            and 0 < max_context_tokens <= 1_000_000_000
        ):
            entry["max_context_tokens"] = max_context_tokens
        if (
            isinstance(max_output_tokens, int)
            and not isinstance(max_output_tokens, bool)
            and 0 < max_output_tokens <= 1_000_000_000
        ):
            entry["max_output_tokens"] = max_output_tokens
        elif (
            provider_default_max_output_tokens(provider_name)
            != DEFAULT_MAX_OUTPUT_TOKENS
        ):
            entry["max_output_tokens"] = provider_default_max_output_tokens(provider_name)
        if isinstance(supports_tools, bool):
            entry["supports_tools"] = supports_tools
        entries.append(entry)

    if not entries:
        raise ConfigError("at least one model must be selected")
    return entries


def _validated_model_name(value: Any) -> str | None:
    """Validate a provider-returned model identifier before config storage."""
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 256:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        return None
    return name


def set_user_config_value(key: str, value: str, path: str | Path | None = None) -> Path:
    """Set one non-secret user config value.

    Provider secrets are intentionally not accepted here.  Use the hidden
    ``config credentials set`` flow, which writes to the platform store and
    publishes only a ``credential_ref``.
    """
    key_parts = [part.casefold() for part in key.replace("[", ".").split(".") if part]
    if any(part in _PROVIDER_SECRET_FIELDS for part in key_parts):
        raise ConfigError(
            "secret configuration fields cannot be set with config set; "
            "use config credentials set"
        )
    if isinstance(value, SecretValue):
        raise ConfigError("SecretValue cannot be written to configuration")
    target = Path(path).expanduser() if path is not None else user_config_path()
    config = _read_yaml_file(target) if target.exists() else {}
    _reject_plaintext_provider_credentials(config, source=str(target))
    set_nested_value(config, key, value)
    _reject_plaintext_provider_credentials(config, source=str(target))
    _write_yaml_file(target, config)
    return target


def reset_user_config(path: str | Path | None = None) -> bool:
    """Delete the user config file if it exists."""
    target = Path(path).expanduser() if path is not None else user_config_path()
    if not target.exists():
        return False
    target.unlink()
    return True


def masked_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy with legacy secret fields fully redacted.

    Kept only for compatibility with older callers.  New CLI paths use the
    structured provider doctor and never serialize an arbitrary config tree.
    """
    data = copy.deepcopy(config)
    _mask_api_keys(data)
    return data


def provider_diagnostics(path: str | Path | None = None) -> dict[str, Any]:
    """Return bounded provider metadata suitable for human/JSON diagnostics.

    This function intentionally does not return the parsed config tree.  Legacy
    secret fields are represented only by a boolean blocked state, and the
    platform store is queried through the canonical CredentialBroker.
    """
    target = Path(path).expanduser() if path is not None else user_config_path()
    diagnostics: dict[str, Any] = {
        "config_path": str(target),
        "config_permissions": _config_permissions(target),
        "providers": [],
    }
    if not target.exists():
        diagnostics["config_status"] = "MISSING"
        return diagnostics
    try:
        raw_config = _read_yaml_file(target)
    except ConfigError:
        diagnostics["config_status"] = "INVALID"
        return diagnostics
    diagnostics["config_status"] = "OK"
    models = raw_config.get("models") if isinstance(raw_config, dict) else None
    providers = models.get("providers") if isinstance(models, dict) else None
    if not isinstance(providers, dict):
        return diagnostics

    broker = CredentialBroker()
    store = build_platform_credential_store()
    try:
        for provider_name, provider_data in sorted(providers.items(), key=lambda item: str(item[0])):
            if not isinstance(provider_name, str) or not isinstance(provider_data, dict):
                continue
            legacy = any(
                isinstance(key, str) and key.casefold() in _PROVIDER_SECRET_FIELDS
                for key in provider_data
            )
            ref: CredentialRef | None = None
            ref_error = False
            if not legacy and "credential_ref" in provider_data:
                try:
                    ref = CredentialRef.from_config(
                        provider_name, provider_data.get("credential_ref")
                    )
                    broker.register_credential_store(ref, store, provider=provider_name)
                except (CredentialBrokerError, TypeError, ValueError):
                    ref_error = True
            if ref is not None and not ref_error:
                status = broker.provider_credential_status(ref, provider=provider_name)
                credential_present = status["credential_present"]
                credential_source = status["backend"]
                credential_status = status["status"]
                backend_audit = credential_store_backend_audit(store)
            elif legacy:
                credential_present = None
                credential_source = "plaintext-config-blocked"
                credential_status = "LEGACY_PLAINTEXT_BLOCKED"
                backend_audit = None
            else:
                credential_present = False
                credential_source = "unconfigured"
                credential_status = "MISSING" if not ref_error else "INVALID_REF"
                backend_audit = None
            model_names = []
            model_entries = provider_data.get("models", [])
            if isinstance(model_entries, list):
                for entry in model_entries:
                    candidate = entry.get("name") if isinstance(entry, dict) else entry
                    model_name = _validated_model_name(candidate)
                    if model_name is not None:
                        model_names.append(model_name)
            safe_provider = {
                "provider": provider_name,
                "type": _safe_metadata_text(provider_data.get("type"), 64),
                "endpoint_profile": _safe_endpoint_profile_for_diagnostics(
                    provider_data.get("base_url")
                ),
                "models": sorted(set(model_names)),
                "credential_ref": ref.value if ref is not None else None,
                "credential_present": credential_present,
                "credential_source": credential_source,
                "credential_status": credential_status,
                "credential_backend_audit": backend_audit,
                "config_permissions": diagnostics["config_permissions"],
                "legacy_plaintext_detected": legacy,
            }
            safe_provider["provider_config_digest"] = provider_config_digest(
                {
                    "provider": provider_name,
                    "type": safe_provider["type"],
                    "base_url": safe_provider["endpoint_profile"],
                    "credential_ref": safe_provider["credential_ref"],
                    "models": safe_provider["models"],
                }
            )
            diagnostics["providers"].append(safe_provider)
    finally:
        broker.close()
    return diagnostics


def _safe_metadata_text(value: object, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_length:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    return value


def _safe_endpoint_profile_for_diagnostics(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "invalid"
    if parsed.scheme not in {"http", "https", "mock"} or not hostname:
        return "invalid"
    suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{hostname.casefold()}{suffix}{parsed.path.rstrip('/')}"[:256]


def _config_permissions(path: Path) -> str:
    """Check owner-only config and parent modes without following symlinks."""
    if os.name != "posix":
        return "NOT_AVAILABLE"
    try:
        file_info = os.lstat(path)
        parent_info = os.stat(path.parent, follow_symlinks=False)
    except OSError:
        return "MISSING"
    if (
        not stat.S_ISREG(file_info.st_mode)
        or file_info.st_uid != os.getuid()
        or stat.S_IMODE(file_info.st_mode) != 0o600
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        return "FAIL"
    return "PASS"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two config mappings, returning a new mapping."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def set_nested_value(config: dict[str, Any], dotted_key: str, value: Any) -> None:
    """Set a dotted key in a nested mapping."""
    parts = [part for part in dotted_key.split(".") if part]
    if not parts:
        raise ConfigError("Config key cannot be empty")
    cursor = config
    for part in parts[:-1]:
        next_value = cursor.setdefault(part, {})
        if not isinstance(next_value, dict):
            raise ConfigError(f"Cannot set {dotted_key}: {part} is not a mapping")
        cursor = next_value
    cursor[parts[-1]] = value


def user_config_path() -> Path:
    """Return the current user's config path."""
    return _user_config_path()


def config_for_models(config: dict[str, Any], model_names: set[str]) -> dict[str, Any]:
    """Return a copy containing only providers needed for the given models.

    This lets a single-router config keep optional providers with unresolved
    API-key placeholders while still resolving and validating the active model.
    """
    if not model_names:
        return copy.deepcopy(config)

    models_config = copy.deepcopy(config.get("models"))
    if not isinstance(models_config, dict):
        return {}
    result: dict[str, Any] = {"models": models_config}

    providers = models_config.get("providers")
    if isinstance(providers, dict):
        filtered: dict[str, Any] = {}
        for provider_name, provider_data in providers.items():
            provider_models = provider_data.get("models", []) if isinstance(provider_data, dict) else []
            selected_models = [
                model
                for model in provider_models
                if isinstance(model, dict) and str(model.get("name", "")) in model_names
            ]
            if selected_models:
                next_provider = copy.deepcopy(provider_data)
                next_provider["models"] = selected_models
                filtered[provider_name] = next_provider
        models_config["providers"] = filtered
        return result

    result["models"] = {
        name: data
        for name, data in models_config.items()
        if name in model_names or name in {"default_model", "router", "moa"}
    }
    return result


def _read_yaml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Expected mapping at top level of {path}")
    return raw


def _write_yaml_file(path: Path, config: dict[str, Any]) -> None:
    parent_fd = _open_config_parent(path)
    temporary = f".khaos-config-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and (
            not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
        ):
            raise ConfigError("config target must be a single-link regular file")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        payload = yaml.safe_dump(
            config, allow_unicode=True, sort_keys=False
        ).encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(
            temporary, path.name,
            src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _open_config_parent(path: Path) -> int:
    """Open the config parent with an owner-only, no-follow authority.

    The normal user config lives directly under ``~/.khaos``.  Creating that
    directory with ``Path.mkdir`` inherited umask (commonly producing 0755),
    which later made the file-audit authority reject the same directory and
    silently fall back to database-only audit.  For the user path, create/open
    ``.khaos`` relative to a fixed home dirfd, verify ownership/type, and
    safely tighten an existing owner-held directory to 0700 via ``fchmod``.

    Explicit non-user paths remain supported for tests and deployments, but
    their final parent is still created owner-only and opened no-follow.
    """
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in getattr(os, "supports_dir_fd", ())
        or os.mkdir not in getattr(os, "supports_dir_fd", ())
    ):
        raise ConfigError(
            "secure config writes require POSIX dirfd/no-follow support"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    target = path.expanduser()
    canonical_user = user_config_path()
    if target == canonical_user:
        if (
            os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or not hasattr(os, "O_NOFOLLOW")
        ):
            raise ConfigError(
                "secure user config directory creation requires dirfd/no-follow support"
            )
        home = canonical_user.parent.parent
        home_fd = os.open(home, flags)
        try:
            try:
                os.mkdir(".khaos", 0o700, dir_fd=home_fd)
            except FileExistsError:
                pass
            parent_fd = os.open(".khaos", flags, dir_fd=home_fd)
        finally:
            os.close(home_fd)
        try:
            info = os.fstat(parent_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ConfigError("user config directory must be owner-held")
            if stat.S_IMODE(info.st_mode) != 0o700:
                os.fchmod(parent_fd, 0o700)
                tightened = os.fstat(parent_fd)
                if stat.S_IMODE(tightened.st_mode) != 0o700:
                    raise ConfigError("failed to secure user config directory")
            return parent_fd
        except BaseException:
            os.close(parent_fd)
            raise

    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_fd = os.open(target.parent, flags)
    info = os.fstat(parent_fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        os.close(parent_fd)
        raise ConfigError("config directory must be owner-held")
    return parent_fd


def _is_configured_secret(value: str) -> bool:
    return bool(value.strip()) and _ENV_PATTERN.search(value) is None


def _prompt_provider() -> str:
    aliases = {
        "": "nvidia",
        "1": "nvidia",
        "nvidia": "nvidia",
        "2": "anthropic",
        "anthropic": "anthropic",
        "claude": "anthropic",
        "3": "openai",
        "openai": "openai",
        "4": "zhipu",
        "zhipu": "zhipu",
        "zhipu-api": "zhipu",
        "api": "zhipu",
        "glm": "zhipu",
        "智谱": "zhipu",
        "5": "zhipu-coding",
        "zhipu-coding": "zhipu-coding",
        "coding": "zhipu-coding",
        "coding-plan": "zhipu-coding",
        "glm-coding": "zhipu-coding",
        "6": "siliconflow",
        "siliconflow": "siliconflow",
        "silicon-flow": "siliconflow",
        "sf": "siliconflow",
        "硅基流动": "siliconflow",
        "硅基": "siliconflow",
    }
    while True:
        raw = input("选择 provider [1]: ").strip().lower()
        provider = aliases.get(raw)
        if provider:
            return provider
        print(
            "请输入 1/nvidia、2/anthropic、3/openai、4/zhipu、"
            "5/zhipu-coding 或 6/siliconflow。"
        )


def _prompt_api_key(provider: str) -> str:
    while True:
        value = getpass.getpass(f"输入 {PROVIDER_DEFAULTS[provider]['label']} API Key: ").strip()
        if len(value) > 10:
            return value
        print("API Key 不能为空，且长度需要大于 10。")


def _normalize_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized not in PROVIDER_DEFAULTS:
        raise ConfigError(f"Unsupported provider: {provider}")
    return normalized


def _mask_api_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                isinstance(key, str)
                and key.casefold() in _PROVIDER_SECRET_FIELDS
                and isinstance(item, str)
            ):
                value[key] = "[REDACTED]"
            else:
                _mask_api_keys(item)
    elif isinstance(value, list):
        for item in value:
            _mask_api_keys(item)


def _mask_secret(value: str) -> str:
    """Return a constant marker without revealing a secret prefix/suffix."""

    return "[REDACTED]" if isinstance(value, str) and value else ""
