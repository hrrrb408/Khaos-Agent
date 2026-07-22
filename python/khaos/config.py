"""Configuration loading and environment placeholder expansion."""

from __future__ import annotations

import copy
import getpass
import logging
import os
import re
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from collections.abc import Iterator
from typing import Any

import yaml

from khaos.exceptions import KhaosError

logger = logging.getLogger(__name__)


class ConfigError(KhaosError):
    """Raised when config.yaml cannot be resolved safely."""


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
USER_CONFIG_PATH = Path("~/.khaos/config.yaml")
PROJECT_CONFIG_PATH = Path("config.yaml")


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
}
_PROVIDER_ENV_KEYS = {
    "nvidia": "NVIDIA_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}


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
    """Read config and expand supported environment placeholders.

    With no explicit path, the project template is loaded first and
    ``~/.khaos/config.yaml`` is merged on top so user config wins.
    """
    if path is not None:
        config_path = Path(path).expanduser()
        raw = _read_yaml_file(config_path)
        expanded = expand_config_placeholders(raw, source=str(config_path), strict=strict_env)
        return EffectiveConfig(
            expanded,
            _field_provenance(
                expanded, ConfigAuthority.RUNTIME_OVERRIDE, str(config_path)
            ),
        )

    project_path = Path(project_path or PROJECT_CONFIG_PATH).expanduser().resolve()
    user_path = user_config_path()
    project = _read_yaml_file(project_path) if project_path.exists() else {}
    _validate_project_config(project, source=str(project_path))
    user = _read_yaml_file(user_path) if user_path.exists() else {}

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
    """Build fixed-endpoint providers from explicitly named host secrets."""
    providers: dict[str, Any] = {}
    for provider_name, env_name in _PROVIDER_ENV_KEYS.items():
        api_key = os.environ.get(env_name, "").strip()
        if not api_key:
            continue
        defaults = PROVIDER_DEFAULTS[provider_name]
        providers[provider_name] = {
            "type": defaults["type"],
            "base_url": defaults["base_url"],
            "api_key": api_key,
            "models": [
                {
                    "name": defaults["model"],
                    "max_context_tokens": 128000,
                }
            ],
        }
    return {"models": {"providers": providers}} if providers else {}


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
                "trusted-only and must be moved to ~/.khaos/config.yaml"
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


def check_needs_setup(config: dict[str, Any] | None = None) -> bool:
    """Return True when no configured provider has a usable API key."""
    data = config if config is not None else load_config(strict_env=False)
    providers = ((data.get("models") or {}).get("providers") or {})
    if not isinstance(providers, dict) or not providers:
        return True
    for provider_data in providers.values():
        if not isinstance(provider_data, dict):
            continue
        api_key = str(provider_data.get("api_key", "") or "")
        if _is_configured_secret(api_key):
            return False
    return True


def run_setup_wizard(config_path: str | Path | None = None) -> Path:
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
    provider = _prompt_provider()
    api_key = _prompt_api_key(provider)
    write_provider_config(provider, api_key, target)
    print(f"✓ 已保存到 {target}")
    return target


def write_provider_config(provider: str, api_key: str, path: str | Path | None = None) -> Path:
    """Write the selected provider API key to the user config file."""
    provider_name = _normalize_provider(provider)
    target = Path(path).expanduser() if path is not None else user_config_path()
    defaults = PROVIDER_DEFAULTS[provider_name]
    config = _read_yaml_file(target) if target.exists() else {}
    set_nested_value(config, f"models.providers.{provider_name}.type", defaults["type"])
    set_nested_value(config, f"models.providers.{provider_name}.base_url", defaults["base_url"])
    set_nested_value(config, f"models.providers.{provider_name}.api_key", api_key)
    set_nested_value(
        config,
        f"models.providers.{provider_name}.models",
        [{"name": defaults["model"], "max_context_tokens": 128000}],
    )
    set_nested_value(config, "models.default_model", defaults["model"])
    _write_yaml_file(target, config)
    return target


def set_user_config_value(key: str, value: str, path: str | Path | None = None) -> Path:
    """Set a dotted config key in the user config file."""
    target = Path(path).expanduser() if path is not None else user_config_path()
    config = _read_yaml_file(target) if target.exists() else {}
    set_nested_value(config, key, value)
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
    """Return a deep copy with API keys masked for display."""
    data = copy.deepcopy(config)
    _mask_api_keys(data)
    return data


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
    return USER_CONFIG_PATH.expanduser()


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
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
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
    }
    while True:
        raw = input("选择 provider [1]: ").strip().lower()
        provider = aliases.get(raw)
        if provider:
            return provider
        print("请输入 1/nvidia、2/anthropic 或 3/openai。")


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
            if key == "api_key" and isinstance(item, str):
                value[key] = _mask_secret(item)
            else:
                _mask_api_keys(item)
    elif isinstance(value, list):
        for item in value:
            _mask_api_keys(item)


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if _ENV_PATTERN.search(value):
        return value
    if len(value) <= 8:
        return "****"
    return f"{value[:6]}...{value[-3:]}"
