"""Configuration loading and environment placeholder expansion."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import yaml

from khaos.exceptions import KhaosError


class ConfigError(KhaosError):
    """Raised when config.yaml cannot be resolved safely."""


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


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


def load_config(path: str | Path, *, strict_env: bool = True) -> dict[str, Any]:
    """Read YAML config and expand supported environment placeholders."""
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Expected mapping at top level of {config_path}")
    return expand_config_placeholders(raw, source=str(config_path), strict=strict_env)


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
