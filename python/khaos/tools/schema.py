"""Closed JSON Schema subset enforced for model-supplied tool arguments."""

from __future__ import annotations

import copy
import re
from typing import Any


_ANNOTATION_KEYWORDS = frozenset({"description", "default", "title"})
_KEYWORDS_BY_TYPE: dict[str, frozenset[str]] = {
    "object": frozenset(
        {"type", "properties", "required", "additionalProperties", "maxProperties"}
    ),
    "array": frozenset({"type", "items", "minItems", "maxItems"}),
    "string": frozenset({"type", "minLength", "maxLength", "pattern", "enum"}),
    "integer": frozenset({"type", "minimum", "maximum", "enum"}),
    "number": frozenset({"type", "minimum", "maximum", "enum"}),
    "boolean": frozenset({"type", "enum"}),
}


def production_schema(
    schema: dict[str, Any], *, property_name: str = ""
) -> dict[str, Any]:
    """Return a bounded, closed model-visible JSON Schema."""
    normalized = copy.deepcopy(schema)
    expected = normalized.get("type")
    if expected == "object":
        normalized.setdefault("additionalProperties", False)
        normalized.setdefault("maxProperties", 64)
        normalized["properties"] = {
            key: production_schema(value, property_name=key)
            for key, value in normalized.get("properties", {}).items()
        }
        for key in normalized.get("required", []):
            child = normalized["properties"].get(key)
            if child is None:
                continue
            if child.get("type") == "string":
                child["minLength"] = max(1, int(child.get("minLength", 0)))
            elif child.get("type") == "array":
                child["minItems"] = max(1, int(child.get("minItems", 0)))
    elif expected == "array":
        normalized.setdefault("minItems", 0)
        normalized.setdefault("maxItems", 256 if property_name == "argv" else 1024)
        if isinstance(normalized.get("items"), dict):
            normalized["items"] = production_schema(
                normalized["items"], property_name=property_name
            )
    elif expected == "string":
        normalized.setdefault("minLength", 0)
        if property_name in {"path", "root", "cwd", "source", "destination"}:
            normalized.setdefault("maxLength", 4096)
        elif property_name == "url":
            normalized.setdefault("maxLength", 8192)
        elif property_name in {"id", "task_id", "session_id", "runtime_id"}:
            normalized.setdefault("maxLength", 256)
        elif property_name in {"content", "text", "script", "prompt"}:
            normalized.setdefault("maxLength", 1_048_576)
        else:
            normalized.setdefault("maxLength", 65_536)
    elif expected == "integer":
        normalized.setdefault("minimum", 0)
        normalized.setdefault("maximum", 86_400)
    elif expected == "number":
        normalized.setdefault("minimum", 0)
        normalized.setdefault("maximum", 1_000_000)
    return normalized


def validate_schema_definition(schema: Any, *, path: str) -> None:
    """Reject schemas outside the exact subset enforced at dispatch time."""
    if not isinstance(schema, dict):
        raise ValueError(f"{path}: schema must be an object")
    expected = schema.get("type")
    if expected not in _KEYWORDS_BY_TYPE:
        raise ValueError(f"{path}: unsupported or missing schema type: {expected!r}")
    allowed = _KEYWORDS_BY_TYPE[expected] | _ANNOTATION_KEYWORDS
    unsupported = sorted(set(schema) - allowed)
    if unsupported:
        raise ValueError(
            f"{path}: unsupported JSON Schema keywords: {', '.join(unsupported)}"
        )
    if "enum" in schema:
        enum_values = schema["enum"]
        if not isinstance(enum_values, list) or not enum_values:
            raise ValueError(f"{path}.enum: must be a non-empty array")
        if any(not _value_matches_type(expected, item) for item in enum_values):
            raise ValueError(f"{path}.enum: values must match type {expected}")
    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", False)
        if not isinstance(properties, dict) or any(
            not isinstance(name, str) for name in properties
        ):
            raise ValueError(f"{path}.properties: must be an object with string keys")
        if (
            not isinstance(required, list)
            or any(not isinstance(name, str) for name in required)
            or len(required) != len(set(required))
        ):
            raise ValueError(f"{path}.required: must contain unique string names")
        missing = sorted(set(required) - set(properties))
        if missing:
            raise ValueError(
                f"{path}.required: unknown properties: {', '.join(missing)}"
            )
        if not isinstance(additional, bool):
            raise ValueError(f"{path}.additionalProperties: must be boolean")
        for name, child in properties.items():
            validate_schema_definition(child, path=f"{path}.properties.{name}")
    elif expected == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            raise ValueError(f"{path}.items: a typed item schema is required")
        validate_schema_definition(items, path=f"{path}.items")


def _value_matches_type(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return False


def validate_json_schema(schema: dict[str, Any], value: Any) -> bool:
    """Validate the production subset used by Khaos tool contracts."""
    if "enum" in schema and value not in schema["enum"]:
        return False
    expected = schema.get("type")
    if expected == "string":
        if not isinstance(value, str):
            return False
        if len(value) < int(schema.get("minLength", 0)):
            return False
        if len(value) > int(schema.get("maxLength", 2**31 - 1)):
            return False
        pattern = schema.get("pattern")
        return pattern is None or re.fullmatch(str(pattern), value) is not None
    if expected == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= schema.get("minimum", value)
            and value <= schema.get("maximum", value)
        )
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= schema.get("minimum", value)
            and value <= schema.get("maximum", value)
        )
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        if not isinstance(value, dict):
            return False
        required = schema.get("required", [])
        if any(key not in value for key in required):
            return False
        if len(value) > int(schema.get("maxProperties", 2**31 - 1)):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(
            key not in properties for key in value
        ):
            return False
        return all(
            key not in properties or validate_json_schema(properties[key], item)
            for key, item in value.items()
        )
    if expected == "array":
        if not isinstance(value, list):
            return False
        if len(value) < int(schema.get("minItems", 0)):
            return False
        if len(value) > int(schema.get("maxItems", 2**31 - 1)):
            return False
        items = schema.get("items")
        return items is None or all(validate_json_schema(items, item) for item in value)
    return expected is None
