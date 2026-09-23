"""Bounded JSON-schema subset for extension supplied schemas and arguments."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import re2

from khaos.security.protocol_boundary import canonical_json_bytes

MAX_SCHEMA_BYTES = 64 * 1024
MAX_SCHEMA_DEPTH = 16
MAX_SCHEMA_NODES = 512
MAX_SCHEMA_PROPERTIES = 128
MAX_SCHEMA_ENUM_VALUES = 128
MAX_SCHEMA_STRING_BYTES = 4096
MAX_ARGUMENT_DEPTH = 16
MAX_ARGUMENT_NODES = 1024

_SCHEMA_KEYS = {
    "type",
    "properties",
    "maxProperties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "pattern",
    "enum",
    "description",
    "title",
    "default",
}
_SCHEMA_TYPES = {"object", "array", "string", "integer", "number", "boolean"}


class ExtensionSchemaError(ValueError):
    """Raised when a schema or argument exceeds the supported subset."""


def _ensure_scalar(value: object, path: str) -> None:
    if value is None or type(value) in {str, int, float, bool}:
        return
    raise ExtensionSchemaError(f"{path} contains a non-JSON scalar")


def validate_external_schema(schema: Mapping[str, object], *, path: str = "schema") -> None:
    """Validate one closed, bounded schema without recursive backtracking regex."""
    if not isinstance(schema, Mapping):
        raise ExtensionSchemaError(f"{path} must be an object")
    try:
        encoded = canonical_json_bytes(dict(schema))
    except Exception as exc:
        raise ExtensionSchemaError(f"{path} is not JSON-safe") from exc
    if len(encoded) > MAX_SCHEMA_BYTES:
        raise ExtensionSchemaError(f"{path} exceeds {MAX_SCHEMA_BYTES} bytes")
    nodes = [0]

    def visit(node: object, current_path: str, depth: int) -> None:
        nodes[0] += 1
        if nodes[0] > MAX_SCHEMA_NODES:
            raise ExtensionSchemaError("schema node budget exceeded")
        if depth > MAX_SCHEMA_DEPTH:
            raise ExtensionSchemaError(f"{current_path} exceeds schema depth")
        if not isinstance(node, Mapping):
            raise ExtensionSchemaError(f"{current_path} must be an object")
        unknown = set(node) - _SCHEMA_KEYS
        if unknown:
            raise ExtensionSchemaError(f"{current_path} contains unsupported keywords")
        expected = node.get("type")
        if expected not in _SCHEMA_TYPES:
            raise ExtensionSchemaError(f"{current_path}.type is unsupported")
        description = node.get("description", node.get("title", ""))
        if description and (type(description) is not str or len(description.encode("utf-8")) > MAX_SCHEMA_STRING_BYTES):
            raise ExtensionSchemaError(f"{current_path} annotation is too large")
        if "default" in node:
            _ensure_scalar_or_container(node["default"], f"{current_path}.default", depth + 1, nodes)
        if "enum" in node:
            values = node["enum"]
            if not isinstance(values, list) or not values or len(values) > MAX_SCHEMA_ENUM_VALUES:
                raise ExtensionSchemaError(f"{current_path}.enum is invalid")
            for index, value in enumerate(values):
                _ensure_scalar_or_container(value, f"{current_path}.enum[{index}]", depth + 1, nodes)
        if expected == "object":
            properties = node.get("properties", {})
            required = node.get("required", [])
            if not isinstance(properties, Mapping) or len(properties) > MAX_SCHEMA_PROPERTIES:
                raise ExtensionSchemaError(f"{current_path}.properties is invalid")
            if (
                not isinstance(required, list)
                or len(required) > MAX_SCHEMA_PROPERTIES
                or any(type(name) is not str for name in required)
                or len(required) != len(set(required))
            ):
                raise ExtensionSchemaError(f"{current_path}.required is invalid")
            _bounded_integer(node, "maxProperties", current_path)
            if any(type(name) is not str or not name or len(name.encode("utf-8")) > 256 for name in properties):
                raise ExtensionSchemaError(f"{current_path}.properties has an invalid name")
            if "maxProperties" in node and len(properties) > node["maxProperties"]:
                raise ExtensionSchemaError(f"{current_path}.properties exceeds maxProperties")
            if any(type(name) is not str or name not in properties for name in required):
                raise ExtensionSchemaError(f"{current_path}.required references an unknown property")
            additional = node.get("additionalProperties", False)
            if type(additional) is not bool:
                raise ExtensionSchemaError(f"{current_path}.additionalProperties must be boolean")
            for name, child in properties.items():
                visit(child, f"{current_path}.properties.{name}", depth + 1)
        elif expected == "array":
            items = node.get("items")
            if not isinstance(items, Mapping):
                raise ExtensionSchemaError(f"{current_path}.items is required")
            _bounded_integer(node, "minItems", current_path)
            _bounded_integer(node, "maxItems", current_path)
            visit(items, f"{current_path}.items", depth + 1)
        elif expected == "string":
            _bounded_integer(node, "minLength", current_path)
            _bounded_integer(node, "maxLength", current_path)
            pattern = node.get("pattern")
            if pattern is not None:
                if type(pattern) is not str or len(pattern.encode("utf-8")) > MAX_SCHEMA_STRING_BYTES:
                    raise ExtensionSchemaError(f"{current_path}.pattern is invalid")
                try:
                    re2.compile(pattern)
                except (re2.error, ValueError) as exc:
                    raise ExtensionSchemaError(f"{current_path}.pattern is not RE2-compatible") from exc
        elif expected in {"integer", "number"}:
            for keyword in ("minimum", "maximum"):
                if keyword in node and (isinstance(node[keyword], bool) or not isinstance(node[keyword], (int, float))):
                    raise ExtensionSchemaError(f"{current_path}.{keyword} is invalid")

    visit(schema, path, 0)


def _bounded_integer(node: Mapping[str, object], key: str, path: str) -> None:
    value = node.get(key)
    if value is not None and (type(value) is not int or value < 0 or value > 1_000_000):
        raise ExtensionSchemaError(f"{path}.{key} is invalid")


def _ensure_scalar_or_container(value: object, path: str, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_SCHEMA_NODES:
        raise ExtensionSchemaError("schema node budget exceeded")
    if depth > MAX_SCHEMA_DEPTH:
        raise ExtensionSchemaError(f"{path} exceeds schema depth")
    if value is None or type(value) in {str, int, float, bool}:
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _ensure_scalar_or_container(child, f"{path}[{index}]", depth + 1, nodes)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_SCHEMA_PROPERTIES:
            raise ExtensionSchemaError(f"{path} has too many properties")
        for key, child in value.items():
            if type(key) is not str:
                raise ExtensionSchemaError(f"{path} has a non-text key")
            _ensure_scalar_or_container(child, f"{path}.{key}", depth + 1, nodes)
        return
    raise ExtensionSchemaError(f"{path} is not JSON-safe")


def validate_arguments(schema: Mapping[str, object], value: object) -> bool:
    """Validate arguments with bounded recursion and linear-time patterns."""
    validate_external_schema(schema)
    nodes = [0]

    def visit(node: Mapping[str, object], candidate: object, depth: int) -> bool:
        nodes[0] += 1
        if nodes[0] > MAX_ARGUMENT_NODES or depth > MAX_ARGUMENT_DEPTH:
            return False
        expected = node.get("type")
        enum_values = node.get("enum")
        if isinstance(enum_values, list) and candidate not in enum_values:
            return False
        if expected == "object":
            if not isinstance(candidate, dict):
                return False
            properties = cast(Mapping[str, Mapping[str, object]], node.get("properties", {}))
            required = cast(list[str], node.get("required", []))
            if any(name not in candidate for name in required):
                return False
            max_properties = node.get("maxProperties", MAX_SCHEMA_PROPERTIES)
            if type(max_properties) is not int:
                return False
            if len(candidate) > max_properties:
                return False
            if node.get("additionalProperties", False) is False and any(name not in properties for name in candidate):
                return False
            return all(name not in properties or visit(properties[name], child, depth + 1) for name, child in candidate.items())
        if expected == "array":
            if not isinstance(candidate, list):
                return False
            min_items = node.get("minItems", 0)
            max_items = node.get("maxItems", 1_000_000)
            if type(min_items) is not int or type(max_items) is not int:
                return False
            if len(candidate) < min_items or len(candidate) > max_items:
                return False
            items = node.get("items")
            return isinstance(items, Mapping) and all(
                visit(cast(Mapping[str, object], items), child, depth + 1)
                for child in candidate
            )
        if expected == "string":
            if not isinstance(candidate, str):
                return False
            min_length = node.get("minLength", 0)
            max_length = node.get("maxLength", 1_000_000)
            if type(min_length) is not int or type(max_length) is not int:
                return False
            if len(candidate) < min_length or len(candidate) > max_length:
                return False
            pattern = node.get("pattern")
            if pattern is not None:
                try:
                    return re2.fullmatch(str(pattern), candidate) is not None
                except (re2.error, ValueError):
                    return False
            return True
        if expected == "integer":
            if type(candidate) is not int:
                return False
            candidate_int = cast(int, candidate)
            minimum = _numeric_bound(node.get("minimum"), candidate_int)
            maximum = _numeric_bound(node.get("maximum"), candidate_int)
            return candidate_int >= minimum and candidate_int <= maximum
        if expected == "number":
            if not isinstance(candidate, (int, float)) or isinstance(candidate, bool):
                return False
            minimum = _numeric_bound(node.get("minimum"), candidate)
            maximum = _numeric_bound(node.get("maximum"), candidate)
            return candidate >= minimum and candidate <= maximum
        if expected == "boolean":
            return type(candidate) is bool
        return False

    return isinstance(schema, Mapping) and visit(schema, value, 0)


def _numeric_bound(value: object, fallback: float) -> int | float:
    """Return a validated numeric schema bound or the candidate fallback."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return fallback


__all__ = [
    "MAX_ARGUMENT_DEPTH",
    "MAX_ARGUMENT_NODES",
    "MAX_SCHEMA_BYTES",
    "MAX_SCHEMA_DEPTH",
    "MAX_SCHEMA_NODES",
    "ExtensionSchemaError",
    "validate_arguments",
    "validate_external_schema",
]
