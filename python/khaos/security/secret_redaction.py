"""Process-local exact-value secret redaction.

Pattern scanners are useful defense in depth but cannot recognize every
provider token shape.  ``SecretRedactor`` keeps exact values only in memory,
never logs or serializes them, and is used at model-visible/durable output
boundaries.  It is intentionally not a credential store or an authorization
authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from khaos.security.credentials import _TRANSPORT_CAPABILITY, SecretValue

_BEARER_HEADER = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"
)
_MAX_REDACTION_BYTES = 2 * 1024 * 1024
_MAX_REDACTION_DEPTH = 32
_MAX_REDACTION_ITEMS = 256
_REDACTED_SECRET = "[REDACTED_SECRET]"
_REDACTED_UNSUPPORTED = "[REDACTED_UNSUPPORTED_OUTPUT]"


class SecretRedactor:
    """Redact registered provider values from bounded output structures."""

    def __init__(self) -> None:
        self._values: list[str] = []

    def register(self, secret: SecretValue) -> None:
        """Register one transient SecretValue without accepting plain strings."""
        if not isinstance(secret, SecretValue):
            raise TypeError("secret redactor accepts SecretValue only")
        value = secret._reveal_for_transport(_TRANSPORT_CAPABILITY)
        if value and value not in self._values:
            self._values.append(value)

    def redact_text(self, value: str) -> str:
        """Redact exact values and credential-bearing Authorization headers."""
        if not isinstance(value, str):
            return "[REDACTED_INVALID_OUTPUT]"
        if len(value.encode("utf-8", errors="replace")) > _MAX_REDACTION_BYTES:
            return "[REDACTED_OUTPUT_TOO_LARGE]"
        result = _BEARER_HEADER.sub(r"\1[REDACTED]", value)
        for secret in sorted(self._values, key=len, reverse=True):
            result = result.replace(secret, _REDACTED_SECRET)
        return result

    def redact(self, value: Any) -> Any:
        """Recursively redact JSON-like values and reject unknown objects."""
        return self._redact(value, depth=0, active=set())

    def redact_fail_closed(self, value: Any) -> Any:
        """Sanitize output, returning a safe marker if traversal fails."""
        try:
            return self.redact(value)
        except Exception:  # noqa: BLE001 - redaction must fail closed
            return _REDACTED_UNSUPPORTED

    def _redact(self, value: Any, *, depth: int, active: set[int]) -> Any:
        if depth > _MAX_REDACTION_DEPTH:
            return _REDACTED_UNSUPPORTED
        if isinstance(value, str):
            return self.redact_text(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in active:
                return _REDACTED_UNSUPPORTED
            active.add(identity)
            sanitized: dict[str, Any] = {}
            try:
                for index, (key, item) in enumerate(value.items()):
                    if index >= _MAX_REDACTION_ITEMS:
                        sanitized["[REDACTED_TRUNCATED_KEYS]"] = True
                        break
                    safe_key = (
                        self.redact_text(key)
                        if isinstance(key, str)
                        else "[REDACTED_NON_STRING_KEY]"
                    )
                    sanitized[safe_key] = self._redact(
                        item, depth=depth + 1, active=active
                    )
            except Exception:  # noqa: BLE001 - hostile mappings must fail closed
                return _REDACTED_UNSUPPORTED
            finally:
                active.discard(identity)
            return sanitized
        if isinstance(value, list):
            return self._redact_sequence(value, depth=depth, active=active)
        if isinstance(value, tuple):
            return tuple(self._redact_sequence(value, depth=depth, active=active))
        return _REDACTED_UNSUPPORTED

    def _redact_sequence(
        self, value: list[Any] | tuple[Any, ...], *, depth: int, active: set[int]
    ) -> list[Any]:
        identity = id(value)
        if identity in active:
            return [_REDACTED_UNSUPPORTED]
        active.add(identity)
        try:
            result = [
                self._redact(item, depth=depth + 1, active=active)
                for item in value[:_MAX_REDACTION_ITEMS]
            ]
            if len(value) > _MAX_REDACTION_ITEMS:
                result.append("[REDACTED_TRUNCATED_ITEMS]")
            return result
        except Exception:  # noqa: BLE001 - hostile sequences must fail closed
            return [_REDACTED_UNSUPPORTED]
        finally:
            active.discard(identity)

    def safe_error(self, error: BaseException) -> str:
        """Return a bounded redacted exception category/message."""
        try:
            message = self.redact_text(str(error))
        except Exception:  # noqa: BLE001 - hostile exception text must fail closed
            return type(error).__name__[:128]
        if not message:
            return type(error).__name__
        return message[:512]

    def contains_registered_secret(self, value: str) -> bool:
        """Check a value for testing/audit assertions without returning a secret."""
        return any(secret in value for secret in self._values)

    def clear(self) -> None:
        """Drop all process-local exact values at broker shutdown."""
        self._values.clear()

    def __repr__(self) -> str:
        return f"SecretRedactor(registered={len(self._values)})"


__all__ = ["SecretRedactor"]
