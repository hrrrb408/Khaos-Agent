"""Bounded, structured tool-output envelopes for model context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType

from khaos.coding.context_engine.contracts import approximate_token_count
from khaos.security.protocol_boundary import canonical_json_bytes

MIN_TOOL_ENVELOPE_BYTES = 264


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _utf8_prefix(value: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _approx_tokens(value: str) -> int:
    return approximate_token_count(value)


@dataclass(frozen=True, slots=True)
class ToolOutputLimits:
    """Hard output bounds; these are disclosure limits, not tool authority."""

    max_bytes: int = 64 * 1024
    max_tokens: int = 4_096
    max_lines: int = 512
    diagnostic_lines: int = 8

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value <= 0
            for value in (self.max_bytes, self.max_tokens, self.max_lines, self.diagnostic_lines)
        ):
            raise ValueError("tool output limits must be positive")
        if self.max_bytes < MIN_TOOL_ENVELOPE_BYTES:
            raise ValueError(
                f"tool output max_bytes must be at least {MIN_TOOL_ENVELOPE_BYTES}"
            )


@dataclass(frozen=True, slots=True)
class ToolOutputEnvelope:
    """A bounded projection that retains a digest of the complete result."""

    tool_name: str
    status: str
    summary: str
    important_fields: dict[str, object] = field(default_factory=dict)
    content: str = ""
    truncated: bool = False
    full_result_digest: str = ""
    first_diagnostics: tuple[str, ...] = ()
    last_diagnostics: tuple[str, ...] = ()
    output_bytes: int = 0
    output_tokens: int = 0

    def __post_init__(self) -> None:
        if type(self.tool_name) is not str or not self.tool_name or len(self.tool_name) > 256:
            raise ValueError("tool name is invalid")
        if self.status not in {"success", "failure", "unknown"}:
            raise ValueError("tool output status is invalid")
        if type(self.summary) is not str or len(self.summary.encode("utf-8")) > 2048:
            raise ValueError("tool output summary is invalid")
        if type(self.content) is not str:
            raise ValueError("tool output content is invalid")
        if len(self.content.encode("utf-8")) > 64 * 1024:
            raise ValueError("tool output content exceeds its bound")
        if type(self.truncated) is not bool:
            raise ValueError("tool output truncation flag is invalid")
        if self.full_result_digest and (
            len(self.full_result_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.full_result_digest)
        ):
            raise ValueError("tool output digest is invalid")
        if not isinstance(self.important_fields, dict) and not isinstance(
            self.important_fields, MappingProxyType
        ):
            raise TypeError("tool output important fields are invalid")
        if type(self.first_diagnostics) is not tuple or type(self.last_diagnostics) is not tuple:
            raise ValueError("tool output diagnostics are invalid")
        if len(self.first_diagnostics) > 8 or len(self.last_diagnostics) > 8:
            raise ValueError("tool output diagnostics exceed their bound")
        if any(
            type(value) is not str or len(value.encode("utf-8")) > 512
            for value in (*self.first_diagnostics, *self.last_diagnostics)
        ):
            raise ValueError("tool output diagnostic is invalid")
        for name in ("output_bytes", "output_tokens"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"tool output {name} is invalid")
        try:
            important_size = len(canonical_json_bytes(dict(self.important_fields)))
        except (TypeError, ValueError) as exc:
            raise TypeError("tool output important fields are not JSON-safe") from exc
        if important_size > 16 * 1024:
            raise ValueError("tool output important fields exceed their bound")
        object.__setattr__(
            self,
            "important_fields",
            MappingProxyType(dict(self.important_fields)),
        )

    @classmethod
    def from_result(
        cls,
        result: object,
        *,
        limits: ToolOutputLimits | None = None,
    ) -> ToolOutputEnvelope:
        limits = limits or ToolOutputLimits()
        tool_name = str(getattr(result, "name", "tool"))[:256] or "tool"
        success = getattr(result, "success", None)
        status = "success" if success is True else "failure" if success is False else "unknown"
        output = _text(getattr(result, "output", ""))
        error = _text(getattr(result, "error", ""))
        combined = output
        if error:
            combined = f"{combined}\nerror: {error}" if combined else f"error: {error}"
        raw_digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        important: dict[str, object] = {
            "success": success if isinstance(success, bool) else None,
            "error_code": _bounded_scalar(getattr(result, "error_code", None)),
            "effect_status": _bounded_scalar(getattr(result, "effect_status", None)),
            "delivery_status": _bounded_scalar(getattr(result, "delivery_status", None)),
            "warning": _bounded_scalar(getattr(result, "warning", None)),
            "effect_id": _bounded_scalar(getattr(result, "effect_id", None)),
            "phase_digest": _bounded_scalar(getattr(result, "phase_digest", None)),
            "retry_safe": getattr(result, "retry_safe", None)
            if isinstance(getattr(result, "retry_safe", None), bool)
            else None,
        }
        important = {key: value for key, value in important.items() if value not in (None, "")}
        lines = combined.splitlines()
        diagnostics = [
            line.strip()
            for line in lines
            if any(marker in line.casefold() for marker in ("error", "fail", "warning", "traceback", "exception"))
            and line.strip()
        ]
        first = tuple(_utf8_prefix(line, 512) for line in diagnostics[: limits.diagnostic_lines])
        last = tuple(_utf8_prefix(line, 512) for line in diagnostics[-limits.diagnostic_lines :])
        kept_lines = lines[: limits.max_lines]
        line_truncated = len(lines) > len(kept_lines)
        content = "\n".join(kept_lines)
        if _approx_tokens(content) > limits.max_tokens:
            content = " ".join(content.split()[: limits.max_tokens])
            line_truncated = True
        content = _utf8_prefix(content, limits.max_bytes)
        byte_truncated = len(content.encode("utf-8")) < len("\n".join(kept_lines).encode("utf-8"))
        truncated = line_truncated or byte_truncated or len(combined.encode("utf-8")) > len(content.encode("utf-8"))
        summary_source = next((line.strip() for line in lines if line.strip()), "")
        summary = _utf8_prefix(summary_source, 512)
        envelope = cls(
            tool_name=tool_name,
            status=status,
            summary=summary,
            important_fields=important,
            content=content,
            truncated=truncated,
            full_result_digest=raw_digest,
            first_diagnostics=first,
            last_diagnostics=last,
            output_bytes=len(combined.encode("utf-8")),
            output_tokens=_approx_tokens(combined),
        )
        return envelope._fit_to_bytes(limits.max_bytes)

    def to_payload(self) -> dict[str, object]:
        return {
            "tool": self.tool_name,
            "status": self.status,
            "summary": self.summary,
            "important_fields": dict(sorted(self.important_fields.items())),
            "content": self.content,
            "first_diagnostics": self.first_diagnostics,
            "last_diagnostics": self.last_diagnostics,
            "truncated": self.truncated,
            "full_result_digest": self.full_result_digest,
            "output_bytes": self.output_bytes,
            "output_tokens": self.output_tokens,
        }

    def to_json(self, *, max_bytes: int | None = None) -> str:
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("tool output max_bytes must be positive")
        if max_bytes is not None and max_bytes < MIN_TOOL_ENVELOPE_BYTES:
            raise ValueError(
                f"tool output max_bytes must be at least {MIN_TOOL_ENVELOPE_BYTES}"
            )
        payload = canonical_json_bytes(self.to_payload()).decode("utf-8")
        if max_bytes is None or len(payload.encode("utf-8")) <= max_bytes:
            return payload
        return self._fit_to_bytes(max_bytes).to_json(max_bytes=None)

    def _fit_to_bytes(self, max_bytes: int) -> ToolOutputEnvelope:
        if len(canonical_json_bytes(self.to_payload())) <= max_bytes:
            return self
        # Binary-search the content projection; the structural fields and
        # complete-result digest remain available even when content is gone.
        low = 0
        high = len(self.content.encode("utf-8"))
        best = self
        while low <= high:
            middle = (low + high) // 2
            candidate = ToolOutputEnvelope(
                tool_name=self.tool_name,
                status=self.status,
                summary=_utf8_prefix(self.summary, min(512, max_bytes // 8)),
                important_fields=self.important_fields,
                content=_utf8_prefix(self.content, middle),
                truncated=True,
                full_result_digest=self.full_result_digest,
                first_diagnostics=tuple(_utf8_prefix(item, 256) for item in self.first_diagnostics),
                last_diagnostics=tuple(_utf8_prefix(item, 256) for item in self.last_diagnostics),
                output_bytes=self.output_bytes,
                output_tokens=self.output_tokens,
            )
            size = len(canonical_json_bytes(candidate.to_payload()))
            if size <= max_bytes:
                best = candidate
                low = middle + 1
            else:
                high = middle - 1
        if len(canonical_json_bytes(best.to_payload())) > max_bytes:
            # The schema itself has a fixed minimum size.  Refuse an
            # impossible bound instead of returning a structurally valid
            # envelope larger than the caller's hard limit.
            minimal = ToolOutputEnvelope(
                tool_name=self.tool_name,
                status=self.status,
                summary="",
                important_fields={},
                content="",
                truncated=True,
                full_result_digest=self.full_result_digest,
                output_bytes=self.output_bytes,
                output_tokens=self.output_tokens,
            )
            if len(canonical_json_bytes(minimal.to_payload())) > max_bytes:
                raise ValueError("tool output structural envelope exceeds max_bytes")
            return minimal
        return best


class ToolOutputPolicy:
    """Reusable policy object for all model-visible tool results."""

    def __init__(self, limits: ToolOutputLimits | None = None) -> None:
        self.limits = limits or ToolOutputLimits()

    def envelope(self, result: object) -> ToolOutputEnvelope:
        return ToolOutputEnvelope.from_result(result, limits=self.limits)

    def render(self, result: object) -> str:
        return self.envelope(result).to_json(max_bytes=self.limits.max_bytes)


def bound_tool_result(
    result: object,
    *,
    limits: ToolOutputLimits | None = None,
) -> ToolOutputEnvelope:
    """Return a bounded envelope for a scheduler result."""

    return ToolOutputEnvelope.from_result(result, limits=limits)


def _bounded_scalar(value: object) -> object:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    return _utf8_prefix(str(value), 512)
