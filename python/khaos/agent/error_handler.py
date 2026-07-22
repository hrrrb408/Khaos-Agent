"""Error classification, recovery helpers, and SSE error events."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable

import httpx

from khaos.agent.core import Message


class ErrorCode(Enum):
    """Phase 1 error codes."""

    MODEL_TIMEOUT = "MODEL_TIMEOUT"
    MODEL_RATE_LIMITED = "MODEL_RATE_LIMITED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_CONTEXT_TOO_LONG = "MODEL_CONTEXT_TOO_LONG"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"
    TOOL_BUDGET_EXHAUSTED = "TOOL_BUDGET_EXHAUSTED"
    TOOL_INVALID_PARAMS = "TOOL_INVALID_PARAMS"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    PERMISSION_REQUIRED = "PERMISSION_REQUIRED"
    SANDBOX_CREATE_FAILED = "SANDBOX_CREATE_FAILED"
    SANDBOX_EXEC_FAILED = "SANDBOX_EXEC_FAILED"
    SANDBOX_TIMEOUT = "SANDBOX_TIMEOUT"
    COMPRESSION_FAILED = "COMPRESSION_FAILED"
    COMPRESSION_CIRCUIT_OPEN = "COMPRESSION_CIRCUIT_OPEN"
    MEMORY_CONFLICT = "MEMORY_CONFLICT"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    CONFIG_INVALID = "CONFIG_INVALID"
    DB_ERROR = "DB_ERROR"


@dataclass
class ErrorEvent:
    """Public SSE error event payload."""

    code: ErrorCode
    message: str
    recoverable: bool = True
    detail: dict | None = None

    def to_message(self) -> Message:
        """Convert to an SSE error Message."""
        return Message(
            role="system",
            content=self.message,
            stop_reason="error",
            event="error",
            metadata={
                "code": self.code.value,
                "message": self.message,
                "recoverable": self.recoverable,
                "detail": self.detail or {},
            },
        )


class ModelRateLimitError(Exception):
    """Raised when a model provider returns a rate-limit error."""


class ModelContextTooLongError(Exception):
    """Raised when a model provider rejects an oversized prompt."""


class ErrorHandler:
    """Classify errors, audit them, and provide recovery operations."""

    def __init__(
        self,
        db=None,
        router=None,
        compressor=None,
        max_retries: int = 3,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
    ):
        self.db = db
        self.router = router
        self.compressor = compressor
        self.max_retries = max_retries
        self.principal_id = principal_id
        self.project_id = project_id

    def classify(self, error: Exception) -> ErrorCode:
        """Map an exception to a stable error code."""
        if isinstance(error, asyncio.TimeoutError):
            return ErrorCode.MODEL_TIMEOUT
        if isinstance(error, httpx.TimeoutException):
            return ErrorCode.MODEL_TIMEOUT
        if isinstance(error, ModelRateLimitError):
            return ErrorCode.MODEL_RATE_LIMITED
        if isinstance(error, ModelContextTooLongError):
            return ErrorCode.MODEL_CONTEXT_TOO_LONG
        if isinstance(error, httpx.TransportError):
            return ErrorCode.MODEL_UNAVAILABLE
        if isinstance(error, TimeoutError):
            return ErrorCode.TOOL_TIMEOUT
        if isinstance(error, PermissionError):
            return ErrorCode.PERMISSION_DENIED
        if isinstance(error, KeyError):
            return ErrorCode.TOOL_NOT_FOUND
        return ErrorCode.INTERNAL_ERROR

    async def audit_error(
        self,
        code: ErrorCode,
        message: str,
        session_id: str | None = None,
        detail: dict | None = None,
    ) -> None:
        """Write an error event to audit_log."""
        if self.db is None:
            return
        await self.db.insert_audit_log(
            action=f"error:{code.value}",
            target=session_id or "",
            result="error",
            detail=json.dumps({"message": message, **(detail or {})}, ensure_ascii=False),
            session_id=session_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )

    async def handle(
        self,
        error: Exception,
        session_id: str | None = None,
        detail: dict | None = None,
    ) -> ErrorEvent:
        """Classify, audit, and return an SSE error event."""
        code = self.classify(error)
        message = _format_error_message(error)
        event = ErrorEvent(code=code, message=message, recoverable=code != ErrorCode.INTERNAL_ERROR, detail=detail)
        await self.audit_error(code, message, session_id, detail)
        return event

    async def retry_rate_limited(self, operation: Callable[[], Awaitable], base_delay: float = 0.01):
        """Retry a rate-limited operation with exponential backoff."""
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                return await operation()
            except ModelRateLimitError as exc:
                last_error = exc
                await asyncio.sleep(base_delay * (2**attempt))
        assert last_error is not None
        raise last_error

    async def fallback_model_call(self, function: str, messages: list[Message]):
        """Call router fallback path after a model timeout/unavailability."""
        if self.router is None:
            raise RuntimeError("router is not configured")
        chunks: list[Message] = []
        async for chunk in self.router.call_with_fallback(function, messages):
            chunks.append(chunk)
        return chunks

    async def recover_prompt_too_long(self, messages: list[Message], threshold: int):
        """Run auto-compaction after prompt-too-long."""
        if self.compressor is None:
            raise RuntimeError("compressor is not configured")
        return await self.compressor.compress(messages, threshold)


def _format_error_message(error: Exception) -> str:
    message = str(error).strip()
    if message:
        return message
    cause = getattr(error, "__cause__", None) or getattr(error, "__context__", None)
    if isinstance(cause, Exception):
        cause_message = str(cause).strip()
        if cause_message:
            return f"{error.__class__.__name__}: {cause_message}"
    return error.__class__.__name__
