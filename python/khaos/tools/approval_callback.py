"""Bounded approval-callback adapter for tool authorization requests.

The callback may be implemented by a UI, gateway, or integration plugin. It
is therefore untrusted with respect to response shape and latency. This
module owns only the adapter lifecycle; it does not decide permission policy
or consume an approval capability.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from khaos.tools.scheduler_models import PermissionRequest

ConfirmCallback = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | bool] | dict[str, Any] | bool]

_CONFIRM_ALLOWED_KEYS = frozenset({"approved", "remember", "pattern", "reason"})
_CONFIRM_PATTERN_MAX_LENGTH = 4096
_CONFIRM_REASON_MAX_LENGTH = 1024

logger = logging.getLogger(__name__)


def normalize_confirmation(value: object) -> dict[str, Any]:
    """Normalize an untrusted approval-adapter result fail-closed."""
    if type(value) is bool:
        return {"approved": value}
    if type(value) is not dict:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    unknown = set(value) - _CONFIRM_ALLOWED_KEYS
    if unknown:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    if type(value.get("approved")) is not bool:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    remember = value.get("remember", False)
    if type(remember) is not bool:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    pattern = value.get("pattern")
    if pattern is not None and (
        type(pattern) is not str
        or not pattern
        or len(pattern) > _CONFIRM_PATTERN_MAX_LENGTH
        or any(char in pattern for char in "\x00\r\n")
    ):
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    reason = value.get("reason")
    if reason is not None and (
        type(reason) is not str
        or len(reason) > _CONFIRM_REASON_MAX_LENGTH
        or any(char in reason for char in "\x00\r\n")
    ):
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    normalized: dict[str, Any] = {"approved": value["approved"]}
    if "remember" in value:
        normalized["remember"] = remember
    if pattern is not None:
        normalized["pattern"] = pattern
    if reason is not None:
        normalized["reason"] = reason
    return normalized


def confirmation_payload(request: PermissionRequest) -> dict[str, Any]:
    """Build the immutable-schema projection sent to an approval adapter."""
    return {
        "id": request.tool_call_id,
        "name": request.name,
        "arguments": request.arguments,
        "level": request.level,
        "target": request.target,
        "reason": request.reason,
        "binding_digest": request.binding_digest,
        "expires_at": request.expires_at,
        "principal_id": request.principal_id,
        "session_id": request.session_id,
        "task_id": request.task_id,
        "workspace_id": request.workspace_id,
        "arguments_digest": request.arguments_digest,
        "profile_digest": request.profile_digest,
        "project_id": request.project_id,
        "workspace_generation": request.workspace_generation,
        "authorization_resource_digest": request.authorization_resource_digest,
        "authorization_epoch": request.authorization_epoch,
        "policy_digest": request.policy_digest,
        "tool_schema_digest": request.tool_schema_digest,
        "tool_security_digest": request.tool_security_digest,
    }


class ApprovalCallbackRunner:
    """Run approval adapters with bounded capacity and terminal shutdown."""

    def __init__(self, *, max_workers: int = 4) -> None:
        if type(max_workers) is not int or max_workers <= 0:
            raise ValueError("max_workers must be a positive integer")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="khaos-approval-callback",
        )
        self._admission = threading.BoundedSemaphore(max_workers)
        self._state_lock = threading.Lock()
        self._active = 0
        self._closed = False
        self._idle = threading.Event()
        self._idle.set()

    async def run(
        self,
        request: PermissionRequest,
        callback: ConfirmCallback | None,
    ) -> dict[str, Any]:
        """Invoke one callback and normalize its response or deny it."""
        if callback is None:
            return {"approved": False}
        remaining = request.expires_at - time.time()
        if remaining <= 0:
            return {"approved": False, "reason": "approval_expired_before_callback"}
        payload = confirmation_payload(request)
        if inspect.iscoroutinefunction(callback):
            value = await asyncio.wait_for(callback(payload), timeout=remaining)
        else:
            value = await self._run_sync(callback, payload, remaining)
        if inspect.isawaitable(value):
            remaining = request.expires_at - time.time()
            if remaining <= 0:
                return {"approved": False, "reason": "approval_expired_before_callback"}
            try:
                value = await asyncio.wait_for(value, timeout=remaining)
            except TimeoutError:
                return {"approved": False, "reason": "approval_callback_timeout"}
        normalized = normalize_confirmation(value)
        if normalized.get("reason") == "invalid_confirmation_response":
            logger.warning("approval callback returned a malformed response; denying request")
        return normalized

    async def _run_sync(
        self,
        callback: ConfirmCallback,
        payload: dict[str, Any],
        remaining: float,
    ) -> object:
        if not self._admission.acquire(blocking=False):
            return {
                "approved": False,
                "reason": "approval_callback_capacity_exhausted",
            }
        with self._state_lock:
            if self._closed:
                self._admission.release()
                return {
                    "approved": False,
                    "reason": "approval_callback_executor_closed",
                }
            self._active += 1
            self._idle.clear()

        def invoke() -> object:
            try:
                return callback(payload)
            finally:
                with self._state_lock:
                    self._active -= 1
                    if self._active == 0:
                        self._idle.set()
                self._admission.release()

        try:
            future = asyncio.get_running_loop().run_in_executor(self._executor, invoke)
        except RuntimeError:
            with self._state_lock:
                self._active -= 1
                if self._active == 0:
                    self._idle.set()
            self._admission.release()
            return {
                "approved": False,
                "reason": "approval_callback_executor_closed",
            }
        try:
            return await asyncio.wait_for(future, timeout=remaining)
        except TimeoutError:
            return {"approved": False, "reason": "approval_callback_timeout"}

    async def aclose(self, *, timeout: float = 5.0) -> None:
        """Close the executor only after all owned callback workers terminate."""
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._state_lock:
            self._closed = True
        if not await asyncio.to_thread(self._idle.wait, timeout):
            raise RuntimeError("approval callback workers did not terminate")
        self._executor.shutdown(wait=True, cancel_futures=True)


__all__ = [
    "ApprovalCallbackRunner",
    "ConfirmCallback",
    "confirmation_payload",
    "normalize_confirmation",
]
