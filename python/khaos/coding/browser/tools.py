"""Model-facing Coding browser tools.

These handlers are deliberately thin: schemas and typed contracts reject
arbitrary JavaScript/argv, while ``BrowserCodingService`` performs all
identity, generation, effect, and observation checks.
"""

from __future__ import annotations

from typing import Any

from khaos.coding.browser.contracts import (
    BrowserAction,
    BrowserContractError,
    BrowserEffectClass,
    BrowserResultStatus,
)
from khaos.coding.browser.service import BrowserCodingService, BrowserServiceError
from khaos.security.protocol_boundary import canonical_digest


def _workspace(
    workspace_manager: Any,
    workspace_id: str,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
    runtime_id: str,
) -> Any:
    if workspace_manager is None:
        raise PermissionError("browser Coding tools require an active TaskWorkspace")
    require = getattr(workspace_manager, "require", None)
    if not callable(require):
        raise PermissionError("browser Coding tools require WorkspaceManager.require")
    return require(
        workspace_id,
        task_id=task_id,
        principal_id=principal_id,
        project_id=project_id,
        runtime_id=runtime_id,
    )


def _observation_payload(observation: Any) -> dict[str, object] | None:
    if observation is None:
        return None
    return observation.to_payload()


def _action_payload(result: Any) -> dict[str, object]:
    return {
        "status": result.status.value,
        "effect_status": result.effect_status.value,
        "action_id": result.action.action_id,
        "sequence": result.action.sequence,
        "observation": _observation_payload(result.observation),
        "error_category": result.error_category,
        "error": result.error,
    }


async def browser_app_open(
    profile_id: str,
    *,
    browser_coding_service: BrowserCodingService | None = None,
    workspace_manager: Any = None,
    workspace_id: str = "",
    task_id: str = "",
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    workspace_generation: int = 0,
    **_injected: object,
) -> dict[str, object]:
    """Open a trusted app profile and bind a real browser session to it."""
    if browser_coding_service is None:
        return {
            "status": BrowserResultStatus.ENVIRONMENT_BLOCKED.value,
            "error_category": "environment-blocked",
            "error": "BrowserCodingService is not composed",
        }
    try:
        workspace = _workspace(
            workspace_manager,
            workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        result = await browser_coding_service.open_app(
            profile_id,
            task_id=task_id,
            workspace=workspace,
            principal_id=principal_id,
            project_id=project_id,
            workspace_generation=workspace_generation,
            runtime_id=runtime_id,
        )
        return {
            "status": result.status.value,
            "session": result.session.to_payload() if result.session is not None else None,
            "error_category": result.error_category,
            "error": result.error,
        }
    except (BrowserContractError, PermissionError) as exc:
        return {
            "status": BrowserResultStatus.FAIL.value,
            "error_category": "browser-contract-failure",
            "error": str(exc),
        }


async def browser_observe(
    session_id: str,
    *,
    browser_coding_service: BrowserCodingService | None = None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    task_id: str = "",
    workspace_id: str = "",
    workspace_generation: int = 0,
    workspace_manager: Any = None,
) -> dict[str, object]:
    """Return bounded, explicitly untrusted semantic browser observation."""
    if browser_coding_service is None:
        return {"status": BrowserResultStatus.ENVIRONMENT_BLOCKED.value, "error": "BrowserCodingService is not composed"}
    try:
        _workspace(
            workspace_manager,
            workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        browser_coding_service.assert_session_scope(
            session_id,
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            runtime_id=runtime_id,
        )
        observation = await browser_coding_service.observe(session_id)
    except (BrowserContractError, BrowserServiceError, PermissionError, ValueError) as exc:
        status = (
            BrowserResultStatus.STALE.value
            if isinstance(exc, BrowserServiceError) and exc.category == "stale"
            else BrowserResultStatus.FAIL.value
        )
        category = exc.category if isinstance(exc, BrowserServiceError) else "browser-contract-failure"
        return {"status": status, "error_category": category, "error": str(exc)}
    return {
        "status": BrowserResultStatus.PASS.value,
        "trust": "untrusted-observation",
        "observation": observation.to_payload(),
    }


async def browser_action(
    *,
    browser_coding_service: BrowserCodingService | None = None,
    browser_approval: dict[str, object] | None = None,
    credential_lease: Any = None,
    credential_broker: Any = None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    task_id: str = "",
    workspace_id: str = "",
    workspace_generation: int = 0,
    workspace_manager: Any = None,
    **arguments: object,
) -> dict[str, object]:
    """Perform one bounded semantic action; arbitrary JS is not a parameter."""
    if browser_coding_service is None:
        return {"status": BrowserResultStatus.ENVIRONMENT_BLOCKED.value, "error": "BrowserCodingService is not composed"}
    try:
        _workspace(
            workspace_manager,
            workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        browser_coding_service.assert_session_scope(
            str(arguments.get("session_id") or ""),
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            runtime_id=runtime_id,
        )
        action = BrowserAction(
            action_id=str(arguments.get("action_id") or "model-action"),
            session_id=str(arguments.get("session_id") or ""),
            sequence=arguments.get("sequence", 0),
            kind=arguments.get("kind", ""),
            effect_class=arguments.get("effect_class", BrowserEffectClass.UNKNOWN.value),
            selector=str(arguments.get("selector") or ""),
            value=str(arguments.get("value") or ""),
            target_url=str(arguments.get("target_url") or ""),
            key=str(arguments.get("key") or ""),
            wait_for=str(arguments.get("wait_for") or ""),
            file_path=str(arguments.get("file_path") or ""),
            precondition_digest=str(arguments.get("precondition_digest") or ""),
            credential_name=str(arguments.get("credential_name") or ""),
        )
        result = await browser_coding_service.perform(
            action,
            approval_context=browser_approval,
            request_arguments_digest=canonical_digest(arguments),
            credential_lease=credential_lease,
            credential_broker=credential_broker,
        )
        return _action_payload(result)
    except (BrowserContractError, BrowserServiceError, ValueError, TypeError) as exc:
        category = (
            exc.category
            if isinstance(exc, BrowserServiceError)
            else "browser-contract-failure"
        )
        return {
            "status": BrowserResultStatus.FAIL.value,
            "effect_status": "not_applied",
            "error_category": category,
            "error": str(exc),
        }


async def browser_session_close(
    session_id: str,
    *,
    browser_coding_service: BrowserCodingService | None = None,
    principal_id: str = "",
    project_id: str = "",
    runtime_id: str = "",
    task_id: str = "",
    workspace_id: str = "",
    workspace_generation: int = 0,
    workspace_manager: Any = None,
) -> dict[str, object]:
    """Close one task-owned browser session."""
    if browser_coding_service is None:
        return {"status": BrowserResultStatus.ENVIRONMENT_BLOCKED.value, "error": "BrowserCodingService is not composed"}
    try:
        _workspace(
            workspace_manager,
            workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        browser_coding_service.assert_session_scope(
            session_id,
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            runtime_id=runtime_id,
        )
        await browser_coding_service.close_session(session_id)
    except (BrowserContractError, BrowserServiceError, PermissionError, ValueError) as exc:
        category = exc.category if isinstance(exc, BrowserServiceError) else "browser-contract-failure"
        return {"status": BrowserResultStatus.UNKNOWN.value, "error_category": category, "error": str(exc)}
    return {"status": BrowserResultStatus.PASS.value, "effect_status": "applied", "session_id": session_id}


__all__ = [
    "browser_action",
    "browser_app_open",
    "browser_observe",
    "browser_session_close",
]
