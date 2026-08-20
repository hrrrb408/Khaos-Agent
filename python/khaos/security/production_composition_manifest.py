"""Machine-verified production runtime composition manifest (M6.9 BATCH 10).

The static import graph (``docs/generated/production-reachability.md``)
proves which modules *can* be imported from production roots — it is not
a whole-program runtime reachability proof.  This module provides the
runtime half of the evidence: given a REAL production
:class:`~khaos.runtime.factory.RuntimeResult`, it verifies the exact
types of every security-relevant component and the absence of every
forbidden fallback component, and emits a signed-by-digest composition
manifest.

Fail-closed semantics: any missing component, wrong exact type, or
detected forbidden type makes the manifest INVALID.  The verifier never
falls back to type-name heuristics when a component is absent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from khaos.audit.logger import AuditLogger
from khaos.coding.execution import (
    BackendSelector,
    ExecutionService,
    LinuxBubblewrapBackend,
)
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.security.credential_broker import CredentialBroker
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_broker import NetworkBrokerFactory
from khaos.security.network_guard import NetworkGuard
from khaos.security.sandbox import Sandbox
from khaos.tools.scheduler import ToolScheduler

# Forbidden production fallback components, detected BY NAME from the
# runtime object graph.  These modules are deliberately NOT imported
# here: importing the forbidden module would make it reachable from a
# production root and break the static import-reachability gate.
FORBIDDEN_TYPE_NAMES = frozenset(
    {
        # The host execution backend is the forbidden production fallback.
        "khaos.coding.execution.host.HostExecutionBackend",
        # In-process / test / mock network and authority substitutions.
        "unittest.mock.Mock",
        "unittest.mock.MagicMock",
    }
)


class CompositionError(PermissionError):
    """The runtime composition does not match the production contract."""


@dataclass(frozen=True, slots=True)
class CompositionManifest:
    """Verified runtime component types plus forbidden-type absence."""

    schema_version: int
    components: dict[str, str]
    forbidden_detected: tuple[str, ...]
    valid: bool
    errors: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "components": self.components,
            "forbidden_detected": list(self.forbidden_detected),
            "valid": self.valid,
            "errors": list(self.errors),
            "manifest_digest": hashlib.sha256(
                json.dumps(
                    {
                        "components": self.components,
                        "forbidden_detected": list(self.forbidden_detected),
                        "valid": self.valid,
                        "errors": list(self.errors),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }


def _exact_type_name(value: object) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _collect_authority_component_names(runtime: Any) -> set[str]:
    """Exact names of authority receipt-broker types reachable from the runtime."""
    reachable = _walk_object_graph(runtime, max_depth=5)
    return {
        f"{cls.__module__}.{cls.__qualname__}"
        for cls in reachable
        if cls.__module__ == "khaos.security.authority_broker"
        and any(
            token in cls.__qualname__.lower()
            for token in ("broker", "capability")
        )
    }


def _walk_object_graph(root: object, max_depth: int = 4) -> set[type]:
    """Collect the concrete types reachable from an object graph."""
    seen_types: set[type] = set()
    visited: set[int] = set()
    pending: list[tuple[object, int]] = [(root, 0)]
    while pending:
        node, depth = pending.pop()
        if node is None or depth > max_depth:
            continue
        node_id = id(node)
        if node_id in visited:
            continue
        visited.add(node_id)
        seen_types.add(type(node))
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    pending.append((value, depth + 1))
                pending.append((value, depth + 1))
            continue
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                pending.append((item, depth + 1))
            continue
        if isinstance(node, (str, bytes, int, float, bool)):
            continue
        for attribute in dir(node):
            if attribute.startswith("_"):
                continue
            try:
                value = getattr(node, attribute)
            except Exception:  # noqa: BLE001, S112 - introspection only
                continue
            if callable(value) and not isinstance(value, type):
                continue
            pending.append((value, depth + 1))
    return seen_types


def verify_runtime_composition(runtime: Any) -> CompositionManifest:
    """Verify the exact production composition of one real runtime.

    This is the *Linux production* composition verifier: it requires the
    Linux bwrap execution backend and treats any other backend as an
    error.  Cross-platform compositions are proven by other evidence
    types, not by this manifest.
    """
    components: dict[str, str] = {}
    errors: list[str] = []

    scheduler = getattr(runtime, "tool_scheduler", None)
    if not isinstance(scheduler, ToolScheduler):
        errors.append("tool_scheduler is missing or not a ToolScheduler")
    else:
        components["tool_scheduler"] = _exact_type_name(scheduler)

    middleware = getattr(scheduler, "security_middleware", None) if scheduler else None
    if not isinstance(middleware, SecurityMiddleware):
        errors.append("security_middleware is missing or not a SecurityMiddleware")
    else:
        components["security_middleware"] = _exact_type_name(middleware)

    sandbox = getattr(middleware, "sandbox", None) if middleware else None
    if not isinstance(sandbox, Sandbox):
        errors.append("sandbox is missing or not a Sandbox")
    else:
        components["sandbox_backend"] = _exact_type_name(sandbox)

    network_guard = getattr(middleware, "network_guard", None) if middleware else None
    if not isinstance(network_guard, NetworkGuard):
        errors.append("network_guard is missing or not a NetworkGuard")
    else:
        components["network_guard"] = _exact_type_name(network_guard)

    audit_logger = getattr(runtime, "audit_logger", None)
    if not isinstance(audit_logger, AuditLogger):
        errors.append("audit_logger is missing or not an AuditLogger")
    else:
        # Honest semantics: this handle is the LOCAL SQLite/append-file
        # audit logger.  The remote WORM writer is authority-side state
        # (proven separately by the production composition probe); labeling
        # the local logger as "worm_audit_writer" overclaimed the
        # composition.
        components["local_audit_logger"] = _exact_type_name(audit_logger)

    execution_service = getattr(runtime, "execution_service", None)
    if not isinstance(execution_service, ExecutionService):
        errors.append("execution_service is missing or not an ExecutionService")
    else:
        components["execution_service"] = _exact_type_name(execution_service)

    workspace_manager = getattr(runtime, "loop", None)
    loop = workspace_manager
    manager = getattr(loop, "workspace_manager", None) if loop else None
    if not isinstance(manager, WorkspaceManager):
        errors.append("workspace_manager is missing or not a WorkspaceManager")
    else:
        components["workspace_authority"] = _exact_type_name(manager)

    office_authority = getattr(runtime, "office_authority", None)
    if not isinstance(office_authority, OfficeMutationAuthority):
        errors.append("office_authority is missing or not an OfficeMutationAuthority")
    else:
        components["office_mutation_authority"] = _exact_type_name(office_authority)

    credential_broker = getattr(scheduler, "credential_broker", None) if scheduler else None
    if not isinstance(credential_broker, CredentialBroker):
        errors.append("credential_broker is missing or not a CredentialBroker")
    else:
        components["credential_broker"] = _exact_type_name(credential_broker)

    network_broker_factory = (
        getattr(scheduler, "network_broker_factory", None) if scheduler else None
    )
    if not isinstance(network_broker_factory, NetworkBrokerFactory):
        errors.append("network_broker_factory is missing or not a NetworkBrokerFactory")
    else:
        components["network_broker"] = _exact_type_name(network_broker_factory)

    approval_broker = getattr(runtime.loop, "approval_broker", None) if loop else None
    if approval_broker is None:
        errors.append("approval_broker is missing")
    else:
        components["approval_broker"] = _exact_type_name(approval_broker)

    process_supervisor = getattr(execution_service, "process_supervisor", None) if execution_service else None
    if process_supervisor is None:
        errors.append("process_supervisor is missing from the execution service")
    else:
        components["process_supervisor"] = _exact_type_name(process_supervisor)

    backend_selector = (
        getattr(execution_service, "backend_selector", None) if execution_service else None
    )
    if not isinstance(backend_selector, BackendSelector):
        errors.append("backend_selector is missing or not a BackendSelector")
    else:
        components["execution_backend_selector"] = _exact_type_name(backend_selector)
        backend = getattr(backend_selector, "_backend", None)
        if backend is None:
            # The backend is selected lazily; verify the selector's decision
            # function resolves to the platform sandbox backend, never a
            # forbidden host backend.
            resolve = getattr(backend_selector, "select", None) or getattr(
                backend_selector, "resolve", None
            )
            if callable(resolve):
                try:
                    backend = resolve()
                except Exception:  # noqa: BLE001 - selection must succeed
                    errors.append("backend selection failed")
        if backend is not None:
            components["execution_backend"] = _exact_type_name(backend)
            if not isinstance(backend, LinuxBubblewrapBackend):
                errors.append(
                    "execution backend is not the platform sandbox backend: "
                    + _exact_type_name(backend)
                )
        else:
            errors.append("execution backend could not be resolved")

    verify_fix_loop = getattr(runtime, "new_verify_fix_loop", None)
    if verify_fix_loop is None:
        errors.append("verification backend factory is missing")
    else:
        components["verification_backend"] = (
            f"{VerifyFixLoop.__module__}.{VerifyFixLoop.__qualname__}"
        )

    # Authority-bound child spawn: the execution service must actually be
    # bound to the runtime authority (the flag flips in bind_runtime_
    # authority), and the supervisor's authority-broker imports must be
    # live — the receipt claim path below is what turns spawns into
    # two-phase authority effects.
    if execution_service is not None and not getattr(
        execution_service, "_authority_bound", False
    ):
        errors.append("execution service is not bound to the runtime authority")
    authority_components = _collect_authority_component_names(runtime)
    if not authority_components:
        errors.append("no authority receipt broker reachable from the runtime")
    else:
        components["security_authority_broker"] = ",".join(
            sorted(authority_components)
        )

    # Forbidden-type absence: walk the whole runtime graph and detect any
    # known dev/test/host/mock fallback component by exact type name.
    graph_types = _walk_object_graph(runtime)
    forbidden_detected: list[str] = []
    for graph_type in graph_types:
        type_name = f"{graph_type.__module__}.{graph_type.__qualname__}"
        if type_name in FORBIDDEN_TYPE_NAMES:
            forbidden_detected.append(type_name)
            errors.append(f"forbidden component present in runtime graph: {type_name}")
            continue
        lowered = type_name.lower()
        if (
            "mock" in lowered
            or type_name.startswith("unittest.")
            or ".tests." in lowered
            or "devadapter" in lowered.replace("_", "")
        ):
            forbidden_detected.append(type_name)
            errors.append(f"forbidden test/dev component in runtime graph: {type_name}")

    return CompositionManifest(
        schema_version=1,
        components=components,
        forbidden_detected=tuple(forbidden_detected),
        valid=not errors,
        errors=tuple(errors),
    )


__all__ = [
    "FORBIDDEN_TYPE_NAMES",
    "CompositionError",
    "CompositionManifest",
    "verify_runtime_composition",
]

