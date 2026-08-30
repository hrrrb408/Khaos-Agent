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
from collections.abc import Mapping
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
        "khaos.coding.execution.host.HostBackend",
        # In-process / test / mock network and authority substitutions.
        "unittest.mock.Mock",
        "unittest.mock.MagicMock",
        # Explicit composition names are kept here even when the forbidden
        # modules are absent from the production graph.  A test/dev adapter
        # injected through an object graph must fail closed without importing
        # the adapter module into this verifier.
        "khaos.security.mock_authority.MockAuthority",
        "khaos.coding.execution.testing_sandbox.TestingSandbox",
        "khaos.runtime.testing.TestingRuntimeComposition",
    }
)


class CompositionError(PermissionError):
    """The runtime composition does not match the production contract."""


_CONSTRUCTION_COMPONENT_KEYS = (
    "tool_scheduler",
    "security_middleware",
    "sandbox_backend",
    "network_guard",
    "local_audit_logger",
    "execution_service",
    "workspace_authority",
    "office_mutation_authority",
    "credential_broker",
    "network_broker",
    "approval_broker",
    "process_supervisor",
    "execution_backend_selector",
    "verification_backend",
)


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


def _declared_type_name(value: object) -> str:
    """Return the type represented by a construction-time witness.

    The verification factory is a class rather than an instance.  Treating
    that class as a witness keeps the construction manifest explicit without
    instantiating a second strategy object merely for inspection.
    """
    if isinstance(value, type):
        return f"{value.__module__}.{value.__qualname__}"
    return _exact_type_name(value)


def _construction_digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build_construction_manifest(
    components: Mapping[str, object],
) -> dict[str, object]:
    """Build the exact component declaration at the factory boundary.

    The runtime factory calls this with the objects it just constructed.  It
    is deliberately a mapping supplied by the constructor, not a reflection
    pass over a running object graph.  Runtime verification still resolves
    the fixed component paths and compares both the live objects and this
    declaration, so changing a component after construction is detected.
    """
    missing = [key for key in _CONSTRUCTION_COMPONENT_KEYS if key not in components]
    if missing:
        raise CompositionError(
            "construction manifest is missing components: " + ", ".join(missing)
        )
    declared = {
        key: _declared_type_name(components[key])
        for key in _CONSTRUCTION_COMPONENT_KEYS
    }
    payload: dict[str, object] = {
        "schema_version": 1,
        "components": declared,
    }
    payload["construction_digest"] = _construction_digest(payload)
    return payload


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
    """Collect concrete types without invoking arbitrary object properties.

    This walk is a bounded forbidden-component detector, not the positive
    composition proof.  Reading ``__dict__`` includes private state while
    avoiding ``dir()``/property evaluation, which could both hide state and
    execute attacker-controlled descriptors.
    """
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
                pending.append((key, depth + 1))
                pending.append((value, depth + 1))
            continue
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                pending.append((item, depth + 1))
            continue
        if isinstance(node, (str, bytes, int, float, bool)):
            continue
        try:
            attributes = object.__getattribute__(node, "__dict__")
        except (AttributeError, TypeError):
            attributes = None
        if isinstance(attributes, dict):
            pending.extend((value, depth + 1) for value in attributes.values())
        # Some lightweight test doubles and immutable configuration objects
        # keep their child component as a class attribute.  Read the raw
        # class dictionary only; do not call descriptors or methods.
        try:
            class_attributes = vars(type(node))
        except TypeError:
            class_attributes = {}
        for name, value in class_attributes.items():
            if name.startswith("__") or callable(value) or isinstance(value, type):
                continue
            if isinstance(value, (property, staticmethod, classmethod)):
                continue
            pending.append((value, depth + 1))
    return seen_types


def _direct_component_values(runtime: Any) -> dict[str, object]:
    """Resolve only the fixed production component paths.

    These paths mirror the constructor wiring in ``runtime.factory``.  No
    graph search or type-name fallback is used for the positive proof.
    """
    scheduler = getattr(runtime, "tool_scheduler", None)
    middleware = getattr(scheduler, "security_middleware", None)
    loop = getattr(runtime, "loop", None)
    execution_service = getattr(runtime, "execution_service", None)
    selector = getattr(execution_service, "backend_selector", None)
    return {
        "tool_scheduler": scheduler,
        "security_middleware": middleware,
        "sandbox_backend": getattr(middleware, "sandbox", None),
        "network_guard": getattr(middleware, "network_guard", None),
        "local_audit_logger": getattr(runtime, "audit_logger", None),
        "execution_service": execution_service,
        "workspace_authority": getattr(loop, "workspace_manager", None),
        "office_mutation_authority": getattr(runtime, "office_authority", None),
        "credential_broker": getattr(scheduler, "credential_broker", None),
        "network_broker": getattr(scheduler, "network_broker_factory", None),
        "approval_broker": getattr(loop, "approval_broker", None),
        "process_supervisor": getattr(execution_service, "process_supervisor", None),
        "execution_backend_selector": selector,
        "verification_backend": getattr(runtime, "new_verify_fix_loop", None),
    }


def _verify_construction_manifest(
    runtime: Any,
    errors: list[str],
) -> dict[str, str]:
    """Validate the factory declaration and return its component names."""
    declared = getattr(runtime, "composition_manifest", None)
    if not isinstance(declared, dict):
        errors.append("factory construction manifest is missing")
        return {}
    if declared.get("schema_version") != 1:
        errors.append("factory construction manifest schema is unsupported")
        return {}
    components = declared.get("components")
    digest = declared.get("construction_digest")
    if not isinstance(components, dict) or not isinstance(digest, str):
        errors.append("factory construction manifest is malformed")
        return {}
    base = {"schema_version": 1, "components": components}
    if digest != _construction_digest(base):
        errors.append("factory construction manifest digest mismatch")
    direct = _direct_component_values(runtime)
    expected_keys = set(_CONSTRUCTION_COMPONENT_KEYS)
    if set(components) != expected_keys:
        errors.append("factory construction manifest component set mismatch")
    for key in _CONSTRUCTION_COMPONENT_KEYS:
        value = direct.get(key)
        if value is None:
            errors.append(f"factory component is missing: {key}")
            continue
        actual = _declared_type_name(value)
        if components.get(key) != actual:
            errors.append(
                f"factory component changed after construction: {key} "
                f"({components.get(key)!r} != {actual!r})"
            )
    return {
        str(key): str(value)
        for key, value in components.items()
        if isinstance(key, str) and isinstance(value, str)
    }


def _verify_production_authority_channel(
    runtime: Any,
    errors: list[str],
    components: dict[str, str],
) -> None:
    """Verify the READY authority channel and every effect consumer binding."""
    profile = getattr(runtime, "profile", None)
    if not bool(getattr(profile, "is_production", False)):
        return

    authority = getattr(runtime, "authority_broker", None)
    if authority is None:
        errors.append("production runtime authority broker is missing")
        return
    components["production_authority_channel"] = _exact_type_name(authority)
    if not bool(getattr(authority, "ready", False)):
        errors.append("production authority broker is not READY")
    binding = getattr(authority, "trust_binding", None)
    if binding is None:
        errors.append("production authority broker has no trust binding")
        return

    seal = getattr(runtime, "authority_seal", None)
    if seal is None or getattr(seal, "policy_digest", None) != binding.policy_digest:
        errors.append("production authority binding does not match the runtime policy")

    loop = getattr(runtime, "loop", None)
    workspace = getattr(loop, "workspace_manager", None)
    catalog = getattr(getattr(workspace, "resource_order", None), "catalog_semantic_digest", None)
    if catalog != binding.catalog_semantic_digest:
        errors.append("production authority binding does not match the runtime catalog")

    scheduler = getattr(runtime, "tool_scheduler", None)
    network_factory = getattr(scheduler, "network_broker_factory", None)
    execution_service = getattr(runtime, "execution_service", None)
    supervisor = getattr(execution_service, "process_supervisor", None)
    for label, consumer in (
        ("workspace", workspace),
        ("network", network_factory),
        ("execution", execution_service),
        ("supervisor", supervisor),
    ):
        if getattr(consumer, "authority_broker", None) is not authority:
            errors.append(
                f"production {label} consumer is not bound to the runtime authority broker"
            )


def verify_runtime_composition(runtime: Any) -> CompositionManifest:
    """Verify the exact production composition of one real runtime.

    This is the *Linux production* composition verifier: it requires the
    Linux bwrap execution backend and treats any other backend as an
    error.  Cross-platform compositions are proven by other evidence
    types, not by this manifest.
    """
    components: dict[str, str] = {}
    errors: list[str] = []

    # RuntimeResult always exposes this field; ad-hoc fake runtimes used by
    # unit tests do not.  A real factory-built runtime must prove the
    # construction declaration before the compatibility diagnostics below.
    if hasattr(runtime, "composition_manifest"):
        components.update(_verify_construction_manifest(runtime, errors))

    scheduler = getattr(runtime, "tool_scheduler", None)
    if type(scheduler) is not ToolScheduler:
        errors.append("tool_scheduler is missing or not a ToolScheduler")
    else:
        components["tool_scheduler"] = _exact_type_name(scheduler)

    middleware = getattr(scheduler, "security_middleware", None) if scheduler else None
    if type(middleware) is not SecurityMiddleware:
        errors.append("security_middleware is missing or not a SecurityMiddleware")
    else:
        components["security_middleware"] = _exact_type_name(middleware)

    sandbox = getattr(middleware, "sandbox", None) if middleware else None
    if type(sandbox) is not Sandbox:
        errors.append("sandbox is missing or not a Sandbox")
    else:
        components["sandbox_backend"] = _exact_type_name(sandbox)

    network_guard = getattr(middleware, "network_guard", None) if middleware else None
    if type(network_guard) is not NetworkGuard:
        errors.append("network_guard is missing or not a NetworkGuard")
    else:
        components["network_guard"] = _exact_type_name(network_guard)

    audit_logger = getattr(runtime, "audit_logger", None)
    if type(audit_logger) is not AuditLogger:
        errors.append("audit_logger is missing or not an AuditLogger")
    else:
        # Honest semantics: this handle is the LOCAL SQLite/append-file
        # audit logger.  The remote WORM writer is authority-side state
        # (proven separately by the production composition probe); labeling
        # the local logger as "worm_audit_writer" overclaimed the
        # composition.
        components["local_audit_logger"] = _exact_type_name(audit_logger)

    execution_service = getattr(runtime, "execution_service", None)
    if type(execution_service) is not ExecutionService:
        errors.append("execution_service is missing or not an ExecutionService")
    else:
        components["execution_service"] = _exact_type_name(execution_service)

    workspace_manager = getattr(runtime, "loop", None)
    loop = workspace_manager
    manager = getattr(loop, "workspace_manager", None) if loop else None
    if type(manager) is not WorkspaceManager:
        errors.append("workspace_manager is missing or not a WorkspaceManager")
    else:
        components["workspace_authority"] = _exact_type_name(manager)

    office_authority = getattr(runtime, "office_authority", None)
    if type(office_authority) is not OfficeMutationAuthority:
        errors.append("office_authority is missing or not an OfficeMutationAuthority")
    else:
        components["office_mutation_authority"] = _exact_type_name(office_authority)

    credential_broker = getattr(scheduler, "credential_broker", None) if scheduler else None
    if type(credential_broker) is not CredentialBroker:
        errors.append("credential_broker is missing or not a CredentialBroker")
    else:
        components["credential_broker"] = _exact_type_name(credential_broker)

    network_broker_factory = (
        getattr(scheduler, "network_broker_factory", None) if scheduler else None
    )
    if type(network_broker_factory) is not NetworkBrokerFactory:
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
    if type(backend_selector) is not BackendSelector:
        errors.append("backend_selector is missing or not a BackendSelector")
    else:
        components["execution_backend_selector"] = _exact_type_name(backend_selector)
        backend = getattr(backend_selector, "_backend", None)
        if backend is None:
            # The backend is selected lazily; verify the selector's decision
            # function resolves to the platform sandbox backend, never a
            # forbidden host backend.
            resolve = getattr(backend_selector, "select", None)
            if callable(resolve):
                try:
                    backend = resolve(writable=True)
                except Exception:  # noqa: BLE001 - selection must succeed
                    errors.append("backend selection failed")
        if backend is not None:
            components["execution_backend"] = _exact_type_name(backend)
            if type(backend) is not LinuxBubblewrapBackend:
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

    _verify_production_authority_channel(runtime, errors, components)

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
    "build_construction_manifest",
    "verify_runtime_composition",
]
