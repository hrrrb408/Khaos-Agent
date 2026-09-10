"""Controlled MCP, Hook, and Skill extension surfaces.

The package is intentionally split into three layers:

* :mod:`khaos.extensions.contracts` contains immutable, digest-bound values;
* :mod:`khaos.extensions.registry` and :mod:`khaos.extensions.admission` own
  discovery/validation and capability admission;
* protocol adapters are untrusted data producers and never become a second
  execution, approval, verification, or completion authority.

Importing this package is lightweight.  Concrete MCP transports are imported
only when the caller asks for them.
"""

from khaos.extensions.admission import (
    CapabilityAdmissionService,
    ExtensionPolicy,
)
from khaos.extensions.contracts import (
    AdmissionStatus,
    CapabilityDescriptor,
    CapabilityKind,
    CapabilityRequest,
    EffectiveCapability,
    EffectKind,
    ExtensionDescriptor,
    ExtensionLifecycleState,
    ExtensionProvenance,
    ExtensionRecord,
    ExtensionSource,
    ExtensionSourceKind,
    ExtensionType,
    InvocationBinding,
    McpTransportKind,
)
from khaos.extensions.hooks import (
    HookDescriptor,
    HookDispatcher,
    HookDispatchReport,
    HookEvent,
    HookFailure,
    HookInvocation,
    HookMode,
    HookResult,
    HookResultStatus,
    HookToolRequest,
)
from khaos.extensions.mcp import (
    MCP_PROTOCOL_VERSION,
    HttpxMcpTransport,
    McpCallResult,
    McpDataResult,
    McpError,
    McpErrorCode,
    McpLimits,
    McpServerSession,
    McpSessionState,
    ScriptedMcpTransport,
    validate_mcp_endpoint,
    validate_redirect,
    validate_resource_uri,
    validate_stdio_configuration,
)
from khaos.extensions.registry import ExtensionRegistry
from khaos.extensions.service import ExtensionDoctorReport, ExtensionService
from khaos.extensions.skills import (
    SkillActivation,
    SkillActivationService,
    SkillActivationStatus,
    SkillPackage,
    SkillPackageError,
    SkillPackageLoader,
    SkillPackageManifest,
)

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "AdmissionStatus",
    "CapabilityAdmissionService",
    "CapabilityDescriptor",
    "CapabilityKind",
    "CapabilityRequest",
    "EffectKind",
    "EffectiveCapability",
    "ExtensionDescriptor",
    "ExtensionDoctorReport",
    "ExtensionLifecycleState",
    "ExtensionPolicy",
    "ExtensionProvenance",
    "ExtensionRecord",
    "ExtensionRegistry",
    "ExtensionService",
    "ExtensionSource",
    "ExtensionSourceKind",
    "ExtensionType",
    "HookDescriptor",
    "HookDispatchReport",
    "HookDispatcher",
    "HookEvent",
    "HookFailure",
    "HookInvocation",
    "HookMode",
    "HookResult",
    "HookResultStatus",
    "HookToolRequest",
    "HttpxMcpTransport",
    "InvocationBinding",
    "McpCallResult",
    "McpDataResult",
    "McpError",
    "McpErrorCode",
    "McpLimits",
    "McpServerSession",
    "McpSessionState",
    "McpTransportKind",
    "ScriptedMcpTransport",
    "SkillActivation",
    "SkillActivationService",
    "SkillActivationStatus",
    "SkillPackage",
    "SkillPackageError",
    "SkillPackageLoader",
    "SkillPackageManifest",
    "validate_mcp_endpoint",
    "validate_redirect",
    "validate_resource_uri",
    "validate_stdio_configuration",
]
