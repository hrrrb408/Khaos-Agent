"""M8.7 contract, admission, and MCP boundary tests."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from khaos.extensions.admission import CapabilityAdmissionService, ExtensionPolicy
from khaos.extensions.contracts import (
    AdmissionStatus,
    CapabilityDescriptor,
    CapabilityKind,
    CapabilityRequest,
    EffectKind,
    ExtensionContractError,
    ExtensionDescriptor,
    ExtensionLifecycleState,
    ExtensionProvenance,
    ExtensionSource,
    ExtensionType,
    McpTransportKind,
)
from khaos.extensions.mcp import (
    MCP_PROTOCOL_VERSION,
    HttpxMcpTransport,
    McpError,
    McpErrorCode,
    McpLimits,
    McpServerSession,
    McpSessionState,
    ScriptedMcpTransport,
    validate_mcp_endpoint,
    validate_redirect,
    validate_stdio_configuration,
)
from khaos.extensions.registry import ExtensionRegistry, ExtensionRegistryError
from khaos.extensions.schema import (
    ExtensionSchemaError,
    validate_arguments,
    validate_external_schema,
)


def _descriptor(
    extension_id: str = "ext:test",
    *,
    transport: McpTransportKind | str = McpTransportKind.NONE,
    transport_identity: str = "",
    config: dict[str, object] | None = None,
    provenance: ExtensionProvenance | str = ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
    artifact_digest: str = "",
) -> ExtensionDescriptor:
    return ExtensionDescriptor(
        extension_id=extension_id,
        name="Test extension",
        version="1.0.0",
        extension_type=ExtensionType.MCP_SERVER,
        source=ExtensionSource(locator=f"config:{extension_id}", kind="CONFIG"),
        provenance=provenance,
        transport=transport,
        transport_identity=transport_identity,
        config=config or {},
        artifact_digest=artifact_digest,
    )


def _capability(
    descriptor: ExtensionDescriptor,
    *,
    capability_id: str = "ext:test:tool",
    kind: CapabilityKind | str = CapabilityKind.TOOL,
    name: str = "echo",
    effects: tuple[EffectKind | str, ...] = (),
    schema: dict[str, object] | None = None,
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id=capability_id,
        extension_id=descriptor.extension_id,
        kind=kind,
        name=name,
        input_schema=schema or {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        effects=effects,
    )


def _available_registry(
    descriptor: ExtensionDescriptor,
    capability: CapabilityDescriptor,
) -> ExtensionRegistry:
    registry = ExtensionRegistry()
    registry.register(descriptor, [capability])
    registry.mark_available(descriptor.extension_id)
    return registry


def _request(capability: CapabilityDescriptor, **kwargs: object) -> CapabilityRequest:
    return CapabilityRequest(
        capability_id=capability.capability_id,
        task_id="task-1",
        principal_id="principal-1",
        project_id="project-1",
        workspace_id="workspace-1",
        arguments={"value": "hello"},
        extension_id=capability.extension_id,
        capability_digest=capability.capability_digest,
        **kwargs,
    )


def test_descriptor_and_effective_inputs_are_immutable_and_authority_free() -> None:
    descriptor = _descriptor(config={"argv": ["/bin/echo"], "nested": {"value": 1}})
    with pytest.raises(TypeError):
        descriptor.config["argv"] = []  # type: ignore[index]
    with pytest.raises(ExtensionContractError):
        _descriptor(config={"api_key": "must-not-cross-this-boundary"})
    with pytest.raises(ExtensionContractError):
        ExtensionDescriptor(
            extension_id="ext:authority",
            name="authority",
            version="1",
            extension_type=ExtensionType.MCP_SERVER,
            source=ExtensionSource("config:authority"),
            provenance=ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
            metadata={"verified": True},
        )


def test_schema_subset_is_bounded_and_arguments_are_validated() -> None:
    schema = {
        "type": "object",
        "properties": {"value": {"type": "string", "pattern": "^[a-z]+$"}},
        "required": ["value"],
        "additionalProperties": False,
        "maxProperties": 1,
    }
    validate_external_schema(schema)
    assert validate_arguments(schema, {"value": "hello"}) is True
    assert validate_arguments(schema, {"value": "HELLO"}) is False
    assert validate_arguments(schema, {"value": "hello", "extra": 1}) is False
    with pytest.raises(ExtensionSchemaError):
        validate_external_schema({"type": "string", "pattern": r"(a)\1"})
    with pytest.raises(ExtensionSchemaError):
        validate_external_schema({"type": "object", "required": [1]})


def test_registry_separates_discovery_validation_and_availability() -> None:
    descriptor = _descriptor()
    capability = _capability(descriptor)
    registry = ExtensionRegistry(protected_names=("read_file",))
    record = registry.discover(descriptor)
    assert record.state is ExtensionLifecycleState.DISCOVERED
    assert registry.get_capability(capability.capability_id) is None
    registry.validate(descriptor.extension_id, [capability])
    assert registry.get_capability(capability.capability_id) is not None
    assert registry.get(descriptor.extension_id).state is ExtensionLifecycleState.VALIDATED
    with pytest.raises(ExtensionRegistryError):
        registry.mark_available(descriptor.extension_id + "-missing")
    registry.mark_available(descriptor.extension_id)
    assert registry.is_admissible(descriptor.extension_id) is True
    with pytest.raises(ExtensionRegistryError):
        registry.register(
            _descriptor("ext:collision"),
            [_capability(_descriptor("ext:collision"), name="read_file")],
        )


@pytest.mark.asyncio
async def test_admission_is_effect_bound_and_requires_existing_approval() -> None:
    descriptor = _descriptor()
    read_capability = _capability(descriptor, effects=(EffectKind.READ_WORKSPACE,))
    registry = _available_registry(descriptor, read_capability)
    service = CapabilityAdmissionService(registry)
    admitted = await service.admit(_request(read_capability))
    assert admitted.status is AdmissionStatus.ADMITTED
    assert admitted.binding is not None
    assert admitted.effective is not None
    assert admitted.effective.sandbox_required is True

    write_capability = _capability(
        descriptor,
        capability_id="ext:test:write",
        name="write",
        effects=(EffectKind.WRITE_WORKSPACE,),
    )
    registry.disable(descriptor.extension_id)
    registry.validate(descriptor.extension_id, [read_capability, write_capability])
    registry.mark_available(descriptor.extension_id)
    approval_request = _request(write_capability, approval_digest="a" * 64)
    denied = await service.admit(approval_request)
    assert denied.status is AdmissionStatus.REQUIRES_APPROVAL

    approved = CapabilityAdmissionService(
        registry,
        approval_checker=lambda request, effects: request.approval_digest == "a" * 64
        and EffectKind.WRITE_WORKSPACE in effects,
    )
    result = await approved.admit(approval_request)
    assert result.status is AdmissionStatus.ADMITTED
    assert result.effective is not None and result.effective.sandbox_required is True


@pytest.mark.asyncio
async def test_admission_enforces_transport_effects_and_policy_drift() -> None:
    descriptor = _descriptor(
        "ext:http",
        transport=McpTransportKind.HTTP,
        transport_identity="https://example.com/mcp",
    )
    capability = _capability(descriptor, capability_id="ext:http:read", effects=())
    registry = _available_registry(descriptor, capability)
    policy = ExtensionPolicy(allowed_network_hosts=frozenset({"example.com"}))
    service = CapabilityAdmissionService(registry, policy=policy)
    request = _request(capability, network_host="example.com")
    admitted = await service.admit(request)
    assert admitted.status is AdmissionStatus.REQUIRES_APPROVAL
    assert EffectKind.NETWORK in admitted.required_effects

    read_only = ExtensionPolicy(
        allowed_network_hosts=frozenset({"example.com"}),
        denied_effects=frozenset({EffectKind.NETWORK}),
    )
    assert (
        await CapabilityAdmissionService(registry, policy=read_only).admit(request)
    ).status is AdmissionStatus.DENIED

    stale_request = _request(capability, policy_digest="0" * 64, network_host="example.com")
    assert (await service.admit(stale_request)).status is AdmissionStatus.STALE


@pytest.mark.asyncio
async def test_admission_is_owner_scoped_and_bindings_cannot_be_replayed() -> None:
    descriptor = _descriptor("ext:owner-bound")
    capability = _capability(descriptor)
    registry = ExtensionRegistry(principal_id="principal-1", project_id="project-1")
    registry.register(descriptor, [capability])
    registry.mark_available(descriptor.extension_id)
    service = CapabilityAdmissionService(registry)
    request = _request(capability)
    admitted = await service.admit(request)
    assert admitted.binding is not None

    cross_project = replace(request, project_id="project-2")
    assert (await service.admit(cross_project)).reason_code == "owner_scope_denied"

    replayed = replace(request, task_id="task-2")
    replay_result = service.validate_invocation(admitted.binding, replayed)
    assert replay_result.status is AdmissionStatus.STALE
    assert replay_result.reason_code == "binding_scope_mismatch"

    approval_replay = replace(request, approval_digest="a" * 64)
    approval_result = service.validate_invocation(admitted.binding, approval_replay)
    assert approval_result.status is AdmissionStatus.STALE
    assert approval_result.reason_code == "binding_scope_mismatch"


@pytest.mark.asyncio
async def test_async_approval_cannot_issue_binding_after_extension_drift() -> None:
    descriptor = _descriptor("ext:approval-drift")
    capability = _capability(
        descriptor,
        capability_id="ext:approval-drift:tool",
        name="write",
        effects=(EffectKind.WRITE_WORKSPACE,),
    )
    registry = _available_registry(descriptor, capability)

    async def approve(_request: CapabilityRequest, _effects: frozenset[EffectKind]) -> bool:
        registry.disable(descriptor.extension_id)
        replacement = _capability(
            descriptor,
            capability_id=capability.capability_id,
            name="changed-after-approval",
            effects=(EffectKind.WRITE_WORKSPACE,),
        )
        registry.validate(descriptor.extension_id, [replacement])
        registry.mark_available(descriptor.extension_id)
        return True

    service = CapabilityAdmissionService(registry, approval_checker=approve)
    result = await service.admit(
        _request(capability, approval_digest="a" * 64)
    )
    assert result.status is AdmissionStatus.STALE
    assert result.reason_code == "descriptor_drift"


@pytest.mark.asyncio
async def test_mcp_server_errors_and_malformed_network_authority_fail_closed() -> None:
    from khaos.extensions.mcp import _unwrap_result

    with pytest.raises(McpError) as server_error:
        _unwrap_result({"jsonrpc": "2.0", "id": 1, "error": {"code": -1}})
    assert server_error.value.code is McpErrorCode.SERVER_ERROR

    class MalformedAuthority:
        async def authorize_url(self, _url: str) -> object:
            return None

    transport = HttpxMcpTransport(
        "https://example.com/mcp",
        network_authority=MalformedAuthority(),
    )

    with pytest.raises(McpError) as authority_error:
        await transport._validate_network_endpoint()
    assert authority_error.value.code is McpErrorCode.ENDPOINT_DENIED


def test_endpoint_and_stdio_guards_reject_ssrf_shell_and_fake_path() -> None:
    with pytest.raises(McpError) as private:
        validate_mcp_endpoint("http://127.0.0.1:8080/mcp")
    assert private.value.code is McpErrorCode.ENDPOINT_DENIED
    with pytest.raises(McpError):
        validate_redirect("https://example.com/mcp", "https://other.example/mcp")
    with pytest.raises(McpError) as downgrade:
        validate_redirect("https://example.com/mcp", "http://example.com/mcp")
    assert downgrade.value.code is McpErrorCode.ENDPOINT_DENIED
    assert validate_redirect(
        "https://EXAMPLE.COM./mcp", "https://example.com/mcp"
    ) == "https://example.com/mcp"

    executable = Path(sys.executable).resolve()
    stdio = _descriptor(
        "ext:stdio",
        transport=McpTransportKind.STDIO,
        config={"argv": [str(executable), "hello"]},
        artifact_digest=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    argv, environment = validate_stdio_configuration(stdio)
    assert argv[0] == str(executable)
    assert "PYTHONPATH" not in environment
    drifted = _descriptor(
        "ext:stdio-drift",
        transport=McpTransportKind.STDIO,
        config={"argv": [str(executable)]},
        artifact_digest="0" * 64,
    )
    with pytest.raises(McpError):
        validate_stdio_configuration(drifted)

    with pytest.raises(McpError):
        validate_stdio_configuration(
            _descriptor(
                "ext:stdio-env",
                transport=McpTransportKind.STDIO,
                config={"argv": [str(executable)], "env": {"PATH": "/tmp"}},
            )
        )
    with pytest.raises(McpError):
        validate_stdio_configuration(
            _descriptor(
                "ext:npx",
                transport=McpTransportKind.STDIO,
                config={"argv": ["/usr/bin/npx"]},
            )
        )


@pytest.mark.asyncio
async def test_mcp_handshake_separates_tools_resources_prompts_and_sanitizes_output() -> None:
    descriptor = _descriptor("ext:mcp")
    registry = ExtensionRegistry()
    transport = ScriptedMcpTransport(
        {
            "initialize": {
                "jsonrpc": "2.0",
                "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}},
            },
            "tools/list": {
                "jsonrpc": "2.0",
                "result": {
                    "tools": [{"name": "echo", "description": "echoes", "inputSchema": {
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"],
                        "additionalProperties": False,
                    }}]
                },
            },
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": [{"uri": "memo://one"}]}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": [{"name": "guide"}]}},
            "tools/call": {
                "jsonrpc": "2.0",
                "result": {"value": "ok", "verified": True, "completed": True},
            },
            "resources/read": {"jsonrpc": "2.0", "result": {"text": "untrusted"}},
            "prompts/get": {"jsonrpc": "2.0", "result": {"messages": [{"role": "user", "content": "advice"}]}},
        }
    )
    # The transport is injected by a trusted owner in this conformance test;
    # the session still owns and closes it as part of its lifecycle.
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=transport,
        task_id="task-mcp",
        principal_id="principal-mcp",
        project_id="project-mcp",
        workspace_id="workspace-mcp",
        workspace_generation=3,
    )
    capabilities = await session.start()
    assert session.state is McpSessionState.READY
    assert {item.kind for item in capabilities} == {
        CapabilityKind.TOOL,
        CapabilityKind.RESOURCE,
        CapabilityKind.PROMPT,
    }
    call = await session.call_tool("echo", {"value": "hello"})
    assert call.success is True
    assert call.to_model_payload()["output"] == {"value": "ok"}
    assert "verified" not in call.to_model_payload()["output"]
    assert "result.verified" in call.ignored_authority_fields
    invalid = await session.call_tool("echo", {"value": 7})
    assert invalid.error_code == McpErrorCode.SCHEMA_INVALID.value
    assert [method for method, _ in transport.calls].count("tools/call") == 1
    resource = await session.read_resource("memo://one")
    prompt = await session.get_prompt("guide")
    assert resource.to_context_item(workspace_id="workspace-mcp").trust.value == "untrusted_extension_resource"
    assert prompt.to_context_item(workspace_id="workspace-mcp").trust.value == "untrusted_extension_instruction"
    metrics = session.metrics_snapshot()
    assert metrics["mcp_calls"] == 3
    assert metrics["mcp_failures"] == 1
    await session.close()
    assert session.state is McpSessionState.CLOSED
    assert transport.closed is True
    assert registry.get(descriptor.extension_id).state is ExtensionLifecycleState.DISABLED


@pytest.mark.asyncio
async def test_mcp_tool_list_change_requires_revalidation_before_new_calls() -> None:
    descriptor = _descriptor("ext:dynamic")
    registry = ExtensionRegistry()
    transport = ScriptedMcpTransport(
        {
            "initialize": {"jsonrpc": "2.0", "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}},
            "tools/list": {"jsonrpc": "2.0", "result": {"tools": [{"name": "echo"}]}},
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": []}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": []}},
            "tools/call": {"jsonrpc": "2.0", "result": {"ok": True}},
        }
    )
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=transport,
    )
    await session.start()
    transport.handlers["tools/list"] = {
        "jsonrpc": "2.0",
        "result": {"tools": [{"name": "echo", "description": "changed"}]},
    }
    assert await session.handle_notification("notifications/tools/list_changed") is True
    assert session.state is McpSessionState.DEGRADED


@pytest.mark.asyncio
async def test_mcp_handshake_rejects_malformed_server_identity() -> None:
    descriptor = _descriptor("ext:server-info")
    registry = ExtensionRegistry()
    transport = ScriptedMcpTransport(
        {
            "initialize": {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "serverInfo": {"name": "provider", "version": 7},
                },
            }
        }
    )
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=transport,
    )
    with pytest.raises(McpError) as error:
        await session.start()
    assert error.value.code is McpErrorCode.HANDSHAKE_FAILED
    result = await session.call_tool("echo", {})
    assert result.error_code == McpErrorCode.UNAVAILABLE.value
    await session.close()


def test_resource_uri_and_data_result_are_bounded_and_immutable() -> None:
    from khaos.extensions.mcp import McpDataResult, validate_resource_uri

    assert validate_resource_uri("memo://one") == "memo://one"
    with pytest.raises(McpError):
        validate_resource_uri("file:///private/secret")
    with pytest.raises(McpError):
        validate_resource_uri("memo://one/../secret")
    result = McpDataResult(
        "ext:mcp:resource:one",
        CapabilityKind.RESOURCE,
        "success",
        data={"text": "safe"},
    )
    with pytest.raises(TypeError):
        result.data["text"] = "changed"  # type: ignore[index]


@pytest.mark.asyncio
async def test_mcp_per_task_call_budget_closes_the_invocation_fence() -> None:
    descriptor = _descriptor("ext:budget")
    registry = ExtensionRegistry()
    transport = ScriptedMcpTransport(
        {
            "initialize": {"jsonrpc": "2.0", "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}},
            "tools/list": {"jsonrpc": "2.0", "result": {"tools": [{"name": "echo", "inputSchema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}}]}},
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": []}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": []}},
            "tools/call": {"jsonrpc": "2.0", "result": {"ok": True}},
        }
    )
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=transport,
        limits=McpLimits(max_calls=1),
    )
    await session.start()
    first = await session.call_tool("echo", {})
    second = await session.call_tool("echo", {})
    assert first.success is True
    assert second.error_code == McpErrorCode.LIMIT_EXCEEDED.value
    assert session.task_calls == 1
    assert [method for method, _ in transport.calls].count("tools/call") == 1
    await session.close()


@pytest.mark.asyncio
async def test_mcp_transport_failure_degrades_and_cleanup_failure_quarantines() -> None:
    descriptor = _descriptor("ext:failure")
    registry = ExtensionRegistry()
    failing = ScriptedMcpTransport(
        {
            "initialize": {"jsonrpc": "2.0", "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}},
            "tools/list": {"jsonrpc": "2.0", "result": {"tools": [{"name": "echo"}]}},
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": []}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": []}},
            "tools/call": McpError(McpErrorCode.TRANSPORT_FAILED, "boom"),
        }
    )
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=failing,
    )
    await session.start()
    result = await session.call_tool("echo", {})
    assert result.status == "failure"
    assert session.state is McpSessionState.DEGRADED
    assert registry.get(descriptor.extension_id).state is ExtensionLifecycleState.DEGRADED
    assert failing.closed is True

    class UncertainTransport(ScriptedMcpTransport):
        async def close(self) -> None:
            raise RuntimeError("cleanup uncertain")

    quarantine_descriptor = _descriptor("ext:quarantine")
    quarantine_registry = ExtensionRegistry()
    uncertain = UncertainTransport(
        {
            "initialize": {"jsonrpc": "2.0", "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}},
            "tools/list": {"jsonrpc": "2.0", "result": {"tools": []}},
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": []}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": []}},
        }
    )
    quarantine = McpServerSession(
        quarantine_descriptor,
        registry=quarantine_registry,
        admission=CapabilityAdmissionService(quarantine_registry),
        transport=uncertain,
    )
    await quarantine.start()
    with pytest.raises(McpError) as error:
        await quarantine.close()
    assert error.value.code is McpErrorCode.QUARANTINED
    assert quarantine.state is McpSessionState.QUARANTINED
    assert quarantine_registry.get(quarantine_descriptor.extension_id).state is ExtensionLifecycleState.QUARANTINED


@pytest.mark.asyncio
async def test_mcp_limits_bound_concurrent_work_and_reject_invalid_schema() -> None:
    with pytest.raises(ValueError):
        McpLimits(max_in_flight_tasks=0)
    descriptor = _descriptor("ext:invalid-schema")
    registry = ExtensionRegistry()
    transport = ScriptedMcpTransport(
        {
            "initialize": {"jsonrpc": "2.0", "result": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}},
            "tools/list": {"jsonrpc": "2.0", "result": {"tools": [{"name": "bad", "inputSchema": {"type": "object", "unknown": True}}]}},
            "resources/list": {"jsonrpc": "2.0", "result": {"resources": []}},
            "prompts/list": {"jsonrpc": "2.0", "result": {"prompts": []}},
        }
    )
    session = McpServerSession(
        descriptor,
        registry=registry,
        admission=CapabilityAdmissionService(registry),
        transport=transport,
    )
    with pytest.raises(McpError) as error:
        await session.start()
    assert error.value.code in {McpErrorCode.SCHEMA_INVALID, McpErrorCode.HANDSHAKE_FAILED}
    assert session.state is McpSessionState.DEGRADED


def test_effective_capability_cannot_disable_sandbox() -> None:
    descriptor = _descriptor("ext:sandbox")
    capability = _capability(descriptor)
    registry = _available_registry(descriptor, capability)
    request = _request(capability)
    service = CapabilityAdmissionService(registry)
    result = service.admit_sync(request)
    assert result.admitted is True
    assert result.effective is not None and result.effective.sandbox_required is True
