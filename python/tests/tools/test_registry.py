import pytest

from khaos.exceptions import ToolNotFoundError
from khaos.modes.manager import MODE_CONFIGS, Mode
from khaos.tools import (
    ToolDefinition,
    ToolCapability,
    ToolRegistry,
    create_builtin_registry,
    create_runtime_registry,
)


def test_capability_names_are_a_closed_typed_contract():
    with pytest.raises(ValueError):
        ToolCapability("filesystem.typo", frozenset({"coding"}), frozenset())


def test_registry_lists_tools_by_mode():
    registry = create_builtin_registry()

    assert {tool.name for tool in registry.list_by_mode("coding")} >= {
        "read_file",
        "write_file",
        "multi_edit",
        "terminal_argv",
        "terminal_shell",
        "todo_read",
        "todo_write",
        "todo_update",
    }
    assert {tool.name for tool in registry.list_by_mode("office")} >= {
        "read_file",
        "search_files",
    }


def test_every_builtin_tool_has_an_explicit_capability_manifest():
    registry = create_builtin_registry()

    assert all(tool.capabilities for tool in registry._tools.values())
    assert registry.get("web_fetch").capabilities[0].name == "network.access"
    assert registry.get("clipboard_read").capabilities[0].name == "host.clipboard.read"
    assert registry.get("quick_note").capabilities[0].name == "host.notes.write"
    assert registry.get("markdown_to_text").capabilities[0].name == "compute.local"


def test_production_schemas_are_closed_bounded_and_digest_stable():
    left = create_builtin_registry()
    right = create_builtin_registry()
    for tool in left._tools.values():
        assert tool.parameters["additionalProperties"] is False
        assert tool.schema_digest == right.get(tool.name).schema_digest
    assert not left.validate_call(
        "read_file", {"path": "README.md", "principal_id": "model-forged"}
    )
    assert not left.validate_call("read_file", {"path": "x" * 4097})
    assert not left.validate_call("terminal_argv", {"argv": []})
    assert left.validate_call("terminal_argv", {"argv": ["pytest", "-q"]})


def test_registry_get_missing_raises():
    registry = ToolRegistry()

    with pytest.raises(ToolNotFoundError):
        registry.get("missing")


def test_registry_supports_all_modes():
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="help",
            description="help",
            parameters={},
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )

    assert registry.list_by_mode("office")[0].name == "help"
    assert registry.list_by_mode("coding")[0].name == "help"


def test_registry_rejects_duplicate_names():
    registry = ToolRegistry()
    definition = ToolDefinition(
        name="help",
        description="help",
        parameters={},
        modes=["all"],
        permission_level="read",
        parallel=True,
    )
    registry.register(definition)

    with pytest.raises(ValueError):
        registry.register(definition)


@pytest.mark.parametrize("keyword", ["oneOf", "anyOf", "allOf", "format", "const"])
def test_production_registry_rejects_unsupported_schema_keywords(keyword):
    registry = ToolRegistry(
        enforce_capabilities=True,
        capability_manifest={
            "strict": (),
        },
    )
    definition = ToolDefinition(
        name="strict",
        description="strict",
        parameters={
            "type": "object",
            "properties": {
                "value": {"type": "string", keyword: "ignored-security-rule"},
            },
        },
        modes=["all"],
        permission_level="read",
        parallel=True,
        capabilities=(
            # A harmless explicit capability lets this test exercise schema
            # registration without involving a privileged resource resolver.
            create_builtin_registry().get("count_words").capabilities[0],
        ),
    )

    with pytest.raises(ValueError, match="unsupported JSON Schema keywords"):
        registry.register(definition)


def test_production_registry_rejects_invalid_nested_schema_contracts():
    registry = ToolRegistry(enforce_capabilities=True)
    capability = create_builtin_registry().get("count_words").capabilities

    with pytest.raises(ValueError, match="unknown properties"):
        registry.register(
            ToolDefinition(
                name="invalid-required",
                description="invalid",
                parameters={
                    "type": "object",
                    "properties": {},
                    "required": ["missing"],
                },
                modes=["all"],
                permission_level="read",
                parallel=True,
                capabilities=capability,
            )
        )

    with pytest.raises(ValueError, match="typed item schema is required"):
        registry.register(
            ToolDefinition(
                name="invalid-array",
                description="invalid",
                parameters={
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                },
                modes=["all"],
                permission_level="read",
                parallel=True,
                capabilities=capability,
            )
        )


def test_registry_validates_required_and_types():
    registry = create_builtin_registry()

    assert registry.validate_call("read_file", {"path": "a.txt", "limit": 10})
    assert not registry.validate_call("read_file", {"limit": 10})
    assert not registry.validate_call("read_file", {"path": "a.txt", "limit": "10"})
    assert registry.validate_call(
        "multi_edit",
        {"path": "a.txt", "edits": [{"old_text": "a", "new_text": "b"}]},
    )
    assert not registry.validate_call("multi_edit", {"path": "a.txt", "edits": "bad"})
    assert not registry.validate_call(
        "multi_edit",
        {"path": "a.txt", "edits": [{"old_text": "a"}]},
    )
    assert not registry.validate_call(
        "todo_update",
        {"todo_id": "task", "status": "blocked"},
    )


def test_registry_splits_parallel_and_serial_calls():
    registry = create_builtin_registry()

    parallel, serial = registry.get_parallel_tools(
        [
            {"id": "1", "name": "read_file", "arguments": {"path": "a.txt"}},
            {"id": "2", "name": "write_file", "arguments": {"path": "a.txt", "content": ""}},
        ]
    )

    assert [call["name"] for call in parallel] == ["read_file"]
    assert [call["name"] for call in serial] == ["write_file"]


def test_coding_mode_allows_multi_edit_and_todo_tools():
    allowed_tools = set(MODE_CONFIGS[Mode.CODING].allowed_tools)

    assert allowed_tools >= {"multi_edit", "todo_read", "todo_write", "todo_update"}


def test_runtime_registry_wires_new_tool_handlers():
    registry = create_runtime_registry()

    assert registry.get("multi_edit").handler is not None
    assert registry.get("todo_read").handler is not None
    assert registry.get("todo_write").handler is not None
    assert registry.get("todo_update").handler is not None


def test_gateway_view_exports_full_catalogue_with_schema_digest():
    """P1-2 (tool descriptor drift): gateway_view() exports the Python
    production registry's model-visible tools so the Go /api/tools endpoint
    is the runtime fact, not a hard-coded three-tool literal."""
    registry = create_runtime_registry()
    view = registry.gateway_view()
    names = {tool["name"] for tool in view}
    # The catalogue must include far more than the legacy hard-coded three.
    assert {"read_file", "write_file", "terminal_argv"} <= names
    assert len(names) > 30, f"expected a broad catalogue, got {len(names)}"
    # Every entry carries the four fields the Gateway needs.
    for tool in view:
        assert {"name", "modes", "permission_level", "schema_digest"} <= set(tool)
        assert tool["schema_digest"]  # non-empty digest


def test_gateway_view_schema_digest_matches_tool_definition():
    """The digest exported by gateway_view must equal the ToolDefinition's
    schema_digest so the Gateway can detect drift on the wire."""
    registry = create_runtime_registry()
    view = registry.gateway_view()
    for entry in view:
        tool = registry.get(entry["name"])
        assert entry["schema_digest"] == tool.schema_digest


# ---------------------------------------------------------------------------
# Batch 15.6: Typed Security Contracts (frozen ToolDefinition + security_digest)
# ---------------------------------------------------------------------------


def test_security_fields_are_frozen_after_registration():
    """Batch 15.6: after register() calls freeze(), mutating any security
    field raises PermissionError.  The tool's security contract is
    immutable for the lifetime of the registry."""
    registry = create_builtin_registry()
    tool = registry.get("read_file")

    security_fields = [
        "name", "parameters", "modes", "permission_level",
        "parallel", "timeout", "capabilities", "resource_resolver",
        "effect_status", "reconciliation_hint",
    ]
    for field_name in security_fields:
        # Use a sentinel value — the type doesn't matter, only that
        # setattr is rejected before it reaches object.__setattr__.
        with pytest.raises(PermissionError, match="frozen security field"):
            setattr(tool, field_name, None)


def test_handler_remains_mutable_after_registration():
    """Batch 15.6: ``handler`` is runtime wiring, NOT a security field.
    It must remain mutable after freeze() so create_runtime_registry()
    can wire up callables post-registration."""
    registry = create_builtin_registry()
    tool = registry.get("read_file")

    def new_handler(**kwargs):
        return {"ok": True}

    # This must NOT raise — handler is excluded from _SECURITY_FIELDS.
    tool.handler = new_handler
    assert tool.handler is new_handler


def test_security_digest_covers_more_than_schema_digest():
    """Batch 15.6: security_digest covers ALL security-relevant fields
    (capabilities, permission_level, modes, etc.), not just name +
    parameters.  Two tools with the same name+parameters but different
    capabilities must have different security_digests."""
    from khaos.tools.registry import ToolDefinition, ToolRegistry
    from khaos.permissions.resource import resolve_single_workspace_path

    cap_a = ToolCapability("filesystem.read", frozenset({"all"}), frozenset({"task-workspace"}))
    cap_b = ToolCapability("filesystem.write", frozenset({"all"}), frozenset({"task-workspace"}))

    def make_tool(caps):
        return ToolDefinition(
            name="test_tool",
            description="test",
            parameters={"type": "object", "properties": {}},
            modes=["coding"],
            permission_level="read",
            parallel=True,
            capabilities=caps,
        )

    reg_a = ToolRegistry(enforce_capabilities=False)
    reg_a.register(make_tool((cap_a,)))
    reg_b = ToolRegistry(enforce_capabilities=False)
    reg_b.register(make_tool((cap_b,)))

    tool_a = reg_a.get("test_tool")
    tool_b = reg_b.get("test_tool")

    # schema_digest is the same (name + parameters are identical)
    assert tool_a.schema_digest == tool_b.schema_digest
    # security_digest differs (capabilities differ)
    assert tool_a.security_digest != tool_b.security_digest


def test_security_digest_is_stable_across_instances():
    """Batch 15.6: security_digest is deterministic — two fresh registry
    instances produce the same digest for every tool."""
    left = create_builtin_registry()
    right = create_builtin_registry()
    for tool in left._tools.values():
        assert tool.security_digest == right.get(tool.name).security_digest


def test_security_digest_differs_from_schema_digest():
    """Batch 15.6: security_digest and schema_digest are different
    values because security_digest covers a broader set of fields."""
    registry = create_builtin_registry()
    for tool in registry._tools.values():
        # They COULD theoretically collide if the extra fields hash to
        # the same value, but in practice they never will because the
        # payload structure is different.
        assert tool.security_digest != tool.schema_digest, (
            f"{tool.name}: security_digest should differ from schema_digest"
        )


def test_gateway_view_exports_security_digest():
    """Batch 15.6: gateway_view() exports security_digest alongside
    schema_digest so the Go Gateway can detect full security contract
    drift, not just model-schema drift."""
    registry = create_runtime_registry()
    view = registry.gateway_view()
    for entry in view:
        assert "security_digest" in entry
        assert entry["security_digest"]  # non-empty
        tool = registry.get(entry["name"])
        assert entry["security_digest"] == tool.security_digest


def test_prune_shares_frozen_definitions():
    """Batch 15.6: prune() shares the same frozen ToolDefinition
    reference — mutations via the pruned registry are also prevented."""
    registry = create_builtin_registry()
    pruned = registry.prune(["read_file", "write_file"])
    tool = pruned.get("read_file")
    # The definition is frozen — mutation raises.
    with pytest.raises(PermissionError, match="frozen security field"):
        tool.permission_level = "execute"
