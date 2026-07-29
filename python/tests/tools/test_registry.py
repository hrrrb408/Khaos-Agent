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
