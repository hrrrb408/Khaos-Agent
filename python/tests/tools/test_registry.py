import pytest

from khaos.exceptions import ToolNotFoundError
from khaos.tools import ToolDefinition, ToolRegistry, create_builtin_registry


def test_registry_lists_tools_by_mode():
    registry = create_builtin_registry()

    assert {tool.name for tool in registry.list_by_mode("coding")} >= {
        "read_file",
        "write_file",
        "terminal",
    }
    assert {tool.name for tool in registry.list_by_mode("office")} >= {
        "read_file",
        "search_files",
    }


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


def test_registry_validates_required_and_types():
    registry = create_builtin_registry()

    assert registry.validate_call("read_file", {"path": "a.txt", "limit": 10})
    assert not registry.validate_call("read_file", {"limit": 10})
    assert not registry.validate_call("read_file", {"path": "a.txt", "limit": "10"})


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
