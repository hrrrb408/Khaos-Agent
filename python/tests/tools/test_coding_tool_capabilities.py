from khaos.tools.registry import create_runtime_registry


def test_every_coding_tool_declares_capability_and_scope():
    registry = create_runtime_registry()
    coding_tools = registry.list_by_mode("coding")
    assert coding_tools
    for tool in coding_tools:
        assert tool.capabilities, tool.name
        for capability in tool.capabilities:
            assert "coding" in capability.modes or "all" in capability.modes
            assert capability.scopes


def test_coding_process_and_write_tools_have_broker_enforceable_capabilities():
    registry = create_runtime_registry()
    for name in ("terminal", "test_run", "sandbox_exec", "write_file", "multi_edit"):
        capability_names = {capability.name for capability in registry.capabilities_for(name)}
        assert capability_names & {"process.execute", "filesystem.write"}
