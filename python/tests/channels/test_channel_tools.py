import pytest

from khaos.channels import ChannelRegistry, ChannelType
from khaos.tools import channel_tools


@pytest.mark.asyncio
async def test_channel_tools():
    assert len(channel_tools.CHANNEL_TOOLS) == 4
    channel_tools.set_channel_registry(None)
    assert (await channel_tools.channel_list())["status"] == "unavailable"
    registry = ChannelRegistry()
    registry.register("main", ChannelType.SLACK)
    channel_tools.set_channel_registry(registry)
    assert (await channel_tools.channel_list())["channels"][0]["id"] == "main"
    assert (await channel_tools.channel_disable("main"))["status"] == "disabled"
    assert (await channel_tools.channel_enable("main"))["status"] == "enabled"
