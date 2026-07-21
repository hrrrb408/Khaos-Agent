from khaos.db import Database
from khaos.runtime import RuntimeConfig, build_runtime


async def test_office_to_coding_switch_enables_per_turn_components(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "switch.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("switch")
    runtime = await build_runtime(RuntimeConfig(db=db, project_root=tmp_path, principal_id="local-uid:test"))
    assert runtime.task_manager is not None
    assert runtime.loop.verify_fix_loop is None
    await runtime.mode_manager.switch(runtime.mode_manager.parse("coding"))
    _events = [event async for event in runtime.loop.run("hello", "switch")]
    assert runtime.loop.verify_fix_loop is not None
    await runtime.aclose()
    await db.close()
