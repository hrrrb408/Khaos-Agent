import pytest

from khaos.db import Database
from khaos.runtime import RuntimeConfig, build_runtime


async def test_factory_requires_db():
    with pytest.raises(ValueError, match="db"):
        await build_runtime(RuntimeConfig())


async def test_factory_wires_office_and_coding_runtime(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "runtime.db")
    await db.connect()
    await db.run_migrations()
    office = await build_runtime(RuntimeConfig(db=db, project_root=tmp_path))
    coding = await build_runtime(RuntimeConfig(db=db, project_root=tmp_path, mode_override="coding"))
    assert office.loop and office.tool_scheduler and office.task_manager is None
    assert coding.task_manager and coding.skill_generator and coding.new_verify_fix_loop
    assert coding.new_verify_fix_loop() is not coding.new_verify_fix_loop()
    await db.close()
