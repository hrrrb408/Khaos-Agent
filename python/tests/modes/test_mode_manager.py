from khaos.db import Database
from khaos.modes import Mode, ModeManager


async def test_switch_persists_current_mode(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    manager = ModeManager(db, project_root=tmp_path)

    mode = await manager.switch(Mode.CODING, intent_context="edit tests")

    assert mode is Mode.CODING
    assert await db.get_config("current_mode") == "coding"
    await db.close()


async def test_detect_and_suggest_does_not_switch(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    manager = ModeManager(db, project_root=tmp_path)

    suggested = await manager.detect_and_suggest("please edit app.py")

    assert suggested is Mode.CODING
    assert manager.current_mode is Mode.OFFICE
    await db.close()

