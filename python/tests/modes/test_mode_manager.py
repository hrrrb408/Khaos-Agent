from khaos.db import Database
from khaos.modes import Mode, ModeManager


async def test_switch_persists_current_mode(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    manager = ModeManager(db, project_root=tmp_path)

    mode = await manager.switch(Mode.CODING, intent_context="edit tests")

    assert mode is Mode.CODING
    # A2-5: mode is now persisted in principal_modes (not user_config).
    # The default ModeManager uses principal_id='legacy', session_id=''.
    assert await db.get_principal_mode("legacy", "") == "coding"
    # user_config is no longer used for mode storage.
    assert await db.get_config("current_mode") is None
    await db.close()


async def test_switch_is_principal_scoped(tmp_path):
    """A2-5: switching mode for one principal does not affect another."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    alice = ModeManager(db, project_root=tmp_path, principal_id="alice")
    bob = ModeManager(db, project_root=tmp_path, principal_id="bob")

    await alice.switch(Mode.CODING)
    await bob.switch(Mode.OFFICE)

    # Reload and verify isolation.
    alice2 = ModeManager(db, project_root=tmp_path, principal_id="alice")
    bob2 = ModeManager(db, project_root=tmp_path, principal_id="bob")
    assert (await alice2.load()) is Mode.CODING
    assert (await bob2.load()) is Mode.OFFICE
    await db.close()


async def test_session_override_beats_principal_default(tmp_path):
    """A2-5: session-specific mode override wins over principal default."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    # Principal default: CODING.
    principal_default = ModeManager(
        db, project_root=tmp_path, principal_id="alice", session_id="",
    )
    await principal_default.switch(Mode.CODING)
    # Session override: OFFICE.
    session_override = ModeManager(
        db, project_root=tmp_path, principal_id="alice", session_id="sess-1",
    )
    await session_override.switch(Mode.OFFICE)

    # A new manager for (alice, sess-1) should load the session override.
    reloaded = ModeManager(
        db, project_root=tmp_path, principal_id="alice", session_id="sess-1",
    )
    assert (await reloaded.load()) is Mode.OFFICE

    # A new manager for (alice, '') should still load the principal default.
    principal_reload = ModeManager(
        db, project_root=tmp_path, principal_id="alice", session_id="",
    )
    assert (await principal_reload.load()) is Mode.CODING
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

