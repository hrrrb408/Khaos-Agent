import pytest
from khaos.agent.control.completion_flow import CompletionProposalController
from khaos.agent.control.completion_recovery import CompletionRecoveryService
from khaos.db import Database
from khaos.runtime import RuntimeConfig, build_runtime


async def test_factory_requires_db():
    with pytest.raises(ValueError, match="db"):
        await build_runtime(RuntimeConfig())


@pytest.mark.posix_host
async def test_factory_wires_office_and_coding_runtime(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "runtime.db")
    await db.connect()
    await db.run_migrations()
    office = await build_runtime(RuntimeConfig(db=db, project_root=tmp_path, principal_id="local-uid:test"))
    coding = await build_runtime(RuntimeConfig(db=db, project_root=tmp_path, mode_override="coding", principal_id="local-uid:test"))
    assert office.loop and office.tool_scheduler and office.task_manager is not None
    assert coding.task_manager and coding.skill_generator and coding.new_verify_fix_loop
    assert isinstance(coding.loop.completion_controller, CompletionProposalController)
    assert isinstance(coding.loop.completion_recovery, CompletionRecoveryService)
    assert coding.new_verify_fix_loop() is not coding.new_verify_fix_loop()
    await db.close()


async def test_factory_rejects_mock_router_outside_explicit_dev_mode(
    tmp_path, monkeypatch,
):
    db = Database(tmp_path / "runtime.db")
    await db.connect()
    await db.run_migrations()
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)

    def unavailable(*_args, **_kwargs):
        raise ValueError("invalid model configuration")

    monkeypatch.setattr("khaos.rpc.composition.load_router_from_config", unavailable)
    with pytest.raises(ValueError, match="invalid model configuration"):
        await build_runtime(
            RuntimeConfig(
                db=db,
                project_root=tmp_path,
                principal_id="local-uid:test",
            )
        )
    await db.close()
