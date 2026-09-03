import json
from types import SimpleNamespace

import pytest
from khaos.agent.control.completion_flow import CompletionProposalController
from khaos.agent.control.completion_recovery import CompletionRecoveryService
from khaos.coding.context_engine import ContextEngineService
from khaos.db import Database
from khaos.runtime import RuntimeConfig, build_runtime
from khaos.security.effective_policy import load_effective_policy
from khaos.security.resource_scope import TypedResourcePartialOrder


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
    assert isinstance(coding.context_engine, ContextEngineService)
    assert coding.loop.context_engine is coding.context_engine
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

    # Production startup now reaches router construction only after the
    # independently loaded catalog and READY authority channel pass.  Supply
    # those trusted inputs through narrow test doubles so this regression
    # continues to exercise the no-mock-router fallback itself.
    effective_policy = load_effective_policy(tmp_path)
    assert effective_policy.resource_order is not None
    catalog_path = tmp_path / "typed-resource-catalog.json"
    catalog_path.write_text(
        json.dumps(effective_policy.resource_order.manifest()), encoding="utf-8"
    )
    catalog_path.chmod(0o640)
    monkeypatch.setenv("KHAOS_TYPED_RESOURCE_CATALOG_PATH", str(catalog_path))
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "native-production")
    # The catalog reader's real Windows ACL contract is exercised by the
    # native deployment workflow.  This regression is narrower: it verifies
    # that a production runtime never falls back to a mock router.  Retain
    # the real catalog parser and only omit the deployment-only ACL check so
    # a pytest temp directory is not mistaken for a provisioned trust root.
    def load_test_catalog(policy, profile, *, preloaded=None):
        assert profile.is_production
        if preloaded is not None:
            return preloaded
        return TypedResourcePartialOrder.from_json_file(
            catalog_path,
            expected_policy_digest=policy.digest if policy is not None else None,
            require_windows_acl=False,
        )

    monkeypatch.setattr(
        "khaos.runtime.factory._load_production_resource_order",
        load_test_catalog,
    )
    authority = SimpleNamespace(
        ready=True,
        trust_binding=SimpleNamespace(
            policy_digest=effective_policy.digest,
            catalog_semantic_digest=effective_policy.resource_order.catalog_semantic_digest,
        ),
        close=lambda: None,
    )
    monkeypatch.setattr(
        "khaos.runtime.factory.AuthorityBroker.for_production",
        classmethod(lambda _cls, **_kwargs: authority),
    )
    monkeypatch.setattr("khaos.rpc.composition.load_router_from_config", unavailable)
    with pytest.raises(ValueError, match="invalid model configuration"):
        await build_runtime(
            RuntimeConfig(
                db=db,
                project_root=tmp_path,
                principal_id="local-uid:test",
                source_transport="tui",
            )
        )
    await db.close()
