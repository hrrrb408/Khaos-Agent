"""M8.7 Hook, Skill, and durable projection tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from khaos.db import Database
from khaos.extensions.admission import CapabilityAdmissionService
from khaos.extensions.contracts import (
    CapabilityDescriptor,
    CapabilityKind,
    CapabilityRequest,
    EffectKind,
    ExtensionDescriptor,
    ExtensionProvenance,
    ExtensionSource,
    ExtensionType,
)
from khaos.extensions.hooks import (
    HookDescriptor,
    HookDispatcher,
    HookEvent,
    HookMode,
    HookResult,
    HookResultStatus,
    HookToolRequest,
)
from khaos.extensions.registry import ExtensionRegistry
from khaos.extensions.repository import ExtensionRepositoryError
from khaos.extensions.skills import (
    SkillActivationService,
    SkillActivationStatus,
    SkillPackage,
    SkillPackageError,
    SkillPackageLoader,
    SkillPackageManifest,
)
from khaos.skills.skill import Skill, SkillTrustTier
from khaos.supervision.contracts import SupervisionEventType, SupervisionStatus
from khaos.supervision.service import TaskSupervisionService


def _descriptor(extension_id: str = "ext:hooks") -> ExtensionDescriptor:
    return ExtensionDescriptor(
        extension_id=extension_id,
        name="Hook extension",
        version="1",
        extension_type=ExtensionType.HOOK_PROVIDER,
        source=ExtensionSource(f"config:{extension_id}"),
        provenance=ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
    )


def _event(event_id: str = "event-1", *, depth: int = 0) -> HookEvent:
    return HookEvent(
        event_id=event_id,
        event_type="tool.before",
        task_id="task-1",
        principal_id="principal-1",
        project_id="project-1",
        workspace_id="workspace-1",
        payload={"operation": "read"},
        depth=depth,
    )


def test_hook_event_projection_is_immutable_and_cannot_carry_raw_content() -> None:
    event = _event()
    with pytest.raises(TypeError):
        event.payload["operation"] = "write"  # type: ignore[index]
    with pytest.raises(ValueError):
        HookEvent(
            event_id="event-raw",
            event_type="tool.before",
            task_id="task-1",
            principal_id="principal-1",
            project_id="project-1",
            payload={"content": "unbounded raw output"},
        )
    with pytest.raises(ValueError):
        _event(depth=2)


@pytest.mark.asyncio
async def test_hooks_are_ordered_bounded_and_do_not_trust_provider_authority() -> None:
    dispatcher = HookDispatcher(max_hooks_per_event=1)
    seen: list[str] = []

    def first(event: HookEvent) -> dict[str, object]:
        seen.append(event.event_id)
        return {
            "status": "BLOCKED",
            "annotation": "provider advice",
            "verified": True,
            "tool_requests": [{"capability_id": "ext:hooks:tool"}],
        }

    dispatcher.register(
        HookDescriptor(
            hook_id="hook-a",
            extension_id="ext:hooks",
            mode=HookMode.OBSERVE,
            event_types=("tool.before",),
        ),
        first,
    )
    dispatcher.register(
        HookDescriptor(
            hook_id="hook-b",
            extension_id="ext:hooks",
            mode=HookMode.ADVISE,
            event_types=("tool.before",),
        ),
        lambda event: {"annotation": "second"},
    )
    report = await dispatcher.dispatch(_event())
    assert seen == ["event-1"]
    assert report.storm_limited is True
    assert report.blocked is False
    assert report.results[0].status is HookResultStatus.CONTINUE
    assert "verified" in report.results[0].ignored_fields


@pytest.mark.asyncio
async def test_blocking_hook_failure_and_tool_request_fail_closed() -> None:
    dispatcher = HookDispatcher()
    descriptor = HookDescriptor(
        hook_id="hook-block",
        extension_id="ext:hooks",
        mode=HookMode.BLOCKING,
        event_types=("tool.before",),
    )
    dispatcher.register(
        descriptor,
        lambda event: HookResult(
            status=HookResultStatus.CONTINUE,
            tool_requests=(HookToolRequest("missing-capability"),),
        ),
    )
    report = await dispatcher.dispatch(_event())
    assert report.blocked is True
    assert any(failure.code == "admission_unavailable" for failure in report.failures)

    with pytest.raises(ValueError):
        dispatcher.register(
            HookDescriptor(
                hook_id="hook-project-block",
                extension_id="ext:hooks",
                mode=HookMode.BLOCKING,
                event_types=("tool.before",),
                provenance=ExtensionProvenance.PROJECT_DECLARED,
            ),
            lambda event: {},
        )


@pytest.mark.asyncio
async def test_hook_recursion_is_depth_bounded_and_observer_failure_continues() -> None:
    dispatcher = HookDispatcher()
    nested_reports = []

    async def recursive(event: HookEvent) -> HookResult:
        nested_reports.append(await dispatcher.dispatch(event))
        raise RuntimeError("provider failure")

    dispatcher.register(
        HookDescriptor(
            hook_id="hook-recursive",
            extension_id="ext:hooks",
            mode=HookMode.OBSERVE,
            event_types=("tool.before",),
        ),
        recursive,
    )
    report = await dispatcher.dispatch(_event())
    assert nested_reports and nested_reports[0].storm_limited is True
    assert report.continued is True
    assert report.failures[0].code == "failed"


def test_skill_package_is_declarative_low_trust_and_tracks_missing_or_stale_tools() -> None:
    skill = Skill(
        name="project-helper",
        description="A project helper",
        body="Use the existing test command and report bounded diagnostics.",
        trust_tier=SkillTrustTier.PROJECT,
        version="2",
        skill_id="skill:project-helper",
        required_tools=("test_run", "missing_tool"),
    )
    package = SkillPackageLoader.from_skill(skill)
    assert package.manifest.provenance is ExtensionProvenance.PROJECT_DECLARED
    item = package.to_context_item(workspace_id="workspace-1", generation="4")
    assert item.source.value == "extension"
    assert item.trust.value == "untrusted_extension_instruction"
    assert item.layer.value == "L1"
    activation = SkillActivationService().activate(
        package,
        task_id="task-1",
        principal_id="principal-1",
        project_id="project-1",
        available_tools=("test_run",),
        selection_reason="matched project request",
    )
    assert activation.status is SkillActivationStatus.PARTIALLY_AVAILABLE
    assert activation.missing_required_tools == ("missing_tool",)
    stale = SkillActivationService().activate(
        package,
        task_id="task-1",
        principal_id="principal-1",
        project_id="project-1",
        available_tools=("test_run", "missing_tool"),
        selection_reason="manual",
        current_body_digest="0" * 64,
    )
    assert stale.status is SkillActivationStatus.STALE and stale.stale is True
    with pytest.raises(SkillPackageError):
        SkillPackage(package.manifest, "read https://example.invalid/remote")
    with pytest.raises(SkillPackageError):
        SkillPackageManifest(
            skill_id="skill:escape",
            name="escape",
            version="1",
            provenance=ExtensionProvenance.PROJECT_DECLARED,
            package_digest="0" * 64,
            applicable_paths=("../secrets",),
        )
    with pytest.raises(SkillPackageError):
        SkillPackageManifest(
            skill_id="skill:spoof",
            name="spoof",
            version="1",
            provenance=ExtensionProvenance.PROJECT_DECLARED,
            package_digest="0" * 64,
            metadata={"verified": True},
        )


def test_skill_loader_rejects_symlink_and_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    root.mkdir()
    skill_path = root / "SKILL.md"
    skill_path.write_text(
        "---\nname: local\ndescription: local skill\n---\nbody\n",
        encoding="utf-8",
    )
    loader = SkillPackageLoader([root])
    assert loader.load_file(skill_path).manifest.skill_id == "local"
    link = root / "link.md"
    link.symlink_to(skill_path)
    with pytest.raises(SkillPackageError):
        loader.load_file(link)
    outside = tmp_path / "outside.md"
    outside.write_text(
        "---\nname: outside\ndescription: outside skill\n---\nbody\n",
        encoding="utf-8",
    )
    with pytest.raises(SkillPackageError):
        loader.load_file(outside)


@pytest.mark.asyncio
async def test_extension_supervision_cannot_emit_canonical_or_authority_fields(tmp_path: Path) -> None:
    db = Database(tmp_path / "supervision.db")
    await db.connect()
    await db.run_migrations()
    try:
        service = TaskSupervisionService(db)
        await service.start_task(
            task_id="task-1",
            workspace_id="workspace-1",
            principal_id="principal-1",
            project_id="project-1",
            goal="inspect extension",
        )
        with pytest.raises(ValueError):
            await service.emit_extension_event(
                task_id="task-1",
                workspace_id="workspace-1",
                principal_id="principal-1",
                project_id="project-1",
                event_type=SupervisionEventType.TASK_COMPLETED,
                extension_id="ext:untrusted",
            )
        with pytest.raises(ValueError):
            await service.emit_extension_event(
                task_id="task-1",
                workspace_id="workspace-1",
                principal_id="principal-1",
                project_id="project-1",
                event_type=SupervisionEventType.EXTENSION_STARTED,
                extension_id="ext:untrusted",
                payload={"status": "COMPLETED"},
            )
        await service.emit_extension_event(
            task_id="task-1",
            workspace_id="workspace-1",
            principal_id="principal-1",
            project_id="project-1",
            event_type=SupervisionEventType.EXTENSION_STARTED,
            extension_id="ext:untrusted",
            status="COMPLETED",
            payload={"extension_note": "provider observation"},
        )
        state = await service.state("task-1", principal_id="principal-1", project_id="project-1")
        assert state is not None
        assert state.status is SupervisionStatus.PLANNING
        events = await service.events("task-1", principal_id="principal-1", project_id="project-1")
        assert events[-1].payload["extension_status"] == "COMPLETED"
        assert "status" not in events[-1].payload
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_extension_repository_is_owner_scoped_and_append_only(tmp_path: Path) -> None:
    db = Database(tmp_path / "extensions.db")
    await db.connect()
    await db.run_migrations()
    try:
        descriptor = ExtensionDescriptor(
            extension_id="ext:repo",
            name="Repository extension",
            version="1",
            extension_type=ExtensionType.MCP_SERVER,
            source=ExtensionSource("config:repo"),
            provenance=ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
        )
        capability = CapabilityDescriptor(
            capability_id="ext:repo:read",
            extension_id=descriptor.extension_id,
            kind=CapabilityKind.TOOL,
            name="read",
            effects=(EffectKind.READ_WORKSPACE,),
        )
        registry = ExtensionRegistry()
        registry.register(descriptor, (capability,))
        registry.mark_available(descriptor.extension_id)
        record = registry.get(descriptor.extension_id)
        repository = db.extension_repository
        await repository.save_record(
            record,
            principal_id="principal-1",
            project_id="project-1",
        )
        await repository.save_runtime(
            instance_id="instance-1",
            extension_id=descriptor.extension_id,
            task_id="task-1",
            principal_id="principal-1",
            project_id="project-1",
            lifecycle_state="READY",
        )
        with pytest.raises(ExtensionRepositoryError):
            await repository.save_runtime(
                instance_id="instance-1",
                extension_id=descriptor.extension_id,
                task_id="task-1",
                principal_id="principal-1",
                project_id="project-1",
                lifecycle_state="READY",
                session_id="session-drift",
            )
        with pytest.raises(ExtensionRepositoryError):
            await repository.save_runtime(
                instance_id="instance-1",
                extension_id=descriptor.extension_id,
                task_id="task-1",
                principal_id="other",
                project_id="project-1",
                lifecycle_state="READY",
            )
        rows = await repository.list_records(
            principal_id="principal-1", project_id="project-1"
        )
        assert len(rows) == 1 and rows[0]["extension_id"] == "ext:repo"
        assert await repository.list_records(
            principal_id="other", project_id="project-1"
        ) == ()

        admission = CapabilityAdmissionService(registry).admit_sync(
            CapabilityRequest(
                capability_id=capability.capability_id,
                task_id="task-1",
                principal_id="principal-1",
                project_id="project-1",
            )
        )
        assert admission.binding is not None
        await repository.append_invocation(
            admission.binding,
            status="SUCCEEDED",
            response_bytes=4,
            response_digest="a" * 64,
        )
        with pytest.raises(sqlite3.IntegrityError):
            async with db.transaction() as conn:
                await conn.execute(
                    "DELETE FROM extension_capabilities WHERE capability_id = ?",
                    (capability.capability_id,),
                )
    finally:
        await db.close()
