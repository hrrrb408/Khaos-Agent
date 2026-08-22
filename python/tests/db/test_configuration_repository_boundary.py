"""Contract tests for the configuration persistence owner."""

from khaos.db import Database
from khaos.db.repositories.configuration import ConfigurationRepository


async def test_configuration_repository_scopes_modes_by_project(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    repository = ConfigurationRepository(db)

    await repository.set_config("ui", {"density": "compact"})
    await repository.set_principal_mode(
        "alice", "coding", project_id="project-a"
    )
    await repository.set_principal_mode(
        "alice", "office", project_id="project-b"
    )

    assert await repository.get_config("ui") == {"density": "compact"}
    assert (
        await repository.get_principal_mode(
            "alice", project_id="project-a", default="office"
        )
        == "coding"
    )
    assert (
        await repository.get_principal_mode(
            "alice", project_id="project-b", default="coding"
        )
        == "office"
    )
    assert (
        await repository.get_principal_mode(
            "alice", project_id="unknown", default="office"
        )
        == "office"
    )
    await db.close()
