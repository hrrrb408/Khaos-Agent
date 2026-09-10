from pathlib import Path

repository = Path("src/repository.py").read_text(encoding="utf-8")
service = Path("src/service.py").read_text(encoding="utf-8")
assert "class RepositoryPort" in repository
assert "RepositoryPort" in service
assert "sqlite3" not in service
