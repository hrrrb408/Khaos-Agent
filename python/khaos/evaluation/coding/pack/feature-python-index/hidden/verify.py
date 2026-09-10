from pathlib import Path

index = Path("src/index.py").read_text(encoding="utf-8")
service = Path("src/service.py").read_text(encoding="utf-8")
assert "def lookup" in index
assert "startswith" in index
assert "lookup" in service
