from pathlib import Path

assert "from_env" in Path("settings.py").read_text(encoding="utf-8")
assert "validate" in Path("settings.py").read_text(encoding="utf-8")
assert "monkeypatch" in Path("tests/test_settings.py").read_text(encoding="utf-8")
assert "environment" in Path("service.py").read_text(encoding="utf-8")
