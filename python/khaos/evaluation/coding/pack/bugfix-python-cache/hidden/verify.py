from pathlib import Path

text = Path("src/cache.py").read_text(encoding="utf-8")
assert "if key in self._values" in text
assert "return self._values[key]" in text
assert "or default" not in text
