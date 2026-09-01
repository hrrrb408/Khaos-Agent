from pathlib import Path

text = Path("src/config.ts").read_text(encoding="utf-8")
assert "input.enabled !== undefined" in text
assert "return input.enabled" in text
