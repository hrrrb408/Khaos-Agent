from pathlib import Path

text = Path("counter.go").read_text(encoding="utf-8")
assert "if delta > c.balance" in text
assert "return false" in text
