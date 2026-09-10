from pathlib import Path

text = Path("src/app.html").read_text(encoding="utf-8")
assert 'id="filter"' in text
assert 'addEventListener("input"' in text
assert 'id="result-count"' in text
assert 'aria-live="polite"' in text
assert "visible.length" in text
