from pathlib import Path

text = Path("src/app.html").read_text(encoding="utf-8")
assert 'document.querySelector("#save-button")' in text
assert 'status.textContent = "Saved"' in text
assert 'role="status"' in text
