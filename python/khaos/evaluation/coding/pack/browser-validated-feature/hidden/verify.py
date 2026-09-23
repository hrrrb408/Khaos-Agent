import re
from pathlib import Path

text = Path("src/app.html").read_text(encoding="utf-8")
# Accept either the original text-search control or an equivalent accessible
# filter form.  The task specifies behavior and accessibility, not a literal
# control id or DOM event spelling.
assert re.search(
    r"<(?:input|select)\b[^>]*(?:id|name)\s*=[\"'][^\"']*filter[^\"']*[\"'][^>]*>",
    text,
    flags=re.IGNORECASE | re.DOTALL,
)
assert re.search(r"addEventListener\(\s*[\"'](?:input|change)[\"']", text)
assert re.search(r"aria-live\s*=\s*[\"']polite[\"']", text, flags=re.IGNORECASE)
assert re.search(
    r"(?:role\s*=\s*[\"']status[\"']|id\s*=\s*[\"'][^\"']*(?:result|count|status)[^\"']*[\"'])",
    text,
    flags=re.IGNORECASE,
)
assert re.search(
    r"(?:textContent|innerText|innerHTML)\s*=\s*[^;\n]*(?:visible|filtered|shown|count|length)",
    text,
    flags=re.IGNORECASE,
)
