import re
from pathlib import Path

text = Path("counter.go").read_text(encoding="utf-8")
match = re.search(
    r"func\s+\(c\s+\*Counter\)\s+Decrement\s*\([^)]*\)\s*bool\s*\{(?P<body>.*?)\n\}",
    text,
    re.DOTALL,
)
assert match, "Counter.Decrement must remain a bool-returning method"
body = re.sub(r"//[^\n]*|/\*.*?\*/", "", match.group("body"), flags=re.DOTALL)

# Accept equivalent Go spellings while checking the behavior that matters:
# negative and overdraw attempts must be rejected without prescribing one
# exact formatting or boolean-expression layout.
assert re.search(r"\bdelta\s*<\s*0\b", body)
assert re.search(r"\bdelta\s*>\s*c\.balance\b|\bc\.balance\s*<\s*delta\b", body)
assert re.search(r"\breturn\s+false\b", body)
