import re
from pathlib import Path

text = Path("src/config.ts").read_text(encoding="utf-8")
match = re.search(
    r"function\s+readEnabled\s*\([^)]*\)[^{]*\{(?P<body>.*?)\n\}",
    text,
    re.DOTALL,
)
assert match, "readEnabled must remain an exported function"
body = re.sub(r"//[^\n]*|/\*.*?\*/", "", match.group("body"), flags=re.DOTALL)

# Nullish coalescing and explicit undefined checks are behaviorally equivalent
# for this contract.  Reject the original truthiness fallback implicitly by
# requiring a bounded, false-preserving form rather than one literal spelling.
false_preserving = (
    re.search(r"\binput\.enabled\s*\?\?\s*true\b", body)
    or (
        re.search(r"\binput\.enabled\s*!==\s*undefined\b", body)
        and re.search(r"\breturn\s+input\.enabled\b", body)
    )
    or re.search(
        r"\binput\.enabled\s*===\s*undefined\s*\?\s*true\s*:\s*input\.enabled\b",
        body,
    )
    or re.search(
        r"\btypeof\s+input\.enabled\s*===\s*[\"']undefined[\"']\s*\?\s*true\s*:\s*input\.enabled\b",
        body,
    )
)
assert false_preserving
