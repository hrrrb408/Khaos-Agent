import re
from pathlib import Path

parser = Path("src/parser.rs").read_text(encoding="utf-8")
lib = Path("src/lib.rs").read_text(encoding="utf-8")
assert "ParseError" in parser
assert re.search(r"split_once|splitn\s*\(\s*2\s*,\s*['\"]=['\"]\s*\)", parser)
assert re.search(r"pub\s+fn\s+parse_record\b", parser)
assert "pub mod parser" in lib
