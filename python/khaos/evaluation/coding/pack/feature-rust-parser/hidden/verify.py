from pathlib import Path

parser = Path("src/parser.rs").read_text(encoding="utf-8")
lib = Path("src/lib.rs").read_text(encoding="utf-8")
assert "ParseError" in parser
assert "split_once" in parser
assert "parse_record" in lib
