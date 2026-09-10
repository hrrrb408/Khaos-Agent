from pathlib import Path

assert "func Validate" in Path("validate.go").read_text(encoding="utf-8")
assert "func Accumulate" in Path("pipeline.go").read_text(encoding="utf-8")
assert "Validate" in Path("service.go").read_text(encoding="utf-8")
