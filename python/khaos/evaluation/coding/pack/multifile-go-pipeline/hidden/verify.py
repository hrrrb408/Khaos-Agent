import re
from pathlib import Path

validate = Path("validate.go").read_text(encoding="utf-8")
pipeline = Path("pipeline.go").read_text(encoding="utf-8")
service = Path("service.go").read_text(encoding="utf-8")

assert re.search(r"\bfunc\s+Validate\s*\(", validate)

# The fixture asks for a result accumulator, not a particular API spelling.
# Accept either a function-style accumulator or the idiomatic Go type with
# constructor/add/results methods, then require the service to use the
# validation path and an accumulator-related symbol.
has_function_accumulator = bool(re.search(r"\bfunc\s+Accumulate\s*\(", pipeline))
has_type_accumulator = bool(re.search(r"\btype\s+Accumulator\b", pipeline))
assert has_function_accumulator or has_type_accumulator
assert re.search(r"\bValidate\s*\(", service)
assert re.search(
    r"\b(?:Accumulate|Accumulator|NewAccumulator)\b|\.Add\s*\(|\.Results\s*\(",
    service,
)
