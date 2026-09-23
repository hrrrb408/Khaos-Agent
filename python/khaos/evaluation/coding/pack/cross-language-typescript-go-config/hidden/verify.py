import json
from pathlib import Path

contract = json.loads(Path("contract.json").read_text(encoding="utf-8"))
typescript = Path("ts/client.ts").read_text(encoding="utf-8")
golang = Path("go/config.go").read_text(encoding="utf-8")
assert "retries" in typescript and "timeout_ms" in typescript
assert "Retries" in golang and "timeout_ms" in golang
assert contract["retries"] == 2
