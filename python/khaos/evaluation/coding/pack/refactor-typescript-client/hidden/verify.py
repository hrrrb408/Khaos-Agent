import re
from pathlib import Path

transport = Path("src/transport.ts").read_text(encoding="utf-8")
client = Path("src/client.ts").read_text(encoding="utf-8")
assert re.search(r"\binterface\s+Transport\b", transport)
assert re.search(r"\bprivate\s+(?:readonly\s+)?transport\b", client)
assert "Request" in client
