import json
from pathlib import Path

contract = json.loads(Path("contract.json").read_text(encoding="utf-8"))
client = Path("python/client.py").read_text(encoding="utf-8")
server = Path("go/server.go").read_text(encoding="utf-8")
assert "error" in client and "version" in client
assert "Error" in server and "Version" in server
assert contract["version"] == 1
