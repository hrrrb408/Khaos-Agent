from pathlib import Path

transport = Path("src/transport.ts").read_text(encoding="utf-8")
client = Path("src/client.ts").read_text(encoding="utf-8")
assert "interface Transport" in transport
assert "private transport" in client
assert "Request" in client
