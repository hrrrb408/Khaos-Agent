from pathlib import Path

server = Path("server.py").read_text(encoding="utf-8")
frontend = Path("frontend/index.html").read_text(encoding="utf-8")
assert 'self.path == "/api/task"' in server
assert '"status": "open"' in server
assert 'fetch("/api/task")' in frontend
assert 'task.status' in frontend
