"""Shared test fixtures."""
from __future__ import annotations

import os

# Force mock mode for all tests — prevent accidentally hitting real APIs
os.environ.setdefault("KHAOS_NO_CONFIG", "1")
# M4 batch 3.1.16A-1: tests legitimately need to create databases in
# ``tmp_path`` without each test constructing a state-root path.  This
# bypasses the state-root enforcement in ``state_root.py`` so that
# ``Database(tmp_path / "khaos.db")`` and ``serve_json_lines(socket,
# str(tmp_path / "khaos.db"), ...)`` continue to work unchanged.
# Production code never sets this variable.
os.environ.setdefault("KHAOS_ALLOW_PROJECT_DB", "1")
