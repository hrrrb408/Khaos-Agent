"""Shared test fixtures."""
from __future__ import annotations

import os

# Force mock mode for all tests — prevent accidentally hitting real APIs
os.environ.setdefault("KHAOS_NO_CONFIG", "1")
