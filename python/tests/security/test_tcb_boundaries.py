"""TCB boundary extraction tests (M6.9 BATCH 11).

The authority transport's frame handling was an inline function inside
authorityd.py; it now lives as a pure, bounded, separately reviewable
boundary in protocol_boundary.  The TCB inventory is generated from a
curated owner map and must stay current.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from khaos.security.protocol_boundary import (
    ProtocolBoundaryError,
    read_bounded_line,
)

ROOT = Path(__file__).resolve().parents[3]


class _FakeConnection:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def recv(self, size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


def test_bounded_line_reads_across_chunks() -> None:
    connection = _FakeConnection([b'{"ok": tr', b'ue}\n{"next"'])
    assert read_bounded_line(connection, max_bytes=1024) == b'{"ok": true}'


def test_bounded_line_fails_closed_on_oversize() -> None:
    connection = _FakeConnection([b"a" * 4096, b"a" * 4096])
    with pytest.raises(ProtocolBoundaryError, match="too large or incomplete"):
        read_bounded_line(connection, max_bytes=1024)


def test_bounded_line_fails_closed_on_unterminated_frame() -> None:
    connection = _FakeConnection([b"no newline here"])
    with pytest.raises(ProtocolBoundaryError, match="too large or incomplete"):
        read_bounded_line(connection, max_bytes=1024)


def test_bounded_line_rejects_invalid_limits_and_connections() -> None:
    with pytest.raises(ProtocolBoundaryError, match="positive"):
        read_bounded_line(_FakeConnection([]), max_bytes=0)
    with pytest.raises(ProtocolBoundaryError, match="recv"):
        read_bounded_line(object(), max_bytes=1024)


def test_tcb_inventory_is_current_and_complete() -> None:
    spec = importlib.util.spec_from_file_location(
        "tcb_inventory", ROOT / "scripts" / "generate_tcb_inventory.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = ROOT / "docs" / "generated" / "tcb-inventory.md"
    assert output.is_file(), "TCB inventory must be committed"
    assert output.read_text(encoding="utf-8") == module.render()
    # Every ownership category from the ADR model is present.
    for category in (
        "Security decision owners",
        "Mutable security state owners",
        "Privileged spawn owners",
        "Secret owners",
        "Network owners",
        "Workspace owners",
        "Effect owners",
        "Native transport TCB",
    ):
        assert f"## {category}" in module.render()
    # Every curated owner module exists in the repository.
    for owners in module.TCB_OWNERS.values():
        for module_path, _, _ in owners:
            if module_path.startswith("python/") or module_path.startswith("rust/"):
                assert (ROOT / module_path).exists(), module_path
                assert (ROOT / module_path).is_dir() or (ROOT / module_path).is_file()
