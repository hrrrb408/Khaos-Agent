"""LSP UTF-16 position → UTF-8 byte offset → code-point column conversion.

The LSP specification uses UTF-16 code unit offsets for ``line`` and
``character`` (specifically, ``character`` is a UTF-16 code unit count
within the line). Khaos's :class:`SourceLocation` uses Unicode code-point
columns and UTF-8 byte offsets. Conflating the two is a classic source
of off-by-one errors with CJK text, emoji, and combining marks.

Conversion pipeline (per spec §5):
    LSP UTF-16 line/character
    → UTF-8 byte offset
    → SourceLocation Unicode code-point column

Covered cases:
    - ASCII (1:1:1 mapping)
    - Chinese / CJK BMP characters (1 UTF-16 unit, 3 UTF-8 bytes, 1 code point)
    - Emoji / supplementary planes (2 UTF-16 units via surrogate pair,
      4 UTF-8 bytes, 1 code point)
    - Surrogate-pair splitting (LSP character lands mid-code-point — clamped)
    - Combining characters (each combining mark is its own UTF-16 unit)
    - CRLF line endings (``\\r\\n`` counts as one line break)
    - LF-only and CR-only line endings
    - No trailing newline
    - Out-of-bounds line numbers (rejected)
    - Out-of-bounds character offsets (rejected)
    - Negative line/character (rejected)

This module NEVER treats an LSP ``character`` as a byte column or a
code-point column directly.
"""
from __future__ import annotations

from dataclasses import dataclass


class PositionConversionError(Exception):
    """Base for LSP position conversion failures."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LineOutOfBoundsError(PositionConversionError):
    """LSP line number exceeds the number of lines in the document."""


class CharacterOutOfBoundsError(PositionConversionError):
    """LSP character exceeds the UTF-16 length of the line."""


@dataclass(frozen=True)
class PositionMapping:
    """Result of converting an LSP (line, character) position.

    All offsets are zero-based:
    - ``byte_offset``: UTF-8 byte offset from the start of the document.
    - ``code_point_column``: Unicode code-point column within the line
      (matches :class:`SourceLocation.start_column`).
    - ``line_start_byte``: UTF-8 byte offset of the start of the line.
    - ``line``: the (validated) LSP line number.
    """

    line: int
    code_point_column: int
    byte_offset: int
    line_start_byte: int


def lsp_position_to_offsets(
    text: str,
    line: int,
    character_utf16: int,
) -> PositionMapping:
    """Convert an LSP ``(line, character)`` position to byte/code-point offsets.

    Args:
        text: The full document text (UTF-8 decoded Python ``str``).
        line: Zero-based LSP line number.
        character_utf16: Zero-based UTF-16 code unit offset within the line.

    Returns:
        A :class:`PositionMapping` with the converted offsets.

    Raises:
        LineOutOfBoundsError: ``line`` is negative or exceeds the document.
        CharacterOutOfBoundsError: ``character_utf16`` is negative or exceeds
            the line's UTF-16 length (with a small clamping exception for
            surrogate-pair splitting).
    """
    if line < 0:
        raise LineOutOfBoundsError(
            "negative-line",
            f"LSP line number must be non-negative, got {line}",
        )
    if character_utf16 < 0:
        raise CharacterOutOfBoundsError(
            "negative-character",
            f"LSP character must be non-negative, got {character_utf16}",
        )

    lines = _split_lines_with_byte_offsets(text)

    if line >= len(lines):
        raise LineOutOfBoundsError(
            "line-out-of-bounds",
            f"LSP line {line} exceeds document line count {len(lines)}",
        )

    line_start_byte, line_content = lines[line]

    code_point_col = _utf16_char_to_code_point(line_content, character_utf16)

    # Convert code-point column to UTF-8 byte offset within the line.
    line_text_before = line_content[:code_point_col]
    byte_offset_in_line = len(line_text_before.encode("utf-8"))
    byte_offset = line_start_byte + byte_offset_in_line

    return PositionMapping(
        line=line,
        code_point_column=code_point_col,
        byte_offset=byte_offset,
        line_start_byte=line_start_byte,
    )


def lsp_range_to_byte_offsets(
    text: str,
    start_line: int,
    start_character_utf16: int,
    end_line: int,
    end_character_utf16: int,
) -> tuple[int, int]:
    """Convert an LSP range to ``(byte_start, byte_end)``.

    Both positions are converted via :func:`lsp_position_to_offsets` and
    the byte offsets are returned. ``byte_end`` is exclusive.
    """
    start = lsp_position_to_offsets(text, start_line, start_character_utf16)
    end = lsp_position_to_offsets(text, end_line, end_character_utf16)
    if end.byte_offset < start.byte_offset:
        raise PositionConversionError(
            "inverted-range",
            f"LSP range end (byte {end.byte_offset}) precedes start (byte {start.byte_offset})",
        )
    return start.byte_offset, end.byte_offset


def _utf16_char_to_code_point(line_content: str, utf16_char: int) -> int:
    """Convert a UTF-16 code unit offset to a code-point index within a line.

    Handles surrogate pairs: if ``utf16_char`` lands in the middle of a
    surrogate pair (i.e. between the high and low surrogate), it is
    clamped to the start of that code point — the position cannot split
    a supplementary character.

    A ``utf16_char`` equal to the line's UTF-16 length is valid (it
    represents the end-of-line cursor position).
    """
    utf16_offset = 0
    for code_point_idx, ch in enumerate(line_content):
        if utf16_offset == utf16_char:
            return code_point_idx
        cp = ord(ch)
        units = 2 if cp >= 0x10000 else 1
        # If the target falls strictly inside a surrogate pair, clamp to
        # the start of this code point (cannot split a supplementary char).
        if utf16_offset < utf16_char < utf16_offset + units:
            return code_point_idx
        utf16_offset += units

    # Character is at or past the end of the line.
    if utf16_char == utf16_offset:
        return len(line_content)

    raise CharacterOutOfBoundsError(
        "character-out-of-bounds",
        f"LSP character {utf16_char} exceeds line UTF-16 length {utf16_offset}",
    )


def byte_offset_to_lsp_position(text: str, byte_offset: int) -> tuple[int, int]:
    """Convert a UTF-8 byte offset to an LSP ``(line, character_utf16)`` position.

    This is the inverse of :func:`lsp_position_to_offsets` — used when building
    LSP requests from Khaos's internal byte offsets.
    """
    if byte_offset < 0:
        raise PositionConversionError(
            "negative-byte-offset",
            f"byte offset must be non-negative, got {byte_offset}",
        )
    if byte_offset > len(text.encode("utf-8")):
        raise PositionConversionError(
            "byte-offset-out-of-bounds",
            f"byte offset {byte_offset} exceeds document byte length {len(text.encode('utf-8'))}",
        )
    lines = _split_lines_with_byte_offsets(text)
    for line_idx, (line_start_byte, line_content) in enumerate(lines):
        line_byte_length = len(line_content.encode("utf-8"))
        line_end_byte = line_start_byte + line_byte_length
        if byte_offset <= line_end_byte or line_idx == len(lines) - 1:
            byte_offset_in_line = byte_offset - line_start_byte
            if byte_offset_in_line < 0:
                byte_offset_in_line = 0
            # Convert byte offset within line to UTF-16 character offset.
            char_utf16 = _byte_offset_in_line_to_utf16(line_content, byte_offset_in_line)
            return line_idx, char_utf16
    return len(lines) - 1, 0


def _byte_offset_in_line_to_utf16(line_content: str, byte_offset_in_line: int) -> int:
    """Convert a UTF-8 byte offset within a line to a UTF-16 code unit offset."""
    byte_count = 0
    utf16_offset = 0
    for ch in line_content:
        if byte_count >= byte_offset_in_line:
            return utf16_offset
        ch_bytes = len(ch.encode("utf-8"))
        if byte_count + ch_bytes > byte_offset_in_line:
            # Byte offset lands inside a multi-byte character — clamp to start.
            return utf16_offset
        byte_count += ch_bytes
        cp = ord(ch)
        utf16_offset += 2 if cp >= 0x10000 else 1
    return utf16_offset


def _split_lines_with_byte_offsets(text: str) -> list[tuple[int, str]]:
    """Split text into lines, tracking the UTF-8 byte offset of each line start.

    Handles ``\\n``, ``\\r\\n``, and ``\\r`` line terminators. The line
    content does NOT include the terminator. A file ending with a newline
    has a trailing empty line (matching LSP semantics).
    """
    lines: list[tuple[int, str]] = []
    current_line_start_byte = 0
    current_line_start_idx = 0
    i = 0
    byte_offset = 0

    while i < len(text):
        ch = text[i]
        if ch == "\n":
            line_content = text[current_line_start_idx:i]
            lines.append((current_line_start_byte, line_content))
            byte_offset += 1  # \n = 1 UTF-8 byte
            i += 1
            current_line_start_idx = i
            current_line_start_byte = byte_offset
        elif ch == "\r":
            line_content = text[current_line_start_idx:i]
            lines.append((current_line_start_byte, line_content))
            byte_offset += 1  # \r = 1 UTF-8 byte
            i += 1
            # Consume \n if part of a CRLF pair.
            if i < len(text) and text[i] == "\n":
                byte_offset += 1  # \n = 1 UTF-8 byte
                i += 1
            current_line_start_idx = i
            current_line_start_byte = byte_offset
        else:
            byte_offset += len(ch.encode("utf-8"))
            i += 1

    # Always include the trailing line (even if empty). This ensures:
    # - "abc" → 1 line: "abc"
    # - "abc\n" → 2 lines: "abc", ""
    # - "" → 1 line: ""
    lines.append((current_line_start_byte, text[current_line_start_idx:]))

    return lines
