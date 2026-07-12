"""Tests for LSP UTF-16 → UTF-8 byte → code-point position conversion (spec §5).

Covers:
    - ASCII (1:1:1 mapping)
    - Chinese / CJK BMP characters (1 UTF-16 unit, 3 UTF-8 bytes, 1 code point)
    - Emoji / supplementary planes (2 UTF-16 units, 4 UTF-8 bytes, 1 code point)
    - Surrogate-pair splitting (mid-code-point clamping)
    - Combining characters
    - CRLF line endings
    - LF-only and CR-only line endings
    - No trailing newline
    - Out-of-bounds line numbers (rejected)
    - Out-of-bounds character offsets (rejected)
    - Negative line/character (rejected)
    - Inverse conversion (byte offset → LSP position)
"""
from __future__ import annotations

import pytest

from khaos.coding.intelligence.lsp.positions import (
    CharacterOutOfBoundsError,
    LineOutOfBoundsError,
    PositionConversionError,
    byte_offset_to_lsp_position,
    lsp_position_to_offsets,
    lsp_range_to_byte_offsets,
)


class TestAscii:
    def test_ascii_single_line(self):
        text = "hello world"
        mapping = lsp_position_to_offsets(text, 0, 0)
        assert mapping.byte_offset == 0
        assert mapping.code_point_column == 0

        mapping = lsp_position_to_offsets(text, 0, 6)
        assert mapping.byte_offset == 6
        assert mapping.code_point_column == 6

    def test_ascii_multiline(self):
        text = "line1\nline2\nline3"
        # Start of line 1
        mapping = lsp_position_to_offsets(text, 1, 0)
        assert mapping.byte_offset == 6  # "line1\n" = 6 bytes
        assert mapping.code_point_column == 0
        # Position in line 2
        mapping = lsp_position_to_offsets(text, 2, 3)
        assert mapping.byte_offset == 6 + 6 + 3  # "line1\nline2\n" + "lin"
        assert mapping.code_point_column == 3

    def test_ascii_end_of_line(self):
        text = "abc\ndef"
        # Character at end of line 0 (after "abc")
        mapping = lsp_position_to_offsets(text, 0, 3)
        assert mapping.byte_offset == 3
        assert mapping.code_point_column == 3


class TestChineseCjk:
    def test_chinese_single_line(self):
        # Each Chinese character: 1 UTF-16 unit, 3 UTF-8 bytes, 1 code point
        text = "你好世界"
        # Position before first char
        mapping = lsp_position_to_offsets(text, 0, 0)
        assert mapping.byte_offset == 0
        assert mapping.code_point_column == 0
        # Position after first char (UTF-16 char 1)
        mapping = lsp_position_to_offsets(text, 0, 1)
        assert mapping.byte_offset == 3  # 3 UTF-8 bytes
        assert mapping.code_point_column == 1
        # Position after second char (UTF-16 char 2)
        mapping = lsp_position_to_offsets(text, 0, 2)
        assert mapping.byte_offset == 6
        assert mapping.code_point_column == 2

    def test_mixed_ascii_chinese(self):
        text = "ab你好cd"
        # After "ab" (UTF-16 char 2)
        mapping = lsp_position_to_offsets(text, 0, 2)
        assert mapping.byte_offset == 2
        assert mapping.code_point_column == 2
        # After "ab你" (UTF-16 char 3)
        mapping = lsp_position_to_offsets(text, 0, 3)
        assert mapping.byte_offset == 5  # 2 + 3 bytes
        assert mapping.code_point_column == 3
        # After "ab你好" (UTF-16 char 4)
        mapping = lsp_position_to_offsets(text, 0, 4)
        assert mapping.byte_offset == 8  # 2 + 3 + 3 bytes
        assert mapping.code_point_column == 4


class TestEmojiSupplementary:
    def test_emoji_uses_surrogate_pair(self):
        # 🎉 = U+1F389, 2 UTF-16 units, 4 UTF-8 bytes, 1 code point
        text = "x🎉y"
        # After "x" (UTF-16 char 1)
        mapping = lsp_position_to_offsets(text, 0, 1)
        assert mapping.byte_offset == 1
        assert mapping.code_point_column == 1
        # After "x🎉" (UTF-16 char 3 — emoji takes 2 units)
        mapping = lsp_position_to_offsets(text, 0, 3)
        assert mapping.byte_offset == 5  # 1 + 4 bytes
        assert mapping.code_point_column == 2  # 2 code points

    def test_multiple_emoji(self):
        text = "🎉🎊"
        # After first emoji (UTF-16 char 2)
        mapping = lsp_position_to_offsets(text, 0, 2)
        assert mapping.byte_offset == 4
        assert mapping.code_point_column == 1
        # After both emoji (UTF-16 char 4)
        mapping = lsp_position_to_offsets(text, 0, 4)
        assert mapping.byte_offset == 8
        assert mapping.code_point_column == 2

    def test_surrogate_pair_splitting_clamped(self):
        text = "🎉"
        # UTF-16 char 1 is the middle of the surrogate pair — should clamp
        # to the start of the emoji (code point 0).
        mapping = lsp_position_to_offsets(text, 0, 1)
        assert mapping.code_point_column == 0
        assert mapping.byte_offset == 0


class TestCombiningCharacters:
    def test_combining_mark_separate_unit(self):
        # é = e + combining acute (U+0301)
        # e = 1 UTF-16 unit, 1 UTF-8 byte
        # combining = 1 UTF-16 unit, 2 UTF-8 bytes
        text = "e\u0301"
        # After "e" (UTF-16 char 1)
        mapping = lsp_position_to_offsets(text, 0, 1)
        assert mapping.byte_offset == 1
        assert mapping.code_point_column == 1
        # After "e\u0301" (UTF-16 char 2)
        mapping = lsp_position_to_offsets(text, 0, 2)
        assert mapping.byte_offset == 3  # 1 + 2 bytes
        assert mapping.code_point_column == 2


class TestLineEndings:
    def test_crlf_line_endings(self):
        text = "abc\r\ndef"
        # Line 0: "abc", Line 1: "def"
        # CRLF = 2 bytes
        mapping = lsp_position_to_offsets(text, 1, 0)
        assert mapping.byte_offset == 5  # "abc\r\n" = 5 bytes
        assert mapping.code_point_column == 0
        mapping = lsp_position_to_offsets(text, 1, 1)
        assert mapping.byte_offset == 6

    def test_lf_only(self):
        text = "ab\ncd"
        mapping = lsp_position_to_offsets(text, 1, 0)
        assert mapping.byte_offset == 3  # "ab\n" = 3 bytes

    def test_cr_only(self):
        text = "ab\rcd"
        mapping = lsp_position_to_offsets(text, 1, 0)
        assert mapping.byte_offset == 3  # "ab\r" = 3 bytes

    def test_no_trailing_newline(self):
        text = "abc"
        # End of the single line
        mapping = lsp_position_to_offsets(text, 0, 3)
        assert mapping.byte_offset == 3
        assert mapping.code_point_column == 3

    def test_trailing_newline_creates_empty_line(self):
        text = "abc\n"
        # Line 1 is the empty line after the newline
        mapping = lsp_position_to_offsets(text, 1, 0)
        assert mapping.byte_offset == 4
        assert mapping.code_point_column == 0

    def test_empty_text(self):
        text = ""
        mapping = lsp_position_to_offsets(text, 0, 0)
        assert mapping.byte_offset == 0
        assert mapping.code_point_column == 0


class TestOutOfBounds:
    def test_line_out_of_bounds(self):
        text = "hello"
        with pytest.raises(LineOutOfBoundsError) as exc_info:
            lsp_position_to_offsets(text, 5, 0)
        assert exc_info.value.code == "line-out-of-bounds"

    def test_negative_line(self):
        text = "hello"
        with pytest.raises(LineOutOfBoundsError) as exc_info:
            lsp_position_to_offsets(text, -1, 0)
        assert exc_info.value.code == "negative-line"

    def test_character_out_of_bounds(self):
        text = "hello"
        with pytest.raises(CharacterOutOfBoundsError) as exc_info:
            lsp_position_to_offsets(text, 0, 100)
        assert exc_info.value.code == "character-out-of-bounds"

    def test_negative_character(self):
        text = "hello"
        with pytest.raises(CharacterOutOfBoundsError) as exc_info:
            lsp_position_to_offsets(text, 0, -1)
        assert exc_info.value.code == "negative-character"


class TestRangeConversion:
    def test_range_ascii(self):
        text = "hello world"
        byte_start, byte_end = lsp_range_to_byte_offsets(text, 0, 0, 0, 5)
        assert byte_start == 0
        assert byte_end == 5

    def test_range_with_chinese(self):
        text = "你好世界"
        byte_start, byte_end = lsp_range_to_byte_offsets(text, 0, 0, 0, 2)
        assert byte_start == 0
        assert byte_end == 6  # 2 Chinese chars = 6 bytes

    def test_range_multiline(self):
        text = "abc\ndef"
        byte_start, byte_end = lsp_range_to_byte_offsets(text, 0, 1, 1, 2)
        assert byte_start == 1
        assert byte_end == 6  # "abc\ndef" -> byte 6 is after "de"

    def test_inverted_range_rejected(self):
        text = "hello"
        with pytest.raises(PositionConversionError) as exc_info:
            lsp_range_to_byte_offsets(text, 0, 3, 0, 1)
        assert exc_info.value.code == "inverted-range"


class TestInverseConversion:
    def test_byte_offset_to_lsp_position_ascii(self):
        text = "hello world"
        line, char = byte_offset_to_lsp_position(text, 0)
        assert line == 0
        assert char == 0
        line, char = byte_offset_to_lsp_position(text, 6)
        assert line == 0
        assert char == 6

    def test_byte_offset_to_lsp_position_chinese(self):
        text = "你好"
        # Byte 3 = after first Chinese char = UTF-16 char 1
        line, char = byte_offset_to_lsp_position(text, 3)
        assert line == 0
        assert char == 1

    def test_byte_offset_to_lsp_position_emoji(self):
        text = "x🎉y"
        # Byte 5 = after "x🎉" = UTF-16 char 3 (x=1, 🎉=2)
        line, char = byte_offset_to_lsp_position(text, 5)
        assert line == 0
        assert char == 3

    def test_byte_offset_to_lsp_position_multiline(self):
        text = "abc\ndef"
        line, char = byte_offset_to_lsp_position(text, 4)  # Start of line 1
        assert line == 1
        assert char == 0

    def test_roundtrip_ascii(self):
        text = "hello world"
        # Forward: position → byte offset
        mapping = lsp_position_to_offsets(text, 0, 5)
        # Inverse: byte offset → position
        line, char = byte_offset_to_lsp_position(text, mapping.byte_offset)
        assert line == 0
        assert char == 5

    def test_roundtrip_chinese(self):
        text = "你好世界"
        mapping = lsp_position_to_offsets(text, 0, 2)
        line, char = byte_offset_to_lsp_position(text, mapping.byte_offset)
        assert line == 0
        assert char == 2

    def test_roundtrip_emoji(self):
        text = "🎉🎊"
        mapping = lsp_position_to_offsets(text, 0, 2)
        line, char = byte_offset_to_lsp_position(text, mapping.byte_offset)
        assert line == 0
        assert char == 2

    def test_negative_byte_offset_rejected(self):
        with pytest.raises(PositionConversionError) as exc_info:
            byte_offset_to_lsp_position("hello", -1)
        assert exc_info.value.code == "negative-byte-offset"

    def test_byte_offset_out_of_bounds_rejected(self):
        with pytest.raises(PositionConversionError) as exc_info:
            byte_offset_to_lsp_position("hello", 100)
        assert exc_info.value.code == "byte-offset-out-of-bounds"
