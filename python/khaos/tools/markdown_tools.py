"""Markdown processing tools: convert, format, extract."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

CHINESE_RE = re.compile(r"[\u4e00-\u9fff]")
SENTENCE_RE = re.compile(r"[。！？.!?]+")


async def markdown_to_text(markdown: str) -> dict[str, Any]:
    """Convert Markdown to plain text."""
    text = re.sub(r"```[^\n]*\n(.*?)```", r"\1", markdown, flags=re.DOTALL)
    text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"(?<!\*)\*\*([^*]+)\*\*(?!\*)", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!_)_([^_\n]+)_(?!_)", r"\1", text)
    text = re.sub(r"^\s{0,3}#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*+]\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\d+\.\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*>\s?", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s{0,3}([-*_])(?:\s*\1){2,}\s*$", "", text, flags=re.MULTILINE)
    return {"ok": True, "text": text.strip()}


async def extract_headings(markdown: str) -> dict[str, Any]:
    """Extract Markdown heading structure."""
    headings: list[dict[str, Any]] = []
    for line in markdown.splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        text = match.group(2).strip()
        headings.append(
            {
                "level": len(match.group(1)),
                "text": text,
                "slug": _slugify(text),
            }
        )
    return {"ok": True, "headings": headings}


async def count_words(text: str) -> dict[str, Any]:
    """Count words, characters, lines, paragraphs, sentences, and reading time."""
    characters = len(text)
    characters_no_spaces = len(re.sub(r"\s+", "", text))
    words = len(text.split())
    lines = 0 if text == "" else text.count("\n") + 1
    paragraphs = len([block for block in re.split(r"\n\s*\n", text.strip()) if block.strip()])
    sentences = len([part for part in SENTENCE_RE.split(text) if part.strip()])
    chinese_chars = len(CHINESE_RE.findall(text))
    non_space_chars = max(characters_no_spaces, 1)
    chinese_ratio = chinese_chars / non_space_chars
    if characters_no_spaces == 0:
        reading_time = 0.0
    elif chinese_ratio > 0.3:
        reading_time = characters_no_spaces / 400
    else:
        reading_time = words / 200

    return {
        "ok": True,
        "characters": characters,
        "characters_no_spaces": characters_no_spaces,
        "words": words,
        "lines": lines,
        "paragraphs": paragraphs,
        "sentences": sentences,
        "reading_time_minutes": round(reading_time, 2),
    }


async def format_markdown_table(
    headers: list[str],
    rows: list[list[str | int | float]],
) -> dict[str, Any]:
    """Format structured data as a Markdown table."""
    columns = len(headers)
    normalized_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(str(header)) for header in headers]
    for row in normalized_rows:
        for index in range(columns):
            value = row[index] if index < len(row) else ""
            widths[index] = max(widths[index], len(value))

    header_line = "| " + " | ".join(
        str(header).ljust(widths[index]) for index, header in enumerate(headers)
    ) + " |"
    separator = "| " + " | ".join("-" * width for width in widths) + " |"
    body_lines = []
    for row in normalized_rows:
        padded = [
            (row[index] if index < len(row) else "").ljust(widths[index])
            for index in range(columns)
        ]
        body_lines.append("| " + " | ".join(padded) + " |")

    table = "\n".join([header_line, separator, *body_lines])
    return {"ok": True, "table": table, "rows": len(rows), "columns": columns}


def _slugify(text: str) -> str:
    lowered = text.strip().lower()
    slug = re.sub(r"[^\w\s-]", "", lowered, flags=re.UNICODE)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")
