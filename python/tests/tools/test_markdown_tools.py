from khaos.tools.markdown_tools import (
    count_words,
    extract_headings,
    format_markdown_table,
    markdown_to_text,
)


async def test_markdown_to_text():
    markdown = """# Title

**Bold** and *italic* with [link](https://example.com).
![Alt text](image.png)

```python
print("hello")
```

- Item one
1. Item two
> Quote
---
`code`
"""

    result = await markdown_to_text(markdown)

    assert result["ok"] is True
    text = result["text"]
    assert "Title" in text
    assert "Bold and italic with link." in text
    assert "Alt text" in text
    assert 'print("hello")' in text
    assert "Item one" in text
    assert "Item two" in text
    assert "Quote" in text
    assert "code" in text
    assert "**" not in text
    assert "[link]" not in text


async def test_extract_headings():
    markdown = "# Main Title\n\n## Section One\n### Deep Dive\nplain text\n"

    result = await extract_headings(markdown)

    assert result == {
        "ok": True,
        "headings": [
            {"level": 1, "text": "Main Title", "slug": "main-title"},
            {"level": 2, "text": "Section One", "slug": "section-one"},
            {"level": 3, "text": "Deep Dive", "slug": "deep-dive"},
        ],
    }


async def test_count_words():
    text = "Hello world. 你好世界！Another sentence?"

    result = await count_words(text)

    assert result["ok"] is True
    assert result["characters"] == len(text)
    assert result["characters_no_spaces"] == len(text.replace(" ", ""))
    assert result["words"] == 4
    assert result["lines"] == 1
    assert result["paragraphs"] == 1
    assert result["sentences"] == 3
    assert result["reading_time_minutes"] > 0


async def test_count_words_chinese():
    text = "这是第一句。这里是第二句！"

    result = await count_words(text)

    assert result["ok"] is True
    assert result["words"] == 1
    assert result["sentences"] == 2
    assert result["reading_time_minutes"] == round(len(text) / 400, 2)


async def test_format_markdown_table():
    result = await format_markdown_table(
        headers=["Name", "Score"],
        rows=[["Alice", 95], ["Bob", 8]],
    )

    assert result["ok"] is True
    assert result["rows"] == 2
    assert result["columns"] == 2
    assert result["table"] == (
        "| Name  | Score |\n"
        "| ----- | ----- |\n"
        "| Alice | 95    |\n"
        "| Bob   | 8     |"
    )


async def test_empty_input():
    text_result = await markdown_to_text("")
    heading_result = await extract_headings("")
    count_result = await count_words("")
    table_result = await format_markdown_table([], [])

    assert text_result == {"ok": True, "text": ""}
    assert heading_result == {"ok": True, "headings": []}
    assert count_result == {
        "ok": True,
        "characters": 0,
        "characters_no_spaces": 0,
        "words": 0,
        "lines": 0,
        "paragraphs": 0,
        "sentences": 0,
        "reading_time_minutes": 0.0,
    }
    assert table_result == {"ok": True, "table": "|  |\n|  |", "rows": 0, "columns": 0}
