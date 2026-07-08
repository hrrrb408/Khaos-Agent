"""Terminal brand assets for the Khaos TUI."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_BRAND_IMAGE = _PROJECT_ROOT / "assets" / "brand" / "khaos-feiyuan.png"


_HAWK_LINES = [
    "                 ╱╲                         ",
    "              ╱╲╲██╲      ╱╲                ",
    "          ╱╲╲███████╲╲╲╲╲██╲               ",
    "       ╱╲╲██████████████████╲╲             ",
    "     ╱╲██████████▀▀▀██████████╲            ",
    "   ╱╲██████▀▀╲╲        ╲███████╲           ",
    "  ╱█████▀       ◉        ╲██████╲          ",
    " ╱████╱     ╲▄▄▄╱          ╲█████╲         ",
    " ████╱     ╱███╲     ╲╲╲╲╲   ╲████        ",
    " ███╱    ╱██████╲╲╲████████╲   ╲██        ",
    "  ██╲  ╱██████████████▀╲████╲   ╲█        ",
    "   ╲██████████████▀▀     ╲███╲            ",
    "     ╲████████▀▀          ╲██╲            ",
    "        ╲██▀      ╲╲╲      ╲╲             ",
    "          ╲╲       ╲██╲                   ",
    "                    ╲╲                    ",
]

_LABEL_LINES = [
    "",
    "",
    "FEIYUAN",
    "Khaos",
    "混沌",
    "",
    "personal agent platform",
    "red hawk / chaos engine",
    "",
    "/help commands",
    "/mode switch",
    "/clear reset",
    "",
    "",
    "",
    "",
]


def brand_art(width: int = 92) -> Text:
    """Return the Khaos personal brand mark as terminal-styled text."""
    image_art = _image_brand_art(width=width)
    if image_art is not None:
        return image_art
    return _unicode_brand_art()


def _image_brand_art(width: int = 92) -> Text | None:
    """Render the source PNG as a truecolor half-block terminal image.

    This is the portable high-fidelity path for terminals that support ANSI
    truecolor. It still uses terminal cells, but each ``▀`` carries a foreground
    and background color sampled from the original image.
    """
    if not _BRAND_IMAGE.exists():
        return None
    try:
        from PIL import Image, ImageEnhance
    except ImportError:
        return None

    try:
        image = Image.open(_BRAND_IMAGE).convert("RGB")
    except OSError:
        return None

    image = _crop_visible_brand(image)
    image = ImageEnhance.Color(image).enhance(1.35)
    image = ImageEnhance.Contrast(image).enhance(1.45)
    image = ImageEnhance.Sharpness(image).enhance(1.8)

    source_width, source_height = image.size
    rows = max(10, round(width * source_height / source_width / 2))
    image = image.resize((width, rows * 2), Image.Resampling.LANCZOS)

    text = Text()
    for y in range(0, rows * 2, 2):
        for x in range(width):
            upper = image.getpixel((x, y))
            lower = image.getpixel((x, y + 1))
            text.append(*_half_block(upper, lower))
        text.append("\n")
    return text


def _half_block(
    upper: tuple[int, int, int],
    lower: tuple[int, int, int],
) -> tuple[str, str | None]:
    """Return one terminal cell while leaving near-black pixels unpainted."""
    upper_visible = _is_visible_pixel(upper)
    lower_visible = _is_visible_pixel(lower)
    if upper_visible and lower_visible:
        return "▀", f"{_hex(upper)} on {_hex(lower)}"
    if upper_visible:
        return "▀", _hex(upper)
    if lower_visible:
        return "▄", _hex(lower)
    return " ", None


def _is_visible_pixel(rgb: tuple[int, int, int]) -> bool:
    red, green, blue = rgb
    brightness = max(red, green, blue)
    red_signal = red - max(green, blue)
    return brightness > 30 or (red > 18 and red_signal > 8)


def _crop_visible_brand(image: "Image.Image") -> "Image.Image":
    """Crop black padding so the terminal render spends cells on the mark."""
    pixels = image.load()
    width, height = image.size
    min_x = width
    min_y = height
    max_x = 0
    max_y = 0

    for y in range(height):
        for x in range(width):
            red, green, blue = pixels[x, y]
            if red > 22 or green > 18 or blue > 18:
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)

    if min_x >= max_x or min_y >= max_y:
        return image

    pad_x = max(12, round((max_x - min_x) * 0.05))
    pad_y = max(12, round((max_y - min_y) * 0.06))
    box = (
        max(0, min_x - pad_x),
        max(0, min_y - pad_y),
        min(width, max_x + pad_x),
        min(height, max_y + pad_y),
    )
    return image.crop(box)


def _unicode_brand_art() -> Text:
    """Return the fallback Unicode logo when image rendering is unavailable."""
    text = Text()
    for mark, label in zip(_HAWK_LINES, _LABEL_LINES):
        text.append(mark, style="bold #ef1d1d")
        if label in {"FEIYUAN", "Khaos", "混沌"}:
            text.append("   " + label, style="bold #f3f4f6")
        elif label.startswith("/"):
            command, _, rest = label.partition(" ")
            text.append("   " + command, style="bold #f59e0b")
            text.append(" " + rest, style="#9ca3af")
        elif label:
            text.append("   " + label, style="#9ca3af")
        else:
            text.append("")
        text.append("\n")
    return text


def _hex(rgb: tuple[int, int, int]) -> str:
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
