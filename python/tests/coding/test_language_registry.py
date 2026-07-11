from pathlib import Path

from khaos.coding.intelligence import LanguageRegistry


def test_registry_supports_first_phase_languages_and_extensions():
    registry = LanguageRegistry()
    assert set(registry.languages()) == {"python", "javascript", "typescript", "go", "rust"}
    assert registry.for_path(Path("main.ts")).language_id == "typescript"
    assert registry.for_path(Path("main.py")).language_id == "python"


def test_legacy_adapters_parse_offline_fixtures():
    registry = LanguageRegistry()
    fixtures = {
        "python_basic/src/fixture_pkg/__init__.py": "python",
        "javascript_basic/index.js": "javascript",
        "typescript_basic/index.ts": "typescript",
        "go_basic/main.go": "go",
        "rust_basic/src/lib.rs": "rust",
    }
    root = Path(__file__).parents[1] / "fixtures" / "repos"
    for relative, language in fixtures.items():
        path = root / relative
        parsed = registry.get(language).parse(path, path.read_bytes())
        assert parsed.language == language
        assert parsed.symbols


def test_invalid_utf8_degrades_to_structured_diagnostic(tmp_path: Path):
    path = tmp_path / "broken.js"
    parsed = LanguageRegistry().for_path(path).parse(path, b"\xff\xfe")
    assert parsed.diagnostics
