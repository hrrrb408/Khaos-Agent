"""Python-side integration tests for the Rust token engine.

These tests are skipped automatically when the native extension is not built,
so ``make test`` stays green on a clean checkout.
"""

from __future__ import annotations

import pytest

from khaos.rust_bridge import RustTokenizer, get_token_engine, rust_available

pytestmark = pytest.mark.skipif(not rust_available(), reason="Rust extension not built")


def test_rust_counts_english():
    tok = RustTokenizer()
    assert tok.count_tokens("hello world") == 2
    assert tok.count_tokens("The quick brown fox") == 4


def test_rust_counts_chinese():
    tok = RustTokenizer()
    assert tok.count_tokens("你好世界") == 4


def test_rust_counts_empty():
    tok = RustTokenizer()
    assert tok.count_tokens("") == 0


def test_rust_batch_consistent_with_single():
    tok = RustTokenizer()
    texts = ["hello world", "你好世界", "", "snake_case"]
    batch = tok.count_tokens_batch(texts)
    single = [tok.count_tokens(t) for t in texts]
    assert batch == single


def test_get_token_engine_prefers_rust():
    engine = get_token_engine()
    # When Rust is available, get_token_engine must return the Rust tokenizer.
    assert isinstance(engine, RustTokenizer)


def test_rust_tokenizer_matches_simple_engine_within_bounds():
    """Rust heuristic and the Python SimpleTokenEngine agree on simple inputs."""
    from khaos.agent.core import SimpleTokenEngine

    rust = RustTokenizer()
    simple = SimpleTokenEngine()
    # Pure ASCII single words: both count words.
    assert rust.count_tokens("hello") == simple.count_tokens("hello")
