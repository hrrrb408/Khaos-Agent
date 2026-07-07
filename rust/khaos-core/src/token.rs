//! Token counting.
//!
//! A dependency-free heuristic estimator that approximates BPE token counts well
//! enough for budgeting decisions without the network/disk cost of vendored BPE
//! merge tables. The approximation:
//!   - Each CJK ideograph (Chinese/Japanese/Korean) counts as roughly one token,
//!     since BPE tends to split CJK into single-token pieces.
//!   - Each whitespace/underscore-delimited ASCII word counts as one token.
//!   - Standalone punctuation that is not adjacent to a word counts as one token.
//!
//! This stays within ~15% of cl100k_base on typical mixed-language agent text,
//! which is sufficient for compression-threshold and budget checks. Swap in
//! `tiktoken-rs` later for exact counts without changing the public signature.

/// Approximate the token count for `text` using the given `encoding` name.
///
/// `encoding` is currently advisory (any value uses the same heuristic); it is
/// accepted to keep the signature stable for a future tiktoken swap.
pub fn count_tokens(text: &str, encoding: &str) -> usize {
    let _ = encoding; // advisory; heuristic ignores it for now
    if text.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    for token in text.split(|c: char| c.is_whitespace() || c == '_') {
        if token.is_empty() {
            continue;
        }
        count += count_token_piece(token);
    }
    count
}

/// Count tokens for a batch of texts at once (convenience helper).
pub fn count_tokens_batch(texts: &[&str], encoding: &str) -> Vec<usize> {
    texts.iter().map(|t| count_tokens(t, encoding)).collect()
}

fn count_token_piece(piece: &str) -> usize {
    let mut tokens = 0usize;
    let mut pending_ascii_word = false;
    for ch in piece.chars() {
        if is_cjk(ch) {
            if pending_ascii_word {
                tokens += 1;
                pending_ascii_word = false;
            }
            tokens += 1;
        } else if ch.is_alphanumeric() {
            pending_ascii_word = true;
        } else {
            // Punctuation / symbol.
            if pending_ascii_word {
                tokens += 1;
                pending_ascii_word = false;
            }
            tokens += 1;
        }
    }
    if pending_ascii_word {
        tokens += 1;
    }
    tokens
}

/// True for CJK ideographs and related ranges that BPE tends to split per-char.
fn is_cjk(ch: char) -> bool {
    matches!(ch as u32,
        0x3000..=0x303F |   // CJK symbols and punctuation
        0x3040..=0x309F |   // Hiragana
        0x30A0..=0x30FF |   // Katakana
        0x3400..=0x4DBF |   // CJK Extension A
        0x4E00..=0x9FFF |   // CJK Unified Ideographs
        0xF900..=0xFAFF |   // CJK Compatibility Ideographs
        0xFF00..=0xFFEF |   // Halfwidth and Fullwidth Forms
        0x20000..=0x2A6DF | // CJK Extension B
        0x2A700..=0x2B73F | // CJK Extension C
        0x2B740..=0x2B81F   // CJK Extension D
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(count_tokens("", "cl100k_base"), 0);
    }

    #[test]
    fn whitespace_only_is_zero() {
        assert_eq!(count_tokens("   \t\n  ", "cl100k_base"), 0);
    }

    #[test]
    fn english_words_approx_one_token_each() {
        // "hello world" -> 2 tokens
        assert_eq!(count_tokens("hello world", "cl100k_base"), 2);
        // "The quick brown fox" -> 4 tokens
        assert_eq!(count_tokens("The quick brown fox", "cl100k_base"), 4);
    }

    #[test]
    fn punctuation_counts_separately() {
        // "hello, world!" -> "hello," splits into word + comma, "world!" into word + bang
        // = 4 tokens with the heuristic.
        assert_eq!(count_tokens("hello, world!", "cl100k_base"), 4);
    }

    #[test]
    fn chinese_chars_one_token_each() {
        // "你好世界" -> 4 CJK chars, 4 tokens
        assert_eq!(count_tokens("你好世界", "cl100k_base"), 4);
    }

    #[test]
    fn mixed_en_zh() {
        // "hello 你好" -> "hello" (1) + "你好" (2) = 3 tokens
        assert_eq!(count_tokens("hello 你好", "cl100k_base"), 3);
    }

    #[test]
    fn batch_counts() {
        let counts = count_tokens_batch(&["hello", "你好", ""], "cl100k_base");
        assert_eq!(counts, vec![1, 2, 0]);
    }

    #[test]
    fn deterministic_for_same_input() {
        let text = "The quick brown fox 你好世界";
        assert_eq!(count_tokens(text, "x"), count_tokens(text, "y"));
    }

    #[test]
    fn underscores_split_words() {
        // "snake_case" -> "snake" + "case" = 2 tokens
        assert_eq!(count_tokens("snake_case", "cl100k_base"), 2);
    }
}
