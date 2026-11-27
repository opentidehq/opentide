//! The lexer on one huge token and on huge runs of unterminated openers: no stack overflow (a
//! logos `#[regex]` with a repeated group of alternatives recurses once per repetition and
//! aborts the process), and no quadratic rescanning. Every case runs on a 1 MB stack, in a
//! debug build, with a time budget.

use opentide_cql::{lexer, syntax};

use std::time::{Duration, Instant};
use syntax::SyntaxKind as K;

const N: usize = 1_000_000;

/// Lexes `source` on a 1 MB stack and checks the lexemes tile it.
fn lex_on_small_stack(name: &'static str, source: String) -> Vec<K> {
    let started = Instant::now();
    let kinds = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let lexemes = lexer::lex(&source);
            let tiled: usize = lexemes
                .iter()
                .map(|l| usize::from(l.range.end()) - usize::from(l.range.start()))
                .sum();
            assert_eq!(tiled, source.len(), "{name}: the lexemes tile the source");
            lexemes.iter().map(|l| K::from_raw(l.kind)).collect()
        })
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .join()
        .unwrap_or_else(|_| panic!("{name}: the lexer panicked or overflowed"));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{name}: took {:?}",
        started.elapsed()
    );
    kinds
}

#[test]
fn one_token_of_a_million_characters() {
    let one = |name, source: String, kind: K| {
        let kinds = lex_on_small_stack(name, source);
        assert!(kinds.contains(&kind), "{name}: {kinds:?}");
    };
    one("word", "a".repeat(N), K::WORD);
    one("word with indexes", "a[0]".repeat(N / 4), K::WORD);
    one("word of escapes", "\\".repeat(N), K::WORD);
    one("tag", format!("#{}", "a".repeat(N)), K::TAG_TOKEN);
    one("pattern", "*".repeat(N), K::PATTERN);
    one("pattern with colons", "a:".repeat(N / 2), K::PATTERN);
    one("string", format!("\"{}\"", "a".repeat(N)), K::STRING_TOKEN);
    one(
        "string of escapes",
        format!("\"{}\"", "\\\"".repeat(N / 2)),
        K::STRING_TOKEN,
    );
    one(
        "regex",
        format!("/{}/i", "a".repeat(N)),
        K::REGEX_PATTERN_TOKEN,
    );
    one(
        "regex of classes",
        format!("/{}/", "[a]".repeat(N / 3)),
        K::REGEX_PATTERN_TOKEN,
    );
    one(
        "regex of escapes",
        format!("/{}/", "\\/".repeat(N / 2)),
        K::REGEX_PATTERN_TOKEN,
    );
    one(
        "line comment",
        format!("//{}", "a".repeat(N)),
        K::LINE_COMMENT,
    );
    one(
        "block comment",
        format!("/*{}*/", "a".repeat(N)),
        K::BLOCK_COMMENT,
    );
    one(
        "number",
        format!("x < 1.{}", "1".repeat(N)),
        K::NUMBER_TOKEN,
    );
    one(
        "expression pattern",
        format!("x := {}", "*".repeat(N)),
        K::PATTERN,
    );
    one("whitespace", " ".repeat(N), K::WHITESPACE);
}

#[test]
fn a_million_openers_that_never_close() {
    for (name, source) in [
        ("block comments", "/*".repeat(N / 2)),
        ("strings", "\"\\".repeat(N / 2)),
        ("strings in a row", "\"a ".repeat(N / 3)),
        ("regex classes", format!("/{}", "[".repeat(N))),
        ("regexes with classes", "/[a".repeat(N / 3)),
        ("brackets", "(".repeat(N)),
        ("braces and parameters", "?{".repeat(N / 2)),
        ("saved queries", "$a(".repeat(N / 3)),
        ("calls", "f(".repeat(N / 2)),
        ("assignments", "x:=".repeat(N / 3)),
        ("pipes", "|".repeat(N)),
    ] {
        lex_on_small_stack(name, source);
    }
}
