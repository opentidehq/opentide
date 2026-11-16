//! The lexer on one huge token and on huge runs of unterminated openers: no stack overflow (a
//! logos `#[regex]` with a repeated group of alternatives recurses once per repetition and
//! aborts the process), and no quadratic rescanning. Every case runs on a 1 MB stack, in a
//! debug build, with a time budget.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/syntax.rs"]
mod syntax;

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
        assert!(
            kinds.contains(&kind),
            "{name}: {:?}",
            &kinds[..kinds.len().min(8)]
        );
    };
    one("word", "a".repeat(N), K::WORD);
    one("tilde word", format!("{}~", "a".repeat(N)), K::TILDE_WORD);
    one("number", "1".repeat(N), K::NUMBER_TOKEN);
    one("fraction", format!("1.{}", "5".repeat(N)), K::NUMBER_TOKEN);
    one("string", format!("\"{}\"", "a".repeat(N)), K::STRING_TOKEN);
    one(
        "string of escapes",
        format!("\"{}\"", "\\\"".repeat(N / 2)),
        K::STRING_TOKEN,
    );
    one(
        "single quoted",
        format!("'{}'", "a".repeat(N)),
        K::STRING_TOKEN,
    );
    one(
        "triple quoted",
        format!("\"\"\"{}\"\"\"", "a".repeat(N)),
        K::STRING_TOKEN,
    );
    one(
        "triple quoted with quotes",
        format!("\"\"\"{}\"\"\"", "a\"b\"\"c".repeat(N / 6)),
        K::STRING_TOKEN,
    );
    one(
        "raw string",
        format!("?\"{}\"", "a\\".repeat(N / 2)),
        K::STRING_TOKEN,
    );
    one(
        "quoted name",
        format!("`{}`", "a``".repeat(N / 3)),
        K::QUOTED_IDENT_TOKEN,
    );
    one("index", format!("[{}]", "1 ".repeat(N / 2)), K::INDEX_TOKEN);
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
    one("whitespace", " ".repeat(N), K::WHITESPACE);
}

#[test]
fn nested_comments_of_a_million_levels() {
    let one = |name, source: String| {
        let kinds = lex_on_small_stack(name, source);
        assert!(kinds.contains(&K::BLOCK_COMMENT), "{name}");
    };
    one(
        "opens then closes",
        format!("{}{}", "/*".repeat(N / 4), "*/".repeat(N / 4)),
    );
    one("opens and closes in turn", "/* /* */ ".repeat(N / 9) + "*/");
    one("slashes and stars", format!("/*{}*/", "/*/".repeat(N / 3)));
}

#[test]
fn runs_of_unterminated_openers_are_linear() {
    let run = |name, unit: &str| {
        let source = unit.repeat(N / unit.len());
        let kinds = lex_on_small_stack(name, source);
        assert!(!kinds.is_empty(), "{name}");
    };
    run("block comments", "/*");
    run("block comments with text", "/* a ");
    run("strings", "\"");
    run("escaped quotes", "\\\"");
    run("strings after a backslash", "\"\\");
    run("single quotes", "'");
    run("triple quotes", "\"\"\"");
    run("raw strings", "?\"");
    run("raw single quotes", "?'a");
    run("quoted names", "`a``");
    run("indexes", "[1 ");
    run("brackets", "[");
    run("bang brackets", "![");
    run("tildes", "a~");
    run("errors between openers", "~/*");
    run("errors between strings", "~\"");
    run("dots", ".");
    run("numbers with exponents", "1e");
    run("nested openers that never close", "/*/*/");
}
