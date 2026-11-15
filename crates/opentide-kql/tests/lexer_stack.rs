//! A logos regex with a repeated group over alternatives can make the
//! generated code recurse once per repetition: a long enough token aborts
//! the process on a small stack. Every token shape with such a group is
//! lexed here at a million repeats on a 1 MB stack, and an unclosed string
//! must stay linear (it takes the rest of the input as one error token).

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_kql::testing::lex_spans;

/// Lexes `source` on a 1 MB stack thread; the process aborts on an overflow.
fn lex_on_small_stack(source: String) -> Vec<(usize, usize, bool)> {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || lex_spans(&source))
        .expect("spawn")
        .join()
        .expect("the lexer panicked")
}

const N: usize = 1_000_000;

#[test]
fn long_tokens_do_not_recurse_per_repetition() {
    let cases: Vec<(&str, String)> = vec![
        ("double-quoted", format!("\"{}\"", "a".repeat(N))),
        ("double-quoted escapes", format!("\"{}\"", "\\\"".repeat(N))),
        ("single-quoted", format!("'{}'", "a".repeat(N))),
        ("single-quoted escapes", format!("'{}'", "\\'".repeat(N))),
        ("verbatim", format!("@\"{}\"", "a".repeat(N))),
        ("verbatim doubled", format!("@\"{}\"", "\"\"".repeat(N))),
        ("verbatim single", format!("@'{}'", "''".repeat(N))),
        ("backtick fence", format!("```{}```", "`a".repeat(N))),
        ("tilde fence", format!("~~~{}~~~", "~a".repeat(N))),
        ("quoted ident", format!("['{}']", "a".repeat(N))),
        (
            "quoted ident escapes",
            format!("[\"{}\"]", "\\\"".repeat(N)),
        ),
        ("word", "a".repeat(N)),
        ("hint", format!("hint.{}", "a".repeat(N))),
        ("number", "1".repeat(N)),
        ("timespan", format!("{}m", "1".repeat(N))),
        ("typed literal", format!("datetime({})", "1".repeat(N))),
        ("comment", format!("//{}", "a".repeat(N))),
        ("white space", " ".repeat(N)),
        ("bang word", format!("!{}", "a".repeat(N))),
        ("unclosed string", format!("\"{}", "a".repeat(N))),
        ("unclosed escapes", format!("\"{}", "\\\"".repeat(N))),
        ("unclosed fences", "`` ".repeat(N)),
    ];
    for (name, source) in cases {
        let len = source.len();
        let started = std::time::Instant::now();
        let spans = lex_on_small_stack(source);
        // Linear: a scan per broken string, not one per character after it.
        assert!(
            started.elapsed().as_secs() < 10,
            "{name}: {:?}",
            started.elapsed()
        );
        let end = spans.last().map_or(0, |s| s.1);
        assert_eq!(end, len, "{name}: lexemes tile the source");
    }
}
