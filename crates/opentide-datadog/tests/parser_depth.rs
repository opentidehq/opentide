//! Inputs that stress the lexer and the parser, on the 1 MB stack of the browser module: one
//! token of every class a million characters long, runs of every one-character piece, a term of
//! a million glued pieces, chains of modifiers, and nesting past the limit. None may overflow
//! the stack, hang, or lose a byte (ADR 0012, decision 4).

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_datadog::{Context, analyze_with, debug_roundtrip};

/// Runs `f` on a thread with a 1 MB stack, as the browser module has.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .expect("a thread")
        .join()
        .expect("no stack overflow, no panic");
}

const MILLION: usize = 1_000_000;

/// The tree is the source, and the analysis (checks, highlight) runs: the number of syntax
/// errors.
fn lossless(source: &str) -> usize {
    let (text, errors) = debug_roundtrip(source);
    assert!(text == source, "the tree lost bytes");
    let _ = analyze_with(source, &Context::RULE);
    errors
}

#[test]
fn one_huge_token_of_every_class() {
    on_small_stack(|| {
        for source in [
            "x".repeat(MILLION),
            format!("@a:{}", "x".repeat(MILLION)),
            format!("@{}:1", "a.".repeat(MILLION / 2)),
            format!("#{}:1", "a".repeat(MILLION)),
            format!("@a:{}", "1".repeat(MILLION)),
            format!("@a:>={}ms", "1".repeat(MILLION)),
            format!("@a:\"{}\"", "\\\"".repeat(MILLION / 2)),
            format!("@a:\"{}", "x".repeat(MILLION)),
            format!("\"{}\"", "é".repeat(MILLION / 2)),
            format!("@a:{}", "\\ ".repeat(MILLION / 2)),
            format!("@a:[{} TO 1]", "z".repeat(MILLION)),
            format!("CIDR(@ip, {})", "1".repeat(MILLION)),
            format!("CIDR(@{}, 10.0.0.0/8)", "a".repeat(MILLION)),
            format!("a{}", " \t\r\n".repeat(MILLION / 4)),
            format!("{}a", "\u{feff}".repeat(MILLION / 3)),
            "“".repeat(MILLION / 3),
            "é".repeat(MILLION / 2),
            format!("@a:{}", "\u{feff}".repeat(MILLION / 3)),
            format!("a{}", "\u{a0}".repeat(MILLION / 2)),
        ] {
            eprintln!("{}", source.chars().take(12).collect::<String>());
            lossless(&source);
        }
    });
}

#[test]
fn runs_of_every_piece() {
    on_small_stack(|| {
        for piece in [
            "*", "?", ":", ",", "-", "+", "=", "!", "~", "^", "<", "<=", ">", ">=", "(", ")", "[",
            "]", "{", "}", "\\", "\"", "&&", "||",
        ] {
            // A one-character piece has no repetition in its pattern: a run of them is many
            // tokens, not one long one, so 100,000 pieces show the parser's handling of each
            // (`long_runs.rs` holds the growth).
            for source in [
                piece.repeat(MILLION / 10 / piece.len()),
                format!("@a:{}", format!("{piece} ").repeat(MILLION / 40)),
            ] {
                eprintln!("{piece}");
                lossless(&source);
            }
        }
    });
}

#[test]
fn a_term_of_a_million_glued_pieces() {
    on_small_stack(|| {
        for source in [
            format!("@a:{}", "b:".repeat(MILLION / 2)),
            format!("@a:{}", "b*".repeat(MILLION / 2)),
            format!("@a:{}", "b!".repeat(MILLION / 2)),
            format!("{}:x", "a-".repeat(MILLION / 2)),
            format!("@a:{}", "\"b\"".repeat(MILLION / 3)),
        ] {
            lossless(&source);
        }
    });
}

#[test]
fn chains_of_modifiers_and_operators() {
    on_small_stack(|| {
        for source in [
            format!("{}a", "-".repeat(MILLION)),
            format!("{}a", "NOT ".repeat(MILLION / 4)),
            format!("{}a", "- ".repeat(MILLION / 2)),
            format!("a{}", " OR".repeat(MILLION / 3)),
            format!("a{}", " AND".repeat(MILLION / 4)),
            format!("a{}", " a".repeat(MILLION / 2)),
            format!("a{}", " OR a".repeat(MILLION / 5)),
        ] {
            lossless(&source);
            // However many errors recovery records, the query gets one diagnostic.
            let errors = analyze_with(&source, &Context::RULE)
                .diagnostics
                .iter()
                .filter(|d| d.severity == opentide_core::Severity::Error)
                .count();
            assert!(errors <= 1, "{}: {errors} errors", &source[..8]);
        }
    });
}

#[test]
fn nesting_past_the_limit_is_one_error() {
    on_small_stack(|| {
        for source in [
            "(".repeat(MILLION),
            format!("{}a{}", "(".repeat(MILLION / 2), ")".repeat(MILLION / 2)),
            "@a:(".repeat(MILLION / 4),
            "-(".repeat(MILLION / 2),
            "NOT(".repeat(MILLION / 4),
            format!("@a:{}", "(".repeat(MILLION)),
        ] {
            assert_eq!(lossless(&source), 1, "{}", &source[..8]);
        }
    });
}

/// A valid term of six million pieces: looking for a field's colon must not run the parser's
/// fuel out (2^24 lookups without progress), as an unbounded lookahead did.
#[test]
fn a_huge_term_parses() {
    on_small_stack(|| {
        for source in [
            "a*".repeat(3_000_000),
            format!("{}:x", "a*".repeat(3_000_000)),
        ] {
            let (text, errors) = debug_roundtrip(&source);
            assert!(text == source && errors == 0, "{errors} errors");
        }
    });
}
