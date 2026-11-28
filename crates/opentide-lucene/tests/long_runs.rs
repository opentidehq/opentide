//! A long run of any one token class must not overflow a 1 MB stack (the
//! browser WASM module's): every token class at 1,000,000 repeats, inside
//! one token and as a run of tokens.

#![expect(
    clippy::string_slice,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_lucene::debug_parse;
use std::thread;

const N: usize = 1_000_000;

fn on_small_stack(input: String) {
    thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let tree = debug_parse(&input);
            assert!(tree.starts_with("SourceFile@0.."), "{}", &tree[..80]);
        })
        .expect("a thread")
        .join()
        .expect("the parse overflowed or panicked");
}

#[test]
fn a_million_repeats_inside_one_token() {
    // Term, wildcard term, phrase, regexp, range bound, boost, fuzzy.
    on_small_stack(r"\:".repeat(N));
    on_small_stack("a".repeat(N));
    on_small_stack("a*".repeat(N));
    on_small_stack("?".repeat(N));
    on_small_stack(format!("\"{}\"", r#"\""#.repeat(N)));
    on_small_stack(format!("\"{}", "x ".repeat(N)));
    on_small_stack(format!("/{}/", r"\/".repeat(N)));
    on_small_stack(format!("/{}", "x".repeat(N)));
    on_small_stack(format!("a:[{} TO b]", "x".repeat(N)));
    on_small_stack(format!("a:[\"{}\" TO b]", r#"\""#.repeat(N)));
    on_small_stack(format!("a^{}", "1".repeat(N)));
    on_small_stack(format!("a^1.{}", "5".repeat(N)));
    on_small_stack(format!("a~{}", "b".repeat(N)));
    on_small_stack(format!("a~{}", r"\~".repeat(N)));
    on_small_stack(" ".repeat(N));
    on_small_stack("\u{3000}".repeat(N));
    on_small_stack(format!("a:[{}", " ".repeat(N)));
}

fn runs(units: &[&str]) {
    for unit in units {
        on_small_stack(unit.repeat(N));
    }
}

// Runs of tokens, split so the test runner spreads them over its threads.

#[test]
fn a_million_terms_and_values() {
    runs(&["a ", "* ", "a* ", "\"x\" ", "/x/ ", "a^2 ", "a~ ", "TO "]);
}

#[test]
fn a_million_operators_and_modifiers() {
    runs(&[
        "- ", "+ ", "! ", "AND ", "OR ", "NOT ", "&& ", "|| ", "a AND ", "a && ", "+a ", "-a ",
        "!a ", "NOT a ",
    ]);
}

#[test]
fn a_million_fields_groups_and_ranges() {
    runs(&[
        "a:",
        "a:b ",
        "(",
        ")",
        "(a) ",
        "[",
        "]",
        "{",
        "}",
        "[a TO b] ",
        "{a TO *} ",
    ]);
}

#[test]
fn a_million_stray_characters() {
    runs(&["^", "~", "\\", "\"", "/", ":"]);
}
