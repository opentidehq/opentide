//! A long run of escapes must not overflow the stack: logos compiles a
//! repeated regex group into recursion, so the lexer scans a word by hand.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_kuery::debug_parse;
use std::thread;

fn on_small_stack(input: String) {
    thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let tree = debug_parse(&input);
            assert!(tree.starts_with("SourceFile@0.."));
        })
        .expect("a thread")
        .join()
        .expect("the parse overflowed or panicked");
}

#[test]
fn a_million_escapes_in_a_word() {
    on_small_stack(r"\:".repeat(1_000_000));
}

#[test]
fn a_run_of_other_escapes() {
    on_small_stack(r"\\".repeat(500_000));
    on_small_stack("\\".repeat(1_000_001));
    on_small_stack(r"\u00e9".repeat(200_000));
    on_small_stack(r"\and\or\not".repeat(100_000));
}

#[test]
fn a_long_quoted_string() {
    on_small_stack(format!("\"{}\"", r#"\""#.repeat(500_000)));
    on_small_stack(format!("a:\"{}", "x ".repeat(500_000)));
}
