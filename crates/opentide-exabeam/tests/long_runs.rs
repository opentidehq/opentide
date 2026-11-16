//! Inputs that stress the lexer and the parser, on the 1 MB stack of the
//! browser module: one very long token of every piece class, one very long
//! chain, and nesting past the parser's limit. None may overflow the stack,
//! hang, or lose a byte.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_exabeam::{debug_parse, highlight_captures, tree_has_error};

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

#[test]
fn one_huge_token_of_every_kind() {
    on_small_stack(|| {
        for source in [
            format!("a:{}", "x".repeat(MILLION)),
            format!("a:{}", "1".repeat(MILLION)),
            format!("{}:1", "a".repeat(MILLION)),
            format!("{}a:1", "a.".repeat(MILLION / 2)),
            format!("{}:1", "AS".repeat(MILLION / 2)),
            format!("a:\"{}\"", "\\\"".repeat(MILLION / 2)),
            format!("a:'{}", "x".repeat(MILLION)),
            format!("a:[{} TO 1]", "z".repeat(MILLION)),
            format!("a:{}", "@".repeat(MILLION)),
            format!("a:{}", "é".repeat(MILLION / 2)),
            "*".repeat(MILLION),
            format!("a:{}", "-".repeat(MILLION)),
            format!("a:1.{}", "2".repeat(MILLION)),
            format!("a:{}1", " \t\r\n\x0b\x0c".repeat(MILLION / 6)),
            format!("a:{}", "+".repeat(MILLION)),
            format!("a:{}", ".".repeat(MILLION)),
        ] {
            eprintln!("{}", source.chars().take(12).collect::<String>());
            assert!(assert_tiled(&source) > 0);
        }
        // Every other piece class: each is one character, and a run of them
        // is a run of errors after the term.
        for piece in [
            "(", ")", "[", "]", "{", "}", ",", ":", "=", "<", ">", "!", "|",
        ] {
            let source = format!("a:1 {}", piece.repeat(MILLION / 10));
            eprintln!("{piece}");
            assert_tiled(&source);
        }
        // Quotes that never close, each an error at which lexing restarts.
        for quote in ["\"", "'"] {
            let source = format!("a:{}", format!("\\{quote}").repeat(MILLION / 2));
            assert_tiled(&source);
        }
    });
}

/// The captures lie inside `source`, in order and apart; how many there are.
fn assert_tiled(source: &str) -> usize {
    let captures = highlight_captures(source);
    let mut end = 0;
    for (span, _) in &captures {
        assert!(span.start >= end && span.end > span.start, "{span:?}");
        end = span.end;
    }
    assert!(end <= source.len());
    captures.len()
}

#[test]
fn a_long_chain_stays_flat() {
    on_small_stack(|| {
        let or = "a:1 OR ".repeat(20_000) + "a:2";
        assert!(!tree_has_error(&or));
        let and = "m AND ".repeat(20_000) + "m";
        assert!(!highlight_captures(&and).is_empty());
        let implicit = "m ".repeat(20_000) + "m";
        assert!(!tree_has_error(&implicit));
        let nots = "NOT ".repeat(100_000) + "m";
        assert!(!tree_has_error(&nots));
        let list = format!("a:({})", "x, ".repeat(100_000) + "x");
        assert!(!tree_has_error(&list));
        let pipes = "a | ".repeat(20_000) + "a";
        assert!(!tree_has_error(&pipes));
    });
}

#[test]
fn nesting_past_the_limit_is_one_error_and_never_a_stack_overflow() {
    on_small_stack(|| {
        for source in [
            "(".repeat(200_000),
            format!("{}m{}", "(".repeat(200_000), ")".repeat(200_000)),
            format!("{}a", "NOT (".repeat(100_000)),
            format!("{}a", "a OR (".repeat(100_000)),
        ] {
            let _ = highlight_captures(&source);
        }
        // Past the analysis' own limit (200, `deep_queries`' floor), and past
        // the parser's.
        let ok = format!("{}a:1{}", "(".repeat(500), ")".repeat(500));
        assert!(!tree_has_error(&ok));
        // Under 64 KiB, so the thread keeps the deep tree (`parse_memo`) and
        // drops it at its exit, on the same small stack.
        let kept = format!("a OR b c AND NOT {}x{}", "(".repeat(510), ")".repeat(510));
        assert!(!tree_has_error(&kept));
        assert_tiled(&kept);
        let deep = format!("{}a:1{}", "(".repeat(2_000), ")".repeat(2_000));
        let dump = debug_parse(&deep);
        assert_eq!(dump.matches("nesting deeper than 512 levels").count(), 1);
    });
}
