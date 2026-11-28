//! Inputs that stress the lexer and the parser, on the 1 MB stack of the
//! browser module: one very long token, one very long chain, and nesting past
//! the parser's limit. None may overflow the stack, hang, or lose a byte.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_falco::{Context, highlight_captures, hover, hover_target, tree_fields};

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
            format!("a.b = {}", "x".repeat(MILLION)),
            format!("a.b = {}", "1".repeat(MILLION)),
            format!("{}.b = 1", "a".repeat(MILLION)),
            format!("{} = 1", "a.".repeat(MILLION / 2)),
            format!("a.b = \"{}\"", "\\\"".repeat(MILLION / 2)),
            format!("a.b = '{}", "x".repeat(MILLION)),
            format!("a.b[{}] = 1", "z".repeat(MILLION)),
            format!("a.b = {}", "<".repeat(MILLION)),
            format!("a.b = {}", "é".repeat(MILLION / 2)),
            // Every class of the `Number` and `Whitespace` regexes.
            format!("a.b = 0x{}", "f".repeat(MILLION)),
            format!("a.b = 1.{}", "2".repeat(MILLION)),
            format!("a.b = 1e+{}", "3".repeat(MILLION)),
            format!("a.b ={}1", " \t\r\n\x0c\x08".repeat(MILLION / 6)),
            format!("len(a.b, 1.{}) = 1", "2".repeat(MILLION)),
        ] {
            let spans = highlight_captures(&source);
            assert!(!spans.is_empty());
            assert!(tree_fields(&source).len() <= 1);
        }
    });
}

#[test]
fn a_long_chain_stays_flat() {
    on_small_stack(|| {
        let or = "a.b = 1 or ".repeat(20_000) + "a.b = 2";
        assert_eq!(tree_fields(&or), ["a.b"]);
        let and = "m and ".repeat(20_000) + "m";
        assert!(!highlight_captures(&and).is_empty());
        let nots = "not ".repeat(100_000) + "m";
        assert!(!highlight_captures(&nots).is_empty());
        let list = format!("a.b in ({})", "x, ".repeat(100_000) + "x");
        assert!(!highlight_captures(&list).is_empty());
    });
}

#[test]
fn nesting_past_the_limit_is_one_error_and_never_a_stack_overflow() {
    on_small_stack(|| {
        for source in [
            "(".repeat(200_000),
            format!("{}m{}", "(".repeat(200_000), ")".repeat(200_000)),
            format!("{}a.b{}", "tolower(".repeat(200_000), ")".repeat(200_000)),
            format!("{}a.b", "not (".repeat(100_000)),
        ] {
            let _ = highlight_captures(&source);
            let _ = tree_fields(&source);
        }
        // What the old engine accepted (`deep_queries`' floor) and well past it.
        let ok = format!("{}a.b = 1{}", "(".repeat(500), ")".repeat(500));
        assert_eq!(tree_fields(&ok), ["a.b"]);
        // Past it: exactly one diagnostic, and the rest of the input in one error node.
        let deep = format!("{}a.b = 1{}", "(".repeat(2_000), ")".repeat(2_000));
        let dump = opentide_falco::debug_parse(&deep);
        assert_eq!(dump.matches("nesting deeper than 512 levels").count(), 1);
    });
}

/// Raised by review (#1404): hover found its token with rowan's
/// `token_at_offset`, which recurses once per tree level. 600 nested
/// `m or m and not (` give the deepest tree the parser builds, about 2,050
/// levels (or, and, not, parentheses per level). Hover, highlight and fields
/// on the innermost `m` must fit the 1 MB stack. (On x86-64 debug builds the
/// recursive lookup used about 520 KB here; `cst`'s unit test shows it
/// overflowing on a deeper tree.)
#[test]
fn hover_in_a_deep_tree_fits_a_small_stack() {
    on_small_stack(|| {
        let source = "m or m and not (".repeat(600) + "m";
        let innermost = source.len() - 1;
        assert_eq!(
            hover_target(&source, innermost),
            Some(("identifier", "m".to_owned()))
        );
        let _ = hover(&source, innermost, &Context::default());
        // The first `m`, a keyword in the middle, a blank, and the end.
        for at in [0, source.len() / 2, 1, source.len()] {
            let _ = hover_target(&source, at);
        }
        assert!(!highlight_captures(&source).is_empty());
        assert!(tree_fields(&source).is_empty());
    });
}
