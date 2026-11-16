//! The analysis on the new tree walks it recursively; on a 1 MB stack (the
//! browser's) it must survive whatever the parser accepts (#1230). That it
//! agrees with the tree-sitter engine where that engine did not overflow is
//! `tests/differential.rs`'s `the_budget_reads_as_deep_as_the_old_engine`.
//!
//! Found by review (#1399): on a 1 MB stack in a debug build the column pass
//! overflowed at 65 nested `join`s, 91 nested `mv-apply`s, 200 nested
//! `union`s and a chain of 841 members or indexes, all inside the parser's
//! nesting limit or not bounded by it; and a function that calls itself
//! (`let f = () { f() }; f()`) recursed until the stack ran out (the
//! tree-sitter pass does too).

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_kql::{Catalog, Profile, analyze_with_catalog, columns, hover};

/// Runs `run` on a thread with a stack of `size` bytes; an overflow aborts.
fn on_stack<T: Send + 'static>(size: usize, run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(size)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("the analysis panicked")
}

/// Every surface that reads the tree, on a 1 MB stack: the codes of the
/// diagnostics.
fn analyze_small(source: String) -> Vec<String> {
    on_stack(1 << 20, move || {
        let catalog = Catalog::for_workspace(Profile::Sentinel, &source);
        let codes = analyze_with_catalog(&source, &catalog)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect();
        let _ = columns(&source, Profile::Sentinel);
        let _ = hover(&source, source.len() / 2, Profile::Sentinel);
        codes
    })
}

fn deep(kind: &str, n: usize) -> String {
    match kind {
        "member" => format!("T | where {} == 1", vec!["a"; n].join(".")),
        "index" => format!("T | where a{} == 1", "[0]".repeat(n)),
        "union" => format!("{}T{}", "union (".repeat(n), ")".repeat(n)),
        "join" => format!("T{}{}", " | join (T".repeat(n), ") on a".repeat(n)),
        "mv-apply" => format!(
            "T{}{}",
            " | mv-apply x on (where b".repeat(n),
            ")".repeat(n)
        ),
        "pipeline" => format!("{}T | take 1{}", "(".repeat(n), ")".repeat(n)),
        "expression" => format!("T | where {}a == 1{}", "(".repeat(n), ")".repeat(n)),
        _ => unreachable!("{kind}"),
    }
}

const KINDS: [&str; 7] = [
    "member",
    "index",
    "union",
    "join",
    "mv-apply",
    "pipeline",
    "expression",
];

#[test]
fn deep_queries_do_not_overflow_a_small_stack() {
    for kind in KINDS {
        // 250 levels: inside the parser's nesting limit; 1,000 members or
        // indexes: a chain it does not bound.
        let n = if matches!(kind, "member" | "index") {
            1_000
        } else {
            250
        };
        let codes = analyze_small(deep(kind, n));
        assert!(
            !codes.iter().any(|c| c == "kql_parse_error"),
            "{kind} {n}: {codes:?}"
        );
    }
}

#[test]
fn a_function_that_calls_itself_is_read_once() {
    for source in [
        "let f = () { f() };\nf()",
        "let f = () { f() | union f() };\nf()",
        "let g = () { T };\nlet f = () { g() | union f() };\nf() | where x == 1",
    ] {
        let codes = analyze_small(source.to_owned());
        assert!(!codes.iter().any(|c| c == "kql_parse_error"), "{source}");
    }
}
