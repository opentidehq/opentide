//! The parser's depth guards, on the 1 MB stack of the browser module: the
//! floors `crates/opentide-analysis/tests/deep_queries.rs` holds for ES|QL
//! (1,000 nesting levels, a 10,000-term chain) must parse without a
//! diagnostic, and deeper nesting is one diagnostic, never an overflow.
//!
//! The parser is private to the crate, so
//! this test includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser/mod.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

/// The stack the depth checks run on: the browser WASM module's 1 MB.
#[cfg(not(any(coverage, windows)))]
const SMALL_STACK: usize = 1 << 20;
/// A Windows debug build's frames are larger, and `cargo llvm-cov`'s
/// instrumentation enlarges every frame: the depths that fit 1 MB on Linux
/// overflowed the nightly's Windows engine tests. Neither binary is the WASM
/// budget, which the Linux and macOS test jobs keep enforcing at 1 MB; 8 MB is
/// a generous bound, not a measurement. The same rule as `SMALL_STACK` in
/// `crates/opentide-analysis/tests/deep_queries.rs`.
#[cfg(any(coverage, windows))]
const SMALL_STACK: usize = 8 << 20;

/// Parses on a [`SMALL_STACK`]; the number of errors.
fn errors(source: String) -> usize {
    eprintln!(
        "parsing {} bytes: {}",
        source.len(),
        &source[..source.len().min(60)]
    );
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || parser::parse(&source).errors.len())
        .map(|h| h.join().unwrap_or(usize::MAX))
        .unwrap_or(usize::MAX)
}

fn nest(atom: &str, n: usize) -> String {
    format!(
        "FROM logs-* | WHERE {}{atom}{}",
        "(".repeat(n),
        ")".repeat(n)
    )
}

#[test]
fn nesting_floor_chain_floor_and_the_limit() {
    assert_eq!(errors(nest("a == 1", 1_000)), 0);
    // The limit itself still fits the stack; past it, one diagnostic.
    assert_eq!(errors(nest("a == 1", 1_090)), 0);
    assert_eq!(errors(nest("a == 1", 10_000)), 1);
    let chain = vec!["a == 1"; 10_000].join(" OR ");
    assert_eq!(errors(format!("FROM logs-* | WHERE {chain}")), 0);
    let sum = vec!["a"; 10_000].join(" + ");
    assert_eq!(errors(format!("FROM logs-* | EVAL x = {sum}")), 0);
    let calls = format!("ROW x = {}1{}", "f(".repeat(500), ")".repeat(500));
    assert_eq!(errors(calls), 0);
    let subqueries = format!("{}FROM a{}", "FROM b, (".repeat(900), ")".repeat(900));
    assert_eq!(errors(subqueries), 0);
}

/// Every construct that recurses, at the nesting the floor asks of
/// parentheses (1,000) and past it (1,100), unclosed too, on a 1 MB stack:
/// none aborts. A call is charged two levels, so 1,000 calls are one
/// diagnostic, not a stack overflow.
#[test]
fn every_recursive_construct_survives_1000_and_1100_levels() {
    let wrap = |open: &str, close: &str, n: usize| {
        format!("FROM logs-* | WHERE {}1{}", open.repeat(n), close.repeat(n))
    };
    for n in [1_000, 1_100, 5_000] {
        let cases = [
            wrap("(", ")", n),
            wrap("f(", ")", n),
            wrap("f(", "", n),
            wrap("(", "", n),
            wrap("not ", "", n),
            wrap("- ", "", n),
            wrap("[", "]", n),
            wrap("f(1, {\"k\": ", "})", n),
            wrap("{\"k\": ", "}", n),
            wrap("a IN (", ")", n),
            format!("{}FROM a{}", "FROM b, (".repeat(n), ")".repeat(n)),
            format!("FROM a | {}WHERE x{}", "FORK (".repeat(n), ")".repeat(n)),
            format!("{}FROM a{}", "EXPLAIN (".repeat(n), ")".repeat(n)),
            format!(
                "FROM a | WHERE x IN {}FROM b{}",
                "(".repeat(n),
                ")".repeat(n)
            ),
            format!("FROM a | WHERE x{}", "::int".repeat(n)),
            format!("FROM a | WHERE {}", vec!["x"; n].join(" + ")),
        ];
        for (i, source) in cases.into_iter().enumerate() {
            // One diagnostic at most past the floor; the point is that it returns.
            let errors = errors(source);
            assert_ne!(
                errors,
                usize::MAX,
                "case {i} at {n} levels overflowed or panicked"
            );
        }
    }
    // The floor itself: 1,000 parentheses parse clean.
    assert_eq!(errors(wrap("(", ")", 1_000)), 0);
    // A call is two levels: 1,000 calls past the limit are one diagnostic.
    assert_eq!(errors(wrap("f(", ")", 1_000)), 1);
    assert_eq!(errors(wrap("f(", ")", 500)), 0);
}
