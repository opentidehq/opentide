//! The parser's depth guards, on the 1 MB stack of the browser module: the
//! floors `crates/opentide-analysis/tests/deep_queries.rs` holds for ES|QL
//! (1,000 nesting levels, a 10,000-term chain) must parse without a
//! diagnostic, and deeper nesting is one diagnostic, never an overflow.
//!
//! The parser is private to the crate (production still runs tree-sitter), so
//! this test includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser/mod.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

/// Parses on a 1 MB stack; the number of errors.
fn errors(source: String) -> usize {
    eprintln!(
        "parsing {} bytes: {}",
        source.len(),
        &source[..source.len().min(60)]
    );
    std::thread::Builder::new()
        .stack_size(1 << 20)
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
    let calls = format!("ROW x = {}1{}", "f(".repeat(900), ")".repeat(900));
    assert_eq!(errors(calls), 0);
    let subqueries = format!("{}FROM a{}", "FROM b, (".repeat(900), ")".repeat(900));
    assert_eq!(errors(subqueries), 0);
}
