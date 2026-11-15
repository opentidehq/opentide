//! A tree snapshot per ES|QL corpus file: the tree and the errors of the
//! pure-Rust parser, one `insta` snapshot each (`tests/snapshots/`). A change
//! to the grammar shows as a reviewed snapshot diff.
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

use opentide_parse::{debug_errors, debug_tree};
use syntax::{Lang, SyntaxKind};

fn kind_name(raw: rowan::SyntaxKind) -> String {
    format!("{:?}", <Lang as rowan::Language>::kind_from_raw(raw))
}

#[test]
fn trees_of_the_corpus() {
    insta::glob!("../../testdata", "**/*.esql", |path| {
        let source = std::fs::read_to_string(path).unwrap_or_default();
        let parse = parser::parse(&source);
        let root = rowan::SyntaxNode::<Lang>::new_root(parse.green);
        let tree = debug_tree(&root, |k: SyntaxKind| format!("{k:?}"));
        let errors = debug_errors(&parse.errors, kind_name);
        insta::assert_snapshot!(format!("{tree}--- errors\n{errors}"));
    });
}

/// Broken queries: where the parser reports, what it wraps, how it goes on.
#[test]
fn recovery() {
    for (name, source) in [
        ("missing_condition", "FROM a | WHERE | LIMIT 1"),
        ("unclosed_paren", "FROM a | WHERE (x == 1 | LIMIT 1"),
        ("stray_close", "FROM a | WHERE x == 1) | LIMIT 1"),
        ("empty_pipe", "FROM a | | LIMIT 1"),
        ("no_source", "| LIMIT 1"),
        ("double_operator", "FROM a | EVAL x = 1 + * 2"),
        ("unclosed_call", "FROM a | EVAL x = f(1, 2 | LIMIT 1"),
        ("trailing_comma", "FROM a | KEEP a, b,"),
        ("bad_string", "FROM a | WHERE x == \"abc"),
        ("tuple_without_subquery", "FROM a | WHERE (x, y) IN (1, 2)"),
        ("unclosed_promql", "PROMQL (rate(x)"),
        ("set_without_semicolon", "SET a = 1 FROM a"),
    ] {
        let parse = parser::parse(source);
        let errors = debug_errors(&parse.errors, kind_name);
        let root = rowan::SyntaxNode::<Lang>::new_root(parse.green);
        let tree = debug_tree(&root, |k: SyntaxKind| format!("{k:?}"));
        insta::assert_snapshot!(name, format!("{source}\n{tree}--- errors\n{errors}"));
    }
}
