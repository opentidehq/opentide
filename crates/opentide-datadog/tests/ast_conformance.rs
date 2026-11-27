//! The typed AST of `datadog.ungram` (`src/generated/ast.rs`, written by `cargo xtask codegen`,
//! kept current by `codegen --check`) and its conformance: every tree of the corpus and of
//! Datadog's published queries that parses without an error has the shape the `.ungram` states,
//! node by node.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_datadog::ast::{self, RULES};
use opentide_parse::ast::AstNode;
use opentide_parse::conformance::check;

/// The corpus fixtures' queries and the published ones.
fn queries() -> Vec<String> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(format!("{root}/corpus/datadog")).expect("the corpus") {
        let text = std::fs::read_to_string(entry.expect("an entry").path()).expect("a file");
        out.push(text.lines().skip(1).collect::<Vec<_>>().join("\n"));
    }
    let published = std::fs::read_to_string(format!(
        "{root}/conformance/external/datadog/published.jsonl"
    ))
    .expect("published.jsonl");
    for line in published.lines() {
        let row: serde_json::Value = serde_json::from_str(line).expect("JSON");
        out.push(row["query"].as_str().expect("query").to_owned());
    }
    out
}

#[test]
fn every_tree_that_parses_conforms_to_the_ungram() {
    let (mut checked, mut bad) = (0, Vec::new());
    for query in queries() {
        let (root, errors) = opentide_datadog::debug_syntax(&query);
        if errors > 0 {
            continue;
        }
        checked += 1;
        let mismatches = check(&root, RULES, opentide_datadog::debug_grammar());
        if !mismatches.is_empty() {
            bad.push(format!("{query:?}: {mismatches:?}"));
        }
    }
    assert!(checked > 2_800, "{checked} trees checked");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn the_accessors_read_the_tree() {
    let (root, _) = opentide_datadog::debug_syntax("@evt.outcome:FAILURE OR @x:[1 TO 5]");
    let query = ast::Query::cast(root).expect("a query");
    let ast::Expr::OrExpr(or) = query.expr().expect("an expression") else {
        panic!("an OR at the top");
    };
    let mut clauses = or.exprs();
    let Some(ast::Expr::FieldClause(first)) = clauses.next() else {
        panic!("a field clause first");
    };
    assert!(matches!(first.field(), Some(ast::Field::Attribute(_))));
    let Some(ast::Expr::FieldClause(second)) = clauses.next() else {
        panic!("a field clause second");
    };
    let Some(ast::FieldValue::Range(range)) = second.value() else {
        panic!("a range");
    };
    assert!(range.lower().is_some() && range.upper().is_some());
    assert!(range.to_token().is_some());
}
