//! The typed AST of `esql.ungram` (`src/generated/ast.rs`, written by
//! `cargo xtask codegen`, kept current by `codegen --check`) and its
//! conformance: every tree of the corpus that parses without an error has
//! the shape the `.ungram` states, node by node.
//!
//! The parser is private to the crate, so
//! this test includes its source.

#![expect(
    dead_code,
    unused_imports,
    reason = "the included modules are used in part"
)]
#![expect(
    clippy::enum_variant_names,
    clippy::wrong_self_convention,
    reason = "the generated AST names its types and variants as the grammar does"
)]

#[path = "../src/generated/ast.rs"]
mod ast;
#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser/mod.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::ast::AstNode;
use opentide_parse::conformance::{assert_conforms, check};
use std::path::{Path, PathBuf};

pub(crate) use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

/// Every `.esql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "esql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

#[test]
fn every_corpus_tree_conforms_to_the_ungram() {
    let mut checked = 0;
    let mut bad = Vec::new();
    for path in corpus() {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let parse = parser::parse(&source);
        if !parse.errors.is_empty() {
            continue;
        }
        let root = SyntaxNode::new_root(parse.green);
        for mismatch in check(&root, ast::RULES, parser::GRAMMAR) {
            bad.push(format!("{}: {mismatch}", path.display()));
        }
        checked += 1;
    }
    assert!(
        bad.is_empty(),
        "{} mismatches:\n{}",
        bad.len(),
        bad.join("\n")
    );
    assert!(checked > 120, "checked {checked} trees");
}

/// Beyond the corpus: one query per command and per expression form, among
/// them the casts of a primary expression (a `LIKE` pattern, the input of
/// `GROK`, `DISSECT` and the extract commands), which the corpus does not
/// have and which once built an `INLINE_CAST` without its `TYPE_NAME`.
#[test]
fn every_command_and_expression_form_conforms() {
    for source in [
        "ROW a = -1::long, b = x::int::long, c = (1 + 2)::int, d = f(x)::int, e = 1 hour::time_duration",
        "FROM a | WHERE x LIKE \"a\"::keyword::text AND y NOT RLIKE \"b\"::keyword",
        "FROM a | WHERE x LIKE (\"a\", ?p) OR x::keyword : \"q\"",
        "FROM a | GROK x::keyword \"%{WORD:a}\", \"%{NUMBER:b}\"",
        "FROM a | DISSECT a.b::keyword \"%{x}\" APPEND_SEPARATOR = \",\"",
        "FROM a | URI_PARTS p = url.full::keyword",
        "FROM a | REGISTERED_DOMAIN d = TO_LOWER(host.name)",
        "FROM a | USER_AGENT ua = message WITH {\"properties\": [\"name\"]}",
        "FROM a | IP_LOCATION g = source.ip",
        "FROM a | DENSE_VECTOR e = message::keyword WITH {\"inference_id\": \"m\"}",
        "FROM a | HIGHLIGHT \"q\" ON host.*, message WITH {\"k\": 1}",
        "FROM a | MMR ?q ON a LIMIT 10 WITH {\"lambda\": 0.5}",
        "FROM a | RERANK r = \"q\" ON message, b = TO_LOWER(x) WITH {\"inference_id\": \"m\"}",
        "FROM a | COMPLETION r = CONCAT(a, b) WITH {\"inference_id\": \"x\"}",
        "FROM a | WHERE host.name IN (FROM b | KEEP host.name)",
        "FROM a | WHERE (host.name, user.name) NOT IN (FROM b | KEEP host.name, user.name)",
        "FROM a | EVAL ?p = x + 1 | STATS ??q = COUNT(*) WHERE x > 1 BY h = BUCKET(@timestamp, 1 hour)",
        "FROM a | LOOKUP JOIN idx AS q ON a == q.b",
        "FROM a | FUSE LINEAR SCORE BY s KEY BY a, b GROUP BY g WITH {\"w\": 1}",
        "FROM a | ENRICH _remote:policy ON host.name WITH n = x, y",
        "FROM a | CHANGE_POINT v ON t AS ty, pv BY h",
        "FROM a | FORK (WHERE a | EVAL b = 1) (STATS c = COUNT(*)) (LIMIT 1)",
        "FROM a | SORT a ASC NULLS LAST, b DESC | LIMIT 10 BY a, b | FILLNULL 0 ON a, b*",
        "FROM a | KEEP `a b`, a*.b, ?p | DROP a.* | RENAME a AS b, c = d | MV_EXPAND a.b",
        "FROM a, b::failures, c:d, \"e\" METADATA _id, _index | SAMPLE 0.5 | DEDUP",
        "SET a = 1; SET b = {\"x\": \"y\"}; EXPLAIN (FROM a | LIMIT 1)",
    ] {
        let parse = parser::parse(source);
        assert!(parse.errors.is_empty(), "{source}: {:?}", parse.errors);
        let root = SyntaxNode::new_root(parse.green);
        let bad = check(&root, ast::RULES, parser::GRAMMAR);
        assert!(
            bad.is_empty(),
            "{source}: {}",
            bad.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
