//! The typed AST of `eql.ungram` (`src/generated/ast.rs`, written by `cargo xtask codegen`,
//! kept current by `codegen --check`) and its conformance: every tree of the corpus that parses
//! without an error has the shape the `.ungram` states, node by node. The parser is private to
//! the crate until the switch, so this test includes its source.

#![expect(
    dead_code,
    unused_imports,
    reason = "the included modules are used in part"
)]
#![expect(clippy::expect_used, reason = "a test")]

#[path = "../src/generated/ast.rs"]
mod ast;
#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::ast::AstNode;
use opentide_parse::conformance::check;
use std::path::{Path, PathBuf};
pub(crate) use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

fn eql_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "eql") {
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
    for path in eql_files() {
        let source = std::fs::read_to_string(&path).expect("read");
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
    assert!(checked > 100, "checked {checked} trees");
}

#[test]
fn the_typed_ast_reads_a_query() {
    let source = "sequence by k with maxspan=5m [process where a == 1] [file where f(b)] | head 3";
    let parse = parser::parse(source);
    assert!(parse.errors.is_empty(), "{:?}", parse.errors);
    let root = ast::SourceFile::cast(SyntaxNode::new_root(parse.green)).expect("a source file");
    let Some(ast::Query::Sequence(sequence)) = root.query() else {
        panic!("a sequence");
    };
    assert_eq!(sequence.by().next().expect("keys").syntax().to_string(), "by k");
    let unit = sequence
        .params()
        .next()
        .and_then(|p| p.maxspan())
        .expect("a maxspan");
    assert_eq!(unit.value().expect("a value").syntax().to_string(), "5");
    assert_eq!(unit.unit().expect("a unit").syntax().to_string(), "m");
    assert_eq!(sequence.sequence_terms().count(), 2);
    let pipe = root.pipe_stages().next().expect("a pipe");
    assert_eq!(pipe.name().expect("a name").syntax().to_string(), "head");
}
