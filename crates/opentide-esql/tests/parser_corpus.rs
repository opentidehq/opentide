//! The parser over every ES|QL file of the corpora: a lossless tree, and the
//! verdict tree-sitter gave (an error or none).
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

use std::path::{Path, PathBuf};

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
fn every_corpus_file_has_the_verdict_tree_sitter_gave() {
    let mut wrong = Vec::new();
    let mut total = 0;
    for path in corpus() {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let parse = parser::parse(&source);
        let tree = rowan::SyntaxNode::<syntax::Lang>::new_root(parse.green);
        assert_eq!(
            tree.to_string(),
            source,
            "{} is not lossless",
            path.display()
        );
        let old = opentide_syntax::parse(opentide_core::LanguageId::Esql, &source).unwrap();
        let old_error = opentide_syntax::first_error(old.root_node()).is_some();
        total += 1;
        if old_error == parse.errors.is_empty() {
            let first = parse.errors.first().map(|e| (e.gap, e.message.clone()));
            wrong.push(format!(
                "{}: tree-sitter error {old_error}, new {first:?}",
                path.display()
            ));
        }
    }
    assert!(total > 150);
    assert!(
        wrong.is_empty(),
        "{} files differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
