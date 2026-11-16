//! The parser over every ES|QL file of the corpora: a lossless tree.
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
fn every_corpus_file_parses_losslessly() {
    let files = corpus();
    assert!(files.len() > 150, "{} files", files.len());
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let parse = parser::parse(&source);
        let tree = rowan::SyntaxNode::<syntax::Lang>::new_root(parse.green);
        assert_eq!(
            tree.to_string(),
            source,
            "{} is not lossless",
            path.display()
        );
    }
}
