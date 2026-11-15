//! The lexer over every ES|QL file of the corpora: it tiles them, and reads
//! the tokens tree-sitter's context-aware lexer read.
//!
//! The lexer is private to the crate (production still runs tree-sitter), so
//! this test includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/syntax.rs"]
mod syntax;

use std::path::{Path, PathBuf};
use syntax::SyntaxKind as K;

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

fn text<'s>(source: &'s str, l: &opentide_parse::Lexeme) -> &'s str {
    &source[std::ops::Range::<usize>::from(l.range)]
}

#[test]
fn lexemes_tile_every_corpus_file_and_valid_ones_have_no_error_token() {
    let files = corpus();
    assert!(files.len() > 150, "found {} corpus files", files.len());
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let lexemes = lexer::lex(&source);
        let joined: String = lexemes.iter().map(|l| text(&source, l)).collect();
        assert_eq!(joined, source, "{} is not tiled", path.display());
        let name = path.to_string_lossy();
        let broken = name.contains("__invalid") || name.contains(".broken.");
        let errors = lexemes
            .iter()
            .filter(|l| l.kind == K::ERROR_TOKEN.raw())
            .count();
        assert!(broken || errors == 0, "{name}: {errors} error tokens");
    }
}

/// The modes reproduce what tree-sitter's lexer read, token for token, on
/// every corpus file it parses without an error.
#[test]
fn tokens_are_the_leaves_tree_sitter_read() {
    let mut compared = 0;
    for path in corpus() {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let tree = opentide_syntax::parse(opentide_core::LanguageId::Esql, &source).unwrap();
        if opentide_syntax::first_error(tree.root_node()).is_some() {
            continue;
        }
        let mut leaves = Vec::new();
        opentide_syntax::walk(tree.root_node(), |node| {
            if node.child_count() == 0 && node.end_byte() > node.start_byte() {
                leaves.push((node.start_byte(), node.end_byte()));
            }
        });
        let ours: Vec<_> = lexer::lex(&source)
            .iter()
            .filter(|l| l.kind != K::WHITESPACE.raw())
            .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
            .collect();
        assert_eq!(ours, leaves, "{}", path.display());
        compared += 1;
    }
    assert!(compared > 120, "compared {compared} files");
}
