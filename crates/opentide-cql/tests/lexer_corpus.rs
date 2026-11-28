//! The lexer over every CQL file of the corpora: it tiles them, and a valid one has no
//! error token.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_cql::{lexer, syntax};

use std::path::{Path, PathBuf};
use syntax::SyntaxKind as K;

/// Every `.cql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "cql") {
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
            .filter(|l| l.kind == K::ERROR_TOKEN.raw() || l.kind == K::PATTERN_ERROR.raw())
            .count();
        assert!(broken || errors == 0, "{name}: {errors} error tokens");
    }
}
