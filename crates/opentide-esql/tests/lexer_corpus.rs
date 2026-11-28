//! The lexer over every ES|QL file of the corpora: it tiles them, and a valid
//! one has no error token.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_esql::{lexer, syntax};

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

/// A logos regex with a repeated group of alternatives recurses once per
/// repetition in its generated code: a long enough token aborts the process.
/// Every token class of the lexer, one million characters long, on a 1 MB
/// stack.
#[test]
fn a_million_character_token_does_not_overflow_the_stack() {
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let cases = [
        format!("FROM a | EVAL {}", "a".repeat(n)),
        format!("FROM a | EVAL {}", "1".repeat(n)),
        format!("FROM a | EVAL 1.{}e5", "1".repeat(n)),
        format!("FROM a | EVAL ?{}", "p".repeat(n)),
        format!("FROM a | EVAL ??{}", "7".repeat(n)),
        format!("FROM a | KEEP {}", "a*".repeat(n / 2)),
        format!("FROM {}", "a-".repeat(n / 2)),
        format!("FROM a | ENRICH {}", "p".repeat(n)),
        format!("FROM a | EVAL \"{}\"", "\\\"".repeat(n / 2)),
        format!("FROM a | EVAL \"\"\"{}\"\"\"", "x".repeat(n)),
        format!("FROM a | EVAL `{}`", "``".repeat(n / 2)),
        format!("FROM a | EVAL /*{}*/", "/*".repeat(n / 20)),
        format!("FROM a | EVAL // {}", "c".repeat(n)),
        format!("FROM a | WEHRE {}", "u".repeat(n)),
        format!("PROMQL {}", "q".repeat(n)),
        "\u{e9}".repeat(n / 2),
    ];
    for source in cases {
        let ok = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                let lexemes = lexer::lex(&source);
                lexemes.last().map(|l| usize::from(l.range.end())) == Some(source.len())
            })
            .map(|h| h.join().unwrap_or(false))
            .unwrap_or(false);
        assert!(ok);
    }
}
