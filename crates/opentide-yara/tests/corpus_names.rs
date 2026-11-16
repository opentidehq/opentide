//! A YARA corpus fixture's verdict is its name: `__valid` parses with
//! `yara-x-parser`, `__invalid` does not. The fixtures were written for
//! libyara's dialect; where YARA-X (the language, #1225) refuses one of its
//! forms, the fixture is listed with the reason.

use std::path::{Path, PathBuf};
use yara_x_parser::Parser;
use yara_x_parser::ast::AST;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yara_x_accepts(source: &str) -> bool {
    AST::from(Parser::new(source.as_bytes()))
        .errors()
        .is_empty()
}

fn inputs(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .collect();
    files.sort();
    files
}

/// Valid libyara fixtures YARA-X refuses, by design.
const EXPECTED: &[(&str, &str)] = &[
    (
        "base64_modifier__valid.yar",
        "an escape in a base64 alphabet: libyara accepts it (its docs' example), YARA-X does not",
    ),
    (
        "rule_set__valid.yar",
        "a rule wildcard in `of` (libyara 4.3): YARA-X reads `base*` as a product",
    ),
    (
        "rule_wildcard__valid.yar",
        "a rule wildcard in `of` (libyara 4.3): YARA-X reads `base*` as a product",
    ),
];

/// A corpus fixture's verdict is its name, except where [`EXPECTED`] says
/// why not; a listed fixture YARA-X comes to accept fails too.
#[test]
fn corpus_fixtures_match_their_names() {
    let mut wrong = Vec::new();
    let files = inputs(&root().join("crates/testdata/corpus/yara"), "yar");
    for path in &files {
        let source = std::fs::read_to_string(path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let valid = name.contains("__valid");
        let excepted = EXPECTED.iter().any(|(n, _)| *n == name);
        if yara_x_accepts(&source) != (valid && !excepted) {
            wrong.push(name);
        }
    }
    assert!(files.len() > 60, "{} fixtures", files.len());
    assert!(wrong.is_empty(), "{wrong:?}");
}
