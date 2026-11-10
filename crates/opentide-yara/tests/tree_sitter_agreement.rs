//! The tree-sitter grammar (highlighting, structure) agrees with
//! `yara-x-parser` (verdicts) on which inputs parse: yara-x-parser's own
//! parser inputs (`testdata/conformance/yara-x/parser`) and the YARA corpus.
//! Where they differ by design, the input is listed with the reason.

use opentide_core::LanguageId;
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

fn tree_sitter_accepts(source: &str) -> bool {
    let tree = opentide_syntax::parse(LanguageId::Yara, source).expect("tree-sitter parses");
    !tree.root_node().has_error()
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

/// Inputs where the parsers disagree by design. The tree-sitter grammar is
/// libyara's dialect: yara-x-parser also accepts YARA-X-only syntax, and
/// refuses some of libyara's (the engine reports those as
/// `yara_x_incompatible`, not as parse errors).
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
    (
        "literal-underscores.in",
        "`1_000`, `0xaa_bb`: digit separators are YARA-X only",
    ),
    (
        "meta.in",
        "float meta values and `\"\"\"` strings are YARA-X only",
    ),
    (
        "of-1.in",
        "`2 of (true, false, ...)`: booleans in `of` tuples are YARA-X only",
    ),
    ("with-1.in", "`with` declarations are YARA-X only"),
    ("with-2.in", "`with` declarations are YARA-X only"),
];

#[test]
fn tree_sitter_agrees_with_yara_x_parser() {
    let mut disagreements = Vec::new();
    let mut files = inputs(&root().join("testdata/conformance/yara-x/parser"), "in");
    files.extend(inputs(&root().join("testdata/corpus/yara"), "yar"));
    for path in &files {
        let source = std::fs::read_to_string(path).unwrap();
        let (yx, ts) = (yara_x_accepts(&source), tree_sitter_accepts(&source));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let expected = EXPECTED.iter().any(|(n, _)| *n == name);
        if (yx != ts) != expected {
            disagreements.push(format!("{name}: yara-x {yx}, tree-sitter {ts}"));
        }
    }
    assert!(files.len() > 70, "{} inputs", files.len());
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
}

/// A corpus fixture's verdict is its name: `__valid` parses, `__invalid`
/// does not. yara-x-parser is held to the same, except where [`EXPECTED`]
/// says why not.
#[test]
fn corpus_fixtures_match_their_names() {
    let mut wrong = Vec::new();
    for path in inputs(&root().join("testdata/corpus/yara"), "yar") {
        let source = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let valid = name.contains("__valid");
        let excepted = EXPECTED.iter().any(|(n, _)| *n == name);
        if (!excepted && yara_x_accepts(&source) != valid) || tree_sitter_accepts(&source) != valid
        {
            wrong.push(name);
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}
