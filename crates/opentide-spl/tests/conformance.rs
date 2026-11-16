//! Every tree of the pure-Rust parser conforms to `spl.ungram`: wherever
//! tree-sitter accepts a file, the children of each node match the rule the
//! grammar documents (`cargo xtask codegen` writes the rules as data).

use opentide_parse::conformance::check;
use opentide_spl::ast::RULES;
use opentide_spl::syntax::{GRAMMAR, parse};
use std::path::Path;
use std::path::PathBuf;

#[expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]
fn body(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read");
    if path.components().any(|c| c.as_os_str() == "corpus") {
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    } else {
        text
    }
}

#[expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "spl") {
            out.push(path);
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]
fn old_accepts(source: &str) -> bool {
    let tree = opentide_syntax::parse(opentide_core::LanguageId::Spl, source).expect("parser");
    !opentide_syntax::has_error(&tree)
}

#[test]
fn every_accepted_file_conforms_to_the_ungram() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    let (mut checked, mut failures) = (0, Vec::new());
    for path in files {
        let source = body(&path);
        if !old_accepts(&source) {
            continue;
        }
        checked += 1;
        let (tree, _) = parse(&source);
        for mismatch in check(&tree, RULES, GRAMMAR).iter().take(2) {
            failures.push(format!("{}: {mismatch}", path.display()));
        }
    }
    assert!(checked > 200, "{checked} files");
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
