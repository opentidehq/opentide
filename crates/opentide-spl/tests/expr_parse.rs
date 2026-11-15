//! `where`, `eval` and their expressions against every file under the test
//! data: wherever tree-sitter accepts a file, the pure-Rust parser does too
//! (and loses no byte); the expression fixtures' trees are snapshots.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::LanguageId;
use opentide_parse::{debug_errors, debug_tree};
use opentide_spl::syntax::{Lang, SyntaxKind, parse};
use std::path::{Path, PathBuf};

fn body(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read");
    if path.components().any(|c| c.as_os_str() == "corpus") {
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    } else {
        text
    }
}

fn render(source: &str) -> String {
    let (tree, parse) = parse(source);
    assert_eq!(tree.to_string(), source, "lossless");
    let mut out = debug_tree(&tree, |k: SyntaxKind| format!("{k:?}"));
    out.push_str("--\n");
    out.push_str(&debug_errors(&parse.errors, |k| {
        format!("{:?}", <Lang as rowan::Language>::kind_from_raw(k))
    }));
    out
}

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

fn old_accepts(source: &str) -> bool {
    let tree = opentide_syntax::parse(LanguageId::Spl, source).expect("parser");
    !opentide_syntax::has_error(&tree)
}

#[test]
fn every_file_the_old_parser_accepts_parses_without_an_error() {
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
        let (tree, parsed) = parse(&source);
        assert_eq!(tree.to_string(), source, "{}", path.display());
        if !parsed.errors.is_empty() {
            let first = parsed.errors[0].gap.start();
            failures.push(format!(
                "{}: {} (at {})",
                path.display(),
                parsed.errors[0].message,
                usize::from(first)
            ));
        }
    }
    assert!(checked > 200, "{checked} files");
    assert!(
        failures.is_empty(),
        "{} of {checked}:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn the_expression_fixtures_are_snapshots() {
    insta::glob!(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/corpus/spl"),
        "*.spl",
        |path| {
            let name = path.file_name().expect("name").to_string_lossy();
            if [
                "where_command",
                "eval_command",
                "assignment",
                "function_call",
            ]
            .iter()
            .any(|p| name.starts_with(p))
            {
                insta::assert_snapshot!(render(&body(path)));
            }
        }
    );
}

#[test]
fn expression_verdicts_follow_the_old_parser() {
    for query in [
        "index=a | where x>1",
        "index=a | where",
        "index=a | where x<1<2",
        "index=a | where (x",
        "index=a | where x +",
        "index=a | eval",
        "index=a | eval x",
        "index=a | eval x=",
        "index=a | eval x=1,",
        "index=a | eval x=f(1,)",
        "index=a | eval x=1 y=2",
        "index=a | eval x=a b",
        "index=a | eval x=NOT y",
        "index=a | where a IN (1, 2) OR b LIKE \"x%\"",
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            old_accepts(query),
            "{query:?}: {}",
            render(query)
        );
    }
}
