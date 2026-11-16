//! `where`, `eval` and their expressions against every file under the test
//! data: wherever tree-sitter accepts a file, the pure-Rust parser does too
//! (and loses no byte); the expression fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::parse;
use std::path::Path;
use support::{body, old_accepts, render, walk};

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
