//! `where`, `eval` and their expressions against every file under the test
//! data (no byte lost), a few queries keep the verdicts tree-sitter gave them,
//! and the expression fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::parse;
use std::path::Path;
use support::{body, render, walk};

/// Every file parses into a lossless tree (`opentide-analysis`'s
/// `parser_baseline` keeps each file's verdict).
#[test]
fn every_file_parses_losslessly() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    assert!(files.len() > 200, "{} files", files.len());
    for path in files {
        let source = body(&path);
        let (tree, _) = parse(&source);
        assert_eq!(tree.to_string(), source, "{}", path.display());
    }
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
fn expression_verdicts_are_pinned() {
    for (query, accepted) in [
        ("index=a | where x>1", true),
        ("index=a | where", true),
        ("index=a | where x<1<2", false),
        ("index=a | where (x", false),
        ("index=a | where x +", false),
        ("index=a | eval", false),
        ("index=a | eval x", false),
        ("index=a | eval x=", false),
        ("index=a | eval x=1,", false),
        ("index=a | eval x=f(1,)", false),
        ("index=a | eval x=1 y=2", false),
        ("index=a | eval x=a b", false),
        ("index=a | eval x=NOT y", true),
        ("index=a | where a IN (1, 2) OR b LIKE \"x%\"", true),
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            accepted,
            "{query:?}: {}",
            render(query)
        );
    }
}
