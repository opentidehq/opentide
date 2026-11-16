//! `join`, `lookup`, `inputlookup`, `outputlookup`, `foreach`, `spath`,
//! `tojson`, the catalog commands and unknown commands against every file
//! under the test data: wherever tree-sitter accepts a file the pure-Rust
//! parser does too; the fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, old_accepts, render, walk};

#[test]
fn every_command_is_read_by_its_rule() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    let (mut seen, mut failures) = (0, Vec::new());
    for path in files {
        let source = body(&path);
        if !old_accepts(&source) {
            continue;
        }
        let (tree, parsed) = parse(&source);
        if !parsed.errors.is_empty() {
            failures.push(format!("{}: {}", path.display(), parsed.errors[0].message));
        }
        seen += tree
            .descendants()
            .filter(|n| {
                matches!(
                    n.kind(),
                    SyntaxKind::JOIN_COMMAND
                        | SyntaxKind::LOOKUP_COMMAND
                        | SyntaxKind::INPUTLOOKUP_COMMAND
                        | SyntaxKind::OUTPUTLOOKUP_COMMAND
                        | SyntaxKind::FOREACH_COMMAND
                        | SyntaxKind::SPATH_COMMAND
                        | SyntaxKind::TOJSON_COMMAND
                        | SyntaxKind::CATALOG_COMMAND
                        | SyntaxKind::UNKNOWN_COMMAND
                )
            })
            .count();
    }
    assert!(seen > 40, "{seen} commands");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_command_fixtures_are_snapshots() {
    insta::glob!(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/corpus/spl"),
        "*.spl",
        |path| {
            let name = path.file_name().expect("name").to_string_lossy();
            let listed = [
                "join_command",
                "lookup_",
                "inputlookup_command",
                "outputlookup_command",
                "foreach_command",
                "spath_command",
                "tojson_command",
                "catalog_command",
                "unknown_command",
                "command_option",
                "function_call",
            ];
            if listed.iter().any(|p| name.starts_with(p)) {
                insta::assert_snapshot!(render(&body(path)));
            }
        }
    );
}

#[test]
fn command_verdicts_follow_the_old_parser() {
    for query in [
        "| index=main",
        "| inputlookup",
        "| inputlookup | head 1",
        "| inputlookup t.csv",
        "| inputlookup append=t t.csv where x=1",
        "index=a | inputlookup",
        "index=a | inputlookup t.csv",
        "index=a | join",
        "index=a | join a [ search b ]",
        "index=a | join type=left a, b [ search c ]",
        "index=a | lookup",
        "index=a | lookup t",
        "index=a | lookup t a as b output c",
        "index=a | lookup t a output",
        "index=a | lookup local=t",
        "index=a | outputlookup",
        "index=a | outputlookup t.csv append=t",
        "index=a | foreach",
        "index=a | foreach * [ eval x=1 ]",
        "index=a | foreach a b",
        "index=a | spath",
        "index=a | spath input=x path=a{}.b output=y",
        "index=a | tojson",
        "index=a | tojson fill_null=true a, b*, str(c)",
        "index=a | makeresults",
        "index=a | makeresults count=5",
        "index=a | top",
        "index=a | top limit=5 x",
        "index=a | bin",
        "index=a | bin span=1h _time",
        "index=a | regex _raw!=\"a\"",
        "index=a | foo",
        "index=a | foo bar=1 baz",
        "index=a | foo (",
        "index=a | foo ]",
        "index=a | foo AND bar",
        "index=a | foo x<5",
        "index=a | foo [ search b ]",
        "index=a | foo `m`",
        "index=a | foo f(1)",
        "index=a | foo =",
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            old_accepts(query),
            "{query:?}: {}",
            render(query)
        );
    }
}
