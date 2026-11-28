//! `join`, `lookup`, `inputlookup`, `outputlookup`, `foreach`, `spath`,
//! `tojson`, the catalog commands and unknown commands against every file
//! under the test data: every file the parser accepts reads each command by
//! its rule, a few queries keep the verdicts tree-sitter gave them, and the
//! fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, render, walk};

#[test]
fn every_command_is_read_by_its_rule() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    let mut seen = 0;
    for path in files {
        let source = body(&path);
        let (tree, parsed) = parse(&source);
        if !parsed.errors.is_empty() {
            continue;
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
fn command_verdicts_are_pinned() {
    for (query, accepted) in [
        ("| index=main", false),
        ("| inputlookup", true),
        ("| inputlookup | head 1", true),
        ("| inputlookup t.csv", true),
        ("| inputlookup append=t t.csv where x=1", true),
        ("index=a | inputlookup", false),
        ("index=a | inputlookup t.csv", true),
        ("index=a | join", false),
        ("index=a | join a [ search b ]", true),
        ("index=a | join type=left a, b [ search c ]", true),
        ("index=a | lookup", true),
        ("index=a | lookup t", false),
        ("index=a | lookup t a as b output c", true),
        ("index=a | lookup t a output", true),
        ("index=a | lookup local=t", false),
        ("index=a | outputlookup", false),
        ("index=a | outputlookup t.csv append=t", true),
        ("index=a | foreach", false),
        ("index=a | foreach * [ eval x=1 ]", true),
        ("index=a | foreach a b", false),
        ("index=a | spath", true),
        ("index=a | spath input=x path=a{}.b output=y", true),
        ("index=a | tojson", true),
        ("index=a | tojson fill_null=true a, b*, str(c)", true),
        ("index=a | makeresults", true),
        ("index=a | makeresults count=5", true),
        ("index=a | top", false),
        ("index=a | top limit=5 x", true),
        ("index=a | bin", false),
        ("index=a | bin span=1h _time", true),
        ("index=a | regex _raw!=\"a\"", true),
        ("index=a | foo", true),
        ("index=a | foo bar=1 baz", true),
        ("index=a | foo (", false),
        ("index=a | foo ]", false),
        ("index=a | foo AND bar", true),
        ("index=a | foo x<5", true),
        ("index=a | foo [ search b ]", true),
        ("index=a | foo `m`", true),
        ("index=a | foo f(1)", true),
        ("index=a | foo =", false),
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            accepted,
            "{query:?}: {}",
            render(query)
        );
    }
}
