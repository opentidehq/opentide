//! The field-list commands (`table`, `fields`, `rename`, `dedup`, `sort`,
//! `head`, `tail`, `rex`, `fillnull`, `mvexpand`, `makemv`) against every
//! file under the test data: every file the parser accepts reads these
//! commands as such, a few queries keep the verdicts tree-sitter gave them,
//! and the fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, render, walk};

const COMMANDS: [&str; 11] = [
    "table", "fields", "rename", "dedup", "sort", "head", "tail", "rex", "fillnull", "mvexpand",
    "makemv",
];

#[test]
fn no_table_command_is_left_to_the_placeholder() {
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
        for node in tree.descendants() {
            if node.kind() == SyntaxKind::UNKNOWN_COMMAND {
                let name = node
                    .first_token()
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                assert!(
                    !COMMANDS.contains(&name.as_str()),
                    "{}: {name} left to the placeholder",
                    path.display()
                );
            } else if matches!(
                node.kind(),
                SyntaxKind::TABLE_COMMAND
                    | SyntaxKind::FIELDS_COMMAND
                    | SyntaxKind::RENAME_COMMAND
                    | SyntaxKind::DEDUP_COMMAND
                    | SyntaxKind::SORT_COMMAND
                    | SyntaxKind::HEAD_COMMAND
                    | SyntaxKind::REX_COMMAND
            ) {
                seen += 1;
            }
        }
    }
    assert!(seen > 25, "{seen} commands");
}

#[test]
fn the_table_fixtures_are_snapshots() {
    insta::glob!(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/corpus/spl"),
        "*.spl",
        |path| {
            let name = path.file_name().expect("name").to_string_lossy();
            let listed = [
                "table_command",
                "fields_command",
                "rename_",
                "dedup_",
                "sort_",
                "head_command",
                "tail_command",
                "rex_command",
                "fillnull_command",
                "mvexpand_command",
                "makemv_command",
                "field_name",
            ];
            if listed.iter().any(|p| name.starts_with(p)) {
                insta::assert_snapshot!(render(&body(path)));
            }
        }
    );
}

#[test]
fn table_verdicts_are_pinned() {
    for (query, accepted) in [
        ("index=a | table", false),
        ("index=a | table a, , b*", true),
        ("index=a | table a,", true),
        ("index=a | fields", true),
        ("index=a | fields - a", true),
        ("index=a | fields + ", true),
        ("index=a | rename a", false),
        ("index=a | rename a as", false),
        ("index=a | rename a b as c", false),
        ("index=a | rename", false),
        ("index=a | dedup", false),
        ("index=a | dedup 3", false),
        ("index=a | dedup a sortby", false),
        ("index=a | dedup a sortby -b", true),
        ("index=a | sort", false),
        ("index=a | sort 0", false),
        ("index=a | sort a desc", true),
        ("index=a | sort desc", true),
        ("index=a | head", true),
        ("index=a | head 5", true),
        ("index=a | head x", false),
        ("index=a | tail 5", true),
        ("index=a | tail 5 6", false),
        ("index=a | rex", false),
        ("index=a | rex \"x\"", true),
        ("index=a | rex field=a", false),
        ("index=a | rex \"x\" \"y\"", false),
        ("index=a | fillnull", true),
        ("index=a | fillnull value=0", true),
        ("index=a | mvexpand", false),
        ("index=a | mvexpand x", true),
        ("index=a | mvexpand limit=2", false),
        ("index=a | makemv", false),
        ("index=a | makemv x", true),
        ("index=a | makemv delim=\",\"", false),
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            accepted,
            "{query:?}: {}",
            render(query)
        );
    }
}
