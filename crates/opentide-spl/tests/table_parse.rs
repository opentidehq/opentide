//! The field-list commands (`table`, `fields`, `rename`, `dedup`, `sort`,
//! `head`, `tail`, `rex`, `fillnull`, `mvexpand`, `makemv`) against every
//! file under the test data: wherever tree-sitter accepts a file the
//! pure-Rust parser does too and reads these commands as such; the fixtures'
//! trees are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, old_accepts, render, walk};

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
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
fn table_verdicts_follow_the_old_parser() {
    for query in [
        "index=a | table",
        "index=a | table a, , b*",
        "index=a | table a,",
        "index=a | fields",
        "index=a | fields - a",
        "index=a | fields + ",
        "index=a | rename a",
        "index=a | rename a as",
        "index=a | rename a b as c",
        "index=a | rename",
        "index=a | dedup",
        "index=a | dedup 3",
        "index=a | dedup a sortby",
        "index=a | dedup a sortby -b",
        "index=a | sort",
        "index=a | sort 0",
        "index=a | sort a desc",
        "index=a | sort desc",
        "index=a | head",
        "index=a | head 5",
        "index=a | head x",
        "index=a | tail 5",
        "index=a | tail 5 6",
        "index=a | rex",
        "index=a | rex \"x\"",
        "index=a | rex field=a",
        "index=a | rex \"x\" \"y\"",
        "index=a | fillnull",
        "index=a | fillnull value=0",
        "index=a | mvexpand",
        "index=a | mvexpand x",
        "index=a | mvexpand limit=2",
        "index=a | makemv",
        "index=a | makemv x",
        "index=a | makemv delim=\",\"",
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            old_accepts(query),
            "{query:?}: {}",
            render(query)
        );
    }
}
