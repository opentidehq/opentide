//! The stats family and `tstats` against every file under the test data:
//! wherever tree-sitter accepts a file the pure-Rust parser does too, and
//! reads the stats commands as such; the fixtures' trees are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, old_accepts, render, walk};

#[test]
fn no_stats_command_is_left_to_the_placeholder() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    let (mut stats, mut failures) = (0, Vec::new());
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
            if node.kind() == SyntaxKind::STATS_COMMAND || node.kind() == SyntaxKind::TSTATS_COMMAND
            {
                stats += 1;
            }
            if node.kind() == SyntaxKind::UNKNOWN_COMMAND {
                let name = node
                    .first_token()
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                assert!(
                    !matches!(
                        name.as_str(),
                        "stats"
                            | "eventstats"
                            | "streamstats"
                            | "sistats"
                            | "chart"
                            | "timechart"
                            | "sichart"
                            | "sitimechart"
                            | "geostats"
                            | "tstats"
                    ),
                    "{}: {name} left to the placeholder",
                    path.display()
                );
            }
        }
    }
    assert!(stats > 100, "{stats} stats commands");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_stats_fixtures_are_snapshots() {
    insta::glob!(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/corpus/spl"),
        "*.spl",
        |path| {
            let name = path.file_name().expect("name").to_string_lossy();
            if ["stats_", "chart_where", "tstats_"]
                .iter()
                .any(|p| name.starts_with(p))
            {
                insta::assert_snapshot!(render(&body(path)));
            }
        }
    );
}

#[test]
fn stats_verdicts_follow_the_old_parser() {
    for query in [
        "index=a | stats",
        "index=a | stats count",
        "index=a | stats count by",
        "index=a | stats by x",
        "index=a | stats count as",
        "index=a | stats dc(x",
        "index=a | stats limit=5 count by x",
        "index=a | stats count, , dc(x) by a, , b,",
        "index=a | chart",
        "index=a | chart count",
        "index=a | chart count by x where count > 5",
        "index=a | chart count by x where count in",
        "index=a | timechart span=1d count by host limit=0",
        "index=a | geostats",
        "index=a | geostats latfield=la",
        "index=a | geostats by x",
        "index=a | tstats",
        "index=a | tstats count",
        "index=a | tstats count from",
        "index=a | tstats count from datamodel=X where a=1 by b",
        "index=a | tstats count where by b",
        "index=a | tstats count by PREFIX(dst=)",
        "index=a | stats values(PREFIX(a=)) as p",
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            old_accepts(query),
            "{query:?}: {}",
            render(query)
        );
    }
}
