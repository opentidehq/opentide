//! The stats family and `tstats` against every file under the test data:
//! every file the parser accepts reads the stats commands as such, a few
//! queries keep the verdicts tree-sitter gave them, and the fixtures' trees
//! are snapshots.

mod support;

use opentide_spl::syntax::{SyntaxKind, parse};
use std::path::Path;
use support::{body, render, walk};

#[test]
fn no_stats_command_is_left_to_the_placeholder() {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    let mut stats = 0;
    for path in files {
        let source = body(&path);
        let (tree, parsed) = parse(&source);
        if !parsed.errors.is_empty() {
            continue;
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
fn stats_verdicts_are_pinned() {
    for (query, accepted) in [
        ("index=a | stats", true),
        ("index=a | stats count", true),
        ("index=a | stats count by", false),
        ("index=a | stats by x", true),
        ("index=a | stats count as", false),
        ("index=a | stats dc(x", false),
        ("index=a | stats limit=5 count by x", true),
        ("index=a | stats count, , dc(x) by a, , b,", true),
        ("index=a | chart", false),
        ("index=a | chart count", true),
        ("index=a | chart count by x where count > 5", true),
        ("index=a | chart count by x where count in", false),
        ("index=a | timechart span=1d count by host limit=0", true),
        ("index=a | geostats", false),
        ("index=a | geostats latfield=la", true),
        ("index=a | geostats by x", true),
        ("index=a | tstats", false),
        ("index=a | tstats count", true),
        ("index=a | tstats count from", false),
        (
            "index=a | tstats count from datamodel=X where a=1 by b",
            true,
        ),
        ("index=a | tstats count where by b", true),
        ("index=a | tstats count by PREFIX(dst=)", true),
        ("index=a | stats values(PREFIX(a=)) as p", true),
    ] {
        assert_eq!(
            parse(query).1.errors.is_empty(),
            accepted,
            "{query:?}: {}",
            render(query)
        );
    }
}
