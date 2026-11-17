//! A query with many findings is analysed in linear time. Each finding's
//! line and column came from `span_to_range`, a scan from the start of the
//! query: `index=x a == b a == b …` took 6.8 s at 5,000 terms and 418 s at
//! 50,000 (debug). One `LineIndex` per analysis answers them now. And an
//! unknown command scanned the command catalog for its typo check and its
//! "did you mean" once per occurrence; it does so once per name.
//!
//! The guards count or read the code; they do not time it.

use std::path::Path;

/// The checks find their positions through the analysis's `LineIndex`: no
/// code of the crate outside a test module calls the scans from the start.
#[test]
fn no_finding_scans_the_query_from_its_start() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.clone()];
    let mut offenders = Vec::new();
    while let Some(path) = files.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                files.push(entry.path());
            }
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        // The code before the file's test module.
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        for (n, line) in code.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            if line.contains("span_to_range(") || line.contains("offset_to_position(") {
                offenders.push(format!("{}:{}: {line}", path.display(), n + 1));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The counter is in debug builds only, as tests run.
#[cfg(debug_assertions)]
#[test]
fn an_unknown_command_is_checked_once_per_name() {
    let built = |query: &str| {
        let before = opentide_spl::unknown_command_findings();
        let findings = opentide_spl::analyze(query)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == "spl_unknown_command")
            .count();
        (opentide_spl::unknown_command_findings() - before, findings)
    };
    let repeated = format!("index=x{}", " | nocmd".repeat(1_000));
    assert_eq!(built(&repeated), (1, 1_000), "one name, 1,000 commands");
    let three = format!("index=x{}", " | nocmd | othercmd | thirdcmd".repeat(300));
    assert_eq!(built(&three), (3, 900), "three names");
}

/// Every finding of a long query keeps its own position.
#[test]
fn findings_on_later_lines_are_placed_on_them() {
    let query = format!("index=x\n{}", "a == b\n".repeat(50));
    let mut lines: Vec<u32> = opentide_spl::analyze(&query)
        .diagnostics
        .iter()
        .filter(|d| d.code == "spl_search_operator")
        .map(|d| d.range.start.line)
        .collect();
    lines.sort_unstable();
    assert_eq!(lines, (1..=50).collect::<Vec<u32>>());
}
