//! One line table for an analysis (ADR 0014 §1): `analyze` builds the line
//! index of its text once and hands it to the column pass, the performance
//! checks and the highlight, which built their own (four tables a call).
//! A work count, not a wall clock.

use opentide_core::line_tables_built;
use opentide_kql::{Dialect, analyze};

/// The tables one `analyze` of `source` builds on this thread.
fn tables(source: &str) -> usize {
    let before = line_tables_built();
    let result = analyze(source, Dialect::Sentinel);
    std::hint::black_box(result);
    line_tables_built() - before
}

#[test]
fn an_analysis_builds_one_line_table() {
    for source in [
        // Clean, over several lines: the column pass and both performance
        // checks run.
        "SecurityEvent\n| where TimeGenerated > ago(1h)\n| where EventID == 4625\n| summarize count() by Account",
        // `search *`: the scope check reports it.
        "search *\n| take 10",
        // Broken: the syntax error and the quieting after it.
        "SecurityEvent\n| where (EventID ==\n| take 10",
        // Non-ASCII, so the table records its wide characters.
        "SecurityEvent\n| where Account == \"é\u{1F600}\"",
    ] {
        // The analysis's own table, which the highlight reads too.
        assert_eq!(tables(source), 1, "{source:?}");
    }
}
