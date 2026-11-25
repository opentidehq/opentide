//! One line table for an analysis (ADR 0014 §1): `analyze` builds the line
//! index of its text once and hands it to the highlight, which built its own.
//! A work count, not a wall clock.

use opentide_core::line_tables_built;

#[test]
fn an_analysis_builds_one_line_table() {
    for source in [
        "activity_type = \"process-create\" AND process_name = \"cmd.exe\"",
        "a = (",
        "x = \"é\"\n",
        "",
    ] {
        let before = line_tables_built();
        std::hint::black_box(opentide_exabeam::analyze(source));
        assert_eq!(line_tables_built() - before, 1, "{source:?}");
    }
}
