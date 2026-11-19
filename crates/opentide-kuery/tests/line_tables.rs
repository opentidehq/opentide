//! One line table for an analysis (ADR 0014 §1): `analyze` builds the line
//! index of its text once and hands it to the highlight, which built its own.
//! A work count, not a wall clock.

use opentide_core::line_tables_built;

#[test]
fn an_analysis_builds_one_line_table() {
    for source in [
        "process.name: cmd.exe and not user.name: x",
        "a:(1 or 2) and",
        "message: \"é\"\n or b: 1",
        "",
    ] {
        let before = line_tables_built();
        std::hint::black_box(opentide_kuery::analyze(source, |_| false));
        assert_eq!(line_tables_built() - before, 1, "{source:?}");
    }
}
