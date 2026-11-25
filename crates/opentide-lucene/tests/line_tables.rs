//! One line table for an analysis (ADR 0014 §1): `analyze` builds the line
//! index of its text once and hands it to the highlight, which built its own.
//! A work count, not a wall clock.

use opentide_core::line_tables_built;

#[test]
fn an_analysis_builds_one_line_table() {
    for source in [
        "process.name:cmd.exe AND NOT user.name:x",
        "a:(1 OR 2) AND",
        "message:\"é\"\n OR b:[1 TO 2]",
        "",
    ] {
        let before = line_tables_built();
        std::hint::black_box(opentide_lucene::analyze(source));
        assert_eq!(line_tables_built() - before, 1, "{source:?}");
    }
}
