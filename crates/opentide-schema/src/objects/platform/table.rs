//! The platform blocks against the oracle (UC-1.4, #810): every case of
//! `tests/oracle/platform_cases.toml`, a rule holding one or more blocks,
//! compared with what the oracle reports (`objects_table.json`, written by
//! `objects_table.py`) by [`crate::objects::table::compare`]: each error's
//! type, field path, message, input, context, span and `yaml_line`, or the
//! whole validated value. A case that differs names the `[[difference]]`
//! that explains it. The Rust results are the reviewed snapshot in
//! `src/objects/platform/snapshots/`.

#[test]
#[ignore = "byte-level replay against the Python oracle: run by hand with --run-ignored only"]
fn platform_cases_match_the_oracle() {
    let (failures, results) = crate::objects::table::compare(
        include_str!("../../../tests/oracle/platform_cases.toml"),
        |id| id.starts_with("platform-"),
        false,
    );
    assert!(
        failures.is_empty(),
        "{} cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
    insta::assert_snapshot!(
        "platform_results",
        serde_json::to_string_pretty(&results).unwrap()
    );
}
