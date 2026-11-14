//! The platform blocks on their table of cases (UC-1.4, #810): every
//! `platform-*` case of `tests/tables/objects.json`, a rule holding one or
//! more blocks, converted by [`crate::objects::table::results`] and held to
//! the reviewed snapshot in `src/objects/platform/snapshots/`: each error's
//! type, field path, message, input, context, span and `yaml_line`, or the
//! whole validated value.

#[test]
fn every_platform_case_converts_as_its_snapshot_says() {
    let results = crate::objects::table::results(|id| id.starts_with("platform-"));
    assert!(results.len() > 50, "{} cases", results.len());
    insta::assert_snapshot!(
        "platform_results",
        serde_json::to_string_pretty(&results).unwrap()
    );
}
