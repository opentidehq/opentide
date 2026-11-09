//! What today's CLI changed in `opentide --json commands` after the oracle
//! (opentide 0.23.0) was recorded. The Rust tree follows today's CLI; these
//! tests compare it with the oracle's recording, so each change is listed
//! here and undone (or applied) at the one place it lands, and a change that
//! is no longer found fails the test.
//!
//! - #874 (UC-0.2): `validate query` checks CrowdStrike's CQL offline. The
//!   `--platform` help names `crowdstrike`, `--file` reads `.cql`, and
//!   `QueryChecked.language` gains `cql`.
//!
//! The `OPENTIDE_ENGINE` environment row (UC-0.7, #805) is handled by
//! `framework_goldens.rs` itself.

use opentide_cli::json::Json;

/// Option help texts: (the oracle's, today's).
const HELP: &[(&str, &str)] = &[
    (
        "Check this platform's queries. Offline, default every platform the engine parses: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, splunk, sysdig. --live needs one of: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, sentinel_one, splunk",
        "Check this platform's queries. Offline, default every platform the engine parses: carbon_black_cloud, crowdstrike, defender_for_endpoint, elastic, sentinel, splunk, sysdig. --live needs one of: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, sentinel_one, splunk",
    ),
    (
        "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, .lucene, .falco) offline (repeatable)",
        "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, .lucene, .falco, .cql) offline (repeatable)",
    ),
];

/// The query language #874 appended to `$defs.QueryChecked.language`.
const ADDED_LANGUAGE: &str = "cql";

/// Replaces every string equal to `from` with `to`, and counts them.
fn replace_strings(value: &mut Json, from: &str, to: &str) -> usize {
    match value {
        Json::Str(text) if text == from => {
            to.clone_into(text);
            1
        }
        Json::Array(items) => items
            .iter_mut()
            .map(|item| replace_strings(item, from, to))
            .sum(),
        Json::Object(members) => members
            .iter_mut()
            .map(|(_, member)| replace_strings(member, from, to))
            .sum(),
        _ => 0,
    }
}

/// `$defs.QueryChecked.properties.language.enum` of a catalogue or of
/// `data/output-schemas.json`.
fn query_languages(document: &mut Json) -> &mut Vec<Json> {
    let mut node = document;
    for key in ["$defs", "QueryChecked", "properties", "language", "enum"] {
        let Json::Object(members) = node else {
            panic!("no object at {key}")
        };
        node = members
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, member)| member)
            .unwrap_or_else(|| panic!("no {key}"));
    }
    let Json::Array(items) = node else {
        panic!("QueryChecked.language.enum is not an array")
    };
    items
}

/// Today's catalogue (or schemas) as the oracle printed it. Panics if a
/// listed change is not in `document`.
pub fn to_oracle(document: &mut Json) {
    for (oracle, today) in HELP {
        assert!(
            replace_strings(document, today, oracle) > 0,
            "today's help is missing: {today}"
        );
    }
    let languages = query_languages(document);
    assert_eq!(
        languages.pop(),
        Some(Json::str(ADDED_LANGUAGE)),
        "QueryChecked.language ends with {ADDED_LANGUAGE}"
    );
}

/// The oracle's schemas as today's CLI prints them.
pub fn to_today(document: &mut Json) {
    query_languages(document).push(Json::str(ADDED_LANGUAGE));
}
