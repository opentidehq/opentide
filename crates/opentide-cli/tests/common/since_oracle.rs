//! What today's CLI changed in `opentide --json commands` after the oracle
//! (opentide 0.23.0) was recorded. The Rust tree follows today's CLI; these
//! tests compare it with the oracle's recording, so each change is listed
//! here and undone (or applied) at the one place it lands, and a change that
//! is no longer found fails the test.
//!
//! - #874 (UC-0.2): `validate query` checks CrowdStrike's CQL offline. The
//!   `--platform` help names `crowdstrike`, `--file` reads `.cql`, and
//!   `QueryChecked.language` gains `cql`.
//! - #899 (0.25.0, H1): HarfangLab's YARA offline. The `--platform` help
//!   names `harfanglab`, `--file` reads `.yar` and `.yara` (and Google
//!   SecOps' `.yaral`), and `QueryChecked.language` is 0.28.1's (`yara`,
//!   `exabeam`, `yaral`), with `cql`. Both help texts are derived from the
//!   platform table (`opentide_cli::tree`).
//! - P-EX (0.28.1): Exabeam's Exabeam Query Language offline. `--file`
//!   reads `.exabeam`.

use opentide_cli::json::Json;

/// Option help texts: (the oracle's, today's).
const HELP: &[(&str, &str)] = &[
    (
        "Check this platform's queries. Offline, default every platform the engine parses: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, splunk, sysdig. --live needs one of: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, sentinel_one, splunk",
        "Check this platform's queries. Offline, default every platform the engine parses: carbon_black_cloud, crowdstrike, defender_for_endpoint, elastic, harfanglab, sentinel, splunk, sysdig. --live needs one of: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, sentinel_one, splunk",
    ),
    (
        "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, .lucene, .falco) offline (repeatable)",
        "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, .lucene, .falco, .yar, .yara, .yaral, .cql, .exabeam) offline (repeatable)",
    ),
];

/// The query languages appended to `$defs.QueryChecked.language`: 0.28.1's
/// (#899, the Exabeam and Google SecOps rows), then #874's `cql`.
const ADDED_LANGUAGES: [&str; 4] = ["yara", "exabeam", "yaral", "cql"];

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

/// `text` without the platform `id` in its comma-separated lists.
fn without_platform(text: &str, id: &str) -> String {
    text.replace(&format!(", {id},"), ",")
        .replace(&format!(", {id}."), ".")
        .replace(&format!(", {id}\""), "\"")
        .replace(&format!("{id}, "), "")
        .replace(&format!(", {id}"), "")
}

/// Removes the platforms the oracle (0.23.0) lacks
/// (`opentide_schema::platforms::SINCE_ORACLE`, ported onto the catch-up
/// train): each one's `--platform` choice, its name in the help texts' lists
/// and its `setup platforms` flag. Returns how many places changed.
fn drop_since_oracle(value: &mut Json) -> usize {
    let ids = opentide_schema::platforms::SINCE_ORACLE;
    match value {
        Json::Str(text) => {
            let mut changed = text.clone();
            for id in ids {
                changed = without_platform(&changed, id);
            }
            usize::from(std::mem::replace(text, changed) != *text)
        }
        Json::Array(items) => {
            let before = items.len();
            items.retain(|item| {
                !matches!(item, Json::Str(text) if ids.contains(&text.as_str()))
                    && !matches!(item, Json::Object(members)
                        if members.iter().any(|(key, value)| key == "name"
                            && matches!(value, Json::Str(name) if ids.contains(&name.as_str()))))
            });
            (before - items.len()) + items.iter_mut().map(drop_since_oracle).sum::<usize>()
        }
        Json::Object(members) => members
            .iter_mut()
            .map(|(_, member)| drop_since_oracle(member))
            .sum(),
        _ => 0,
    }
}

/// Today's catalogue (or schemas) as the oracle printed it. Panics if a
/// listed change is not in `document`.
pub fn to_oracle(document: &mut Json) {
    // First: `exabeam` is a language and a platform the oracle lacks, which
    // `drop_since_oracle` drops from every list.
    let languages = query_languages(document);
    for added in ADDED_LANGUAGES.iter().rev() {
        assert_eq!(
            languages.pop(),
            Some(Json::str(*added)),
            "QueryChecked.language ends with {ADDED_LANGUAGES:?}"
        );
    }
    drop_since_oracle(document);
    for (oracle, today) in HELP {
        assert!(
            replace_strings(document, today, oracle) > 0,
            "today's help is missing: {today}"
        );
    }
}

/// The oracle's schemas as today's CLI prints them.
pub fn to_today(document: &mut Json) {
    query_languages(document).extend(ADDED_LANGUAGES.iter().map(|language| Json::str(*language)));
}
