//! `query_folded_comment` (B16): a `//` comment in a query that YAML folds
//! into one line comments out the lines after it, in every language whose
//! comments are `//`, and in every scalar style that folds.

use opentide_core::{Severity, codes};
use opentide_tide::analyze_queries;

const HEAD: &str =
    "name: Folded\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.1\n";

/// The `query_folded_comment` findings of `source`: `(field path, line from
/// 0, severity)`.
fn folded(source: &str) -> Vec<(String, u32, Severity)> {
    analyze_queries(source, &[])
        .into_iter()
        .flat_map(|query| query.diagnostics)
        .filter(|d| d.code == codes::QUERY_FOLDED_COMMENT)
        .map(|d| {
            (
                d.field_path.unwrap_or_default().join("."),
                d.range.start.line,
                d.severity,
            )
        })
        .collect()
}

/// A rule whose `configurations` block is `block` (indented under it).
fn rule(block: &str) -> String {
    format!("{HEAD}configurations:\n{block}")
}

#[test]
fn a_comment_folding_carries_over_is_an_error_in_every_language() {
    // `(case, block, field path, line of the comment from 0)`: line 4 is
    // `configurations:`.
    let cases = [
        (
            "sentinel >+",
            "  sentinel:\n    query: >+\n      SecurityEvent\n      // note\n      | take 1\n",
            "configurations.sentinel.query",
            8,
        ),
        (
            "sentinel >2-",
            "  sentinel:\n    query: >2-\n      SecurityEvent\n      // note\n      | take 1\n",
            "configurations.sentinel.query",
            8,
        ),
        (
            "sentinel double-quoted",
            "  sentinel:\n    query: \"SecurityEvent\n      // note\n      | take 1\"\n",
            "configurations.sentinel.query",
            7,
        ),
        (
            "defender",
            "  defender_for_endpoint:\n    query: >-\n      DeviceProcessEvents\n      // note\n      | take 1\n",
            "configurations.defender_for_endpoint.query",
            8,
        ),
        (
            "es|ql",
            "  elastic:\n    type: esql\n    query: >-\n      FROM logs-*\n      // note\n      | LIMIT 10\n",
            "configurations.elastic.query",
            9,
        ),
        (
            "eql",
            "  elastic:\n    type: eql\n    query: >-\n      process where true\n      // note\n      and process.name == \"a\"\n",
            "configurations.elastic.query",
            9,
        ),
        (
            "cql",
            "  crowdstrike:\n    query: >-\n      #event_simpleName=ProcessRollup2\n      // note\n      | ImageFileName=/cmd\\.exe/\n",
            "configurations.crowdstrike.query",
            8,
        ),
        (
            "yara-l section",
            "  google_secops:\n    enabled: true\n    status: STAGING\n    events: >-\n      $e.metadata.event_type = \"PROCESS_LAUNCH\"\n      // note\n      $e.principal.hostname = \"h\"\n    condition: |\n      $e\n",
            "configurations.google_secops.events",
            10,
        ),
        (
            "yara signature (harfanglab)",
            "  harfanglab:\n    yara:\n      signature: >-\n        rule a {\n        // note\n        condition: true }\n",
            "configurations.harfanglab.yara.signature",
            9,
        ),
        (
            "yara signature (bitdefender)",
            "  bitdefender:\n    yara:\n      signature: >-\n        rule a {\n        // note\n        condition: true }\n",
            "configurations.bitdefender.yara.signature",
            9,
        ),
        (
            "yara assembled from the harfanglab fields",
            "  harfanglab:\n    enabled: true\n    schema: platform::harfanglab::1.0\n    status: STAGING\n    yara:\n      meta:\n        context:\n          - file\n        os: Windows\n      strings: |\n        $a = \"x\"\n      condition: >-\n        $a\n        // note\n        and true\n",
            "configurations.harfanglab.yara",
            18,
        ),
    ];
    for (case, block, path, line) in cases {
        let found = folded(&rule(block));
        assert_eq!(found, [(path.to_owned(), line, Severity::Error)], "{case}");
    }
}

#[test]
fn a_hunt_search_is_checked_too() {
    let source = format!(
        "{HEAD}response:\n  procedure:\n    searches:\n      - system: google_secops\n        query: >-\n          $e.metadata.event_type = \"PROCESS_LAUNCH\"\n          // note\n          $e.principal.hostname = \"h\"\n"
    );
    let found = folded(&source);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "response.procedure.searches.0.query");
}

#[test]
fn a_comment_that_loses_nothing_is_not_reported() {
    for (case, block) in [
        // A more-indented line keeps its line break: the comment ends.
        (
            "more indented",
            "  sentinel:\n    query: >-\n      SecurityEvent\n      // note\n        | take 1\n",
        ),
        // SPL's comment is fenced, not a line comment.
        (
            "spl",
            "  splunk:\n    query: >-\n      index=main\n      ```note```\n      | head 1\n",
        ),
        (
            "literal",
            "  sentinel:\n    query: |-\n      SecurityEvent\n      // note\n      | take 1\n",
        ),
    ] {
        assert_eq!(folded(&rule(block)), [], "{case}");
    }
}
