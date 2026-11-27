//! A Datadog block's queries and a `system: datadog` hunt in a Tide object,
//! through `analyze_queries` (RFC `rfc-datadog-cloud-siem.md` §6.1, §6.8):
//! each `queries[].query` is the Datadog search syntax under the `rule`
//! profile, where full-text `*:term` and a calculated field are warnings,
//! and a hunt is a search, the `search` profile, where they are not.

use opentide_core::LanguageId;
use opentide_tide::{analyze_queries, language_for_field_path};

const RULE: &str = "\
name: r
response:
  procedure:
    searches:
      - purpose: look around
        system: datadog
        query: '*:mimikatz #duration_ms:>500'
configurations:
  datadog:
    schema: platform::datadog::1.0
    status: STAGING
    queries:
      - name: failed
        query: source:okta @evt.outcome:FAILURE
      - query: '*:mimikatz'
    cases:
      - condition: failed > 5
";

/// `(field path, platform, codes)` of every Datadog query.
fn queries(source: &str) -> Vec<(String, String, Vec<String>)> {
    analyze_queries(source, &[])
        .into_iter()
        .filter(|query| query.query.language == LanguageId::Datadog)
        .map(|query| {
            (
                query.query.field_path.join("."),
                query.query.platform.clone(),
                query.diagnostics.into_iter().map(|d| d.code).collect(),
            )
        })
        .collect()
}

#[test]
fn each_query_is_a_rule_query_and_the_hunt_a_search() {
    assert_eq!(
        queries(RULE),
        [
            (
                "response.procedure.searches.0.query".to_owned(),
                "datadog".to_owned(),
                Vec::<String>::new()
            ),
            (
                "configurations.datadog.queries.0.query".to_owned(),
                "datadog".to_owned(),
                Vec::new()
            ),
            (
                "configurations.datadog.queries.1.query".to_owned(),
                "datadog".to_owned(),
                vec!["datadog_full_text_in_rule".to_owned()]
            ),
        ]
    );
}

#[test]
fn only_a_query_s_query_is_the_search_syntax() {
    for (path, expected) in [
        (
            &["configurations", "datadog", "queries", "0", "query"][..],
            Some(LanguageId::Datadog),
        ),
        (
            &["configurations", "datadog", "queries", "x", "query"],
            None,
        ),
        (&["configurations", "datadog", "query"], None),
        (
            &["configurations", "datadog", "cases", "0", "condition"],
            None,
        ),
        (&["configurations", "datadog", "message"], None),
    ] {
        assert_eq!(language_for_field_path(path), expected, "{path:?}");
    }
}
