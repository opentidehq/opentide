//! `ExabeamConfig` and its constraint codes, ported from 0.28.0's
//! `tests/test_platforms/test_exabeam_model.py`: each block is a Python
//! dict there, a JSON value here, read as the node the YAML would give.

use std::collections::BTreeSet;

use serde_json::{Value as Json, json};

use super::*;
use crate::from_node::FromNode;
use crate::objects::platform::json_node;

const QUERY: &str = "activity_type:\"app-login\"";

/// A fixture of `tests/fixtures/exabeam/`, compiled in (the crate does no I/O).
fn fixture(name: &str) -> &'static str {
    macro_rules! fixtures {
        ($($file:literal),* $(,)?) => {
            match name {
                $($file => include_str!(concat!("../../../../../tests/fixtures/exabeam/", $file)),)*
                other => panic!("no fixture {other}"),
            }
        };
    }
    fixtures!(
        "block-exabeam.yaml",
        "rule-exabeam-threshold-1.0.yaml",
        "rule-exabeam-sequence-1.0.yaml",
        "invalid/rule-exabeam-correlation-single.yaml",
        "invalid/rule-exabeam-threshold-operator.yaml",
        "invalid/rule-exabeam-context-table-threshold.yaml",
        "invalid/rule-exabeam-delay.yaml",
        "invalid/rule-exabeam-advanced-query.yaml",
    )
}

fn base() -> Json {
    json!({
        "enabled": true,
        "schema": "platform::exabeam::1.0",
        "status": "STAGING",
        "sequences": [{"query": QUERY}],
    })
}

fn block(keys: &Json) -> Json {
    let mut out = base();
    for (key, value) in keys.as_object().unwrap_or(&serde_json::Map::new()) {
        out[key] = value.clone();
    }
    out
}

fn codes(keys: &Json) -> BTreeSet<&'static str> {
    block_codes(&json_node(&block(keys)))
}

fn threshold(overrides: &Json) -> Json {
    let mut threshold = json!({
        "function": "count", "operator": "more_than", "value": 5, "within": "10m"
    });
    for (key, value) in overrides.as_object().unwrap_or(&serde_json::Map::new()) {
        if value.is_null() {
            threshold.as_object_mut().map(|map| map.remove(key));
        } else {
            threshold[key] = value.clone();
        }
    }
    json!([{"query": QUERY, "threshold": threshold}])
}

/// `(code, field_path)` of each error the model reports, as validate does.
fn errors(block: &Json) -> Vec<(String, Vec<String>)> {
    let mut cx = Context::new();
    let _ = ExabeamConfig::from_node(&json_node(block), &mut cx);
    let errors = cx.into_errors();
    errors
        .iter()
        .map(|error| {
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                error.field_path(),
            )
        })
        .collect()
}

fn pair(code: &str, path: &[&str]) -> (String, Vec<String>) {
    (
        code.to_owned(),
        path.iter().map(|part| (*part).to_owned()).collect(),
    )
}

fn yaml_block(name: &str) -> std::sync::Arc<Node> {
    let document = crate::node::load(fixture(name)).unwrap();
    let root = document.root().unwrap().clone();
    root.get("configurations")
        .and_then(|configurations| configurations.get("exabeam"))
        .unwrap()
        .clone()
}

#[test]
fn the_specification_fixtures_validate() {
    for name in [
        "block-exabeam.yaml",
        "rule-exabeam-threshold-1.0.yaml",
        "rule-exabeam-sequence-1.0.yaml",
    ] {
        let node = yaml_block(name);
        assert_eq!(block_findings(&node), Vec::new(), "{name}");
        let mut cx = Context::new();
        let value = ExabeamConfig::from_node(&node, &mut cx);
        assert_eq!(cx.into_errors(), Vec::new(), "{name}");
        assert!(value.is_some());
    }
}

#[test]
fn each_invalid_fixture_fails_with_its_code() {
    for (name, code) in [
        (
            "rule-exabeam-correlation-single.yaml",
            "exabeam_correlation",
        ),
        (
            "rule-exabeam-threshold-operator.yaml",
            "exabeam_threshold_operator",
        ),
        (
            "rule-exabeam-context-table-threshold.yaml",
            "exabeam_context_table_trigger",
        ),
        ("rule-exabeam-delay.yaml", "exabeam_duration"),
    ] {
        let node = yaml_block(&format!("invalid/{name}"));
        let mut cx = Context::new();
        assert!(ExabeamConfig::from_node(&node, &mut cx).is_none());
        let found: BTreeSet<String> = cx
            .into_errors()
            .iter()
            .map(|error| error.code(crate::Surface::Object).to_owned())
            .collect();
        assert_eq!(found, BTreeSet::from([code.to_owned()]), "{name}");
    }
}

#[test]
fn the_advanced_query_fixture_is_the_engines() {
    let node = yaml_block("invalid/rule-exabeam-advanced-query.yaml");
    assert_eq!(block_findings(&node), Vec::new());
}

/// The cases of specifications' `test_platform_exabeam.py`
/// (`CheckerTests.test_block_codes`), without the language and unknown-key
/// ones, which are not this module's.
#[test]
fn block_codes_table() {
    let two = json!([{"query": "vendor:\"a\""}, {"query": "vendor:\"b\""}]);
    let cases: Vec<(Json, &[&str])> = vec![
        (json!({}), &[]),
        (json!({"sequences": []}), &["exabeam_sequences"]),
        (
            json!({"sequences": [{"query": "  "}]}),
            &["exabeam_sequences"],
        ),
        (json!({"sequences": two}), &["exabeam_correlation"]),
        (
            json!({"sequences": two, "correlation": {"within": "15m"}}),
            &[],
        ),
        (
            json!({"sequences": two, "correlation": {"within": "1h30m"}}),
            &["exabeam_duration"],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "median"}))}),
            &["exabeam_threshold_function"],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "sum"}))}),
            &["exabeam_threshold_function"],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "sum", "field": "bytes"}))}),
            &[],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "sum", "field": " "}))}),
            &["exabeam_threshold_function"],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "value", "field": "dest_ip"}))}),
            &["exabeam_threshold_operator"],
        ),
        (
            json!({"sequences": threshold(&json!({
                "function": "value", "field": "dest_ip", "operator": "not_in", "value": ["1.1.1.1"]
            }))}),
            &[],
        ),
        (
            json!({"sequences": threshold(&json!({
                "function": "value", "field": "user", "operator": "changed", "value": null
            }))}),
            &["exabeam_threshold_operator"],
        ),
        (
            json!({"sequences": threshold(&json!({"value": 2.5}))}),
            &["exabeam_threshold_value"],
        ),
        (
            json!({"sequences": threshold(&json!({"value": -1}))}),
            &["exabeam_threshold_value"],
        ),
        (
            json!({"sequences": threshold(&json!({"value": true}))}),
            &["exabeam_threshold_value"],
        ),
        (
            json!({"sequences": threshold(&json!({"function": "max", "field": "bytes", "value": 2.5}))}),
            &[],
        ),
        (
            json!({"sequences": threshold(&json!({
                "function": "value", "field": "dest_ip", "operator": "in", "value": ["a,b"]
            }))}),
            &["exabeam_threshold_value"],
        ),
        (
            json!({"sequences": threshold(&json!({"operator": "between", "value": [2, 10]}))}),
            &["exabeam_threshold_operator"],
        ),
        (
            json!({"sequences": threshold(&json!({"within": "1w"}))}),
            &["exabeam_duration"],
        ),
        (
            json!({"sequences": [{"query": QUERY, "group_by": ["a", "b", "c", "d"]}]}),
            &["exabeam_group_by"],
        ),
        (
            json!({"sequences": [{"query": QUERY, "group_by": ["a", "a"]}]}),
            &["exabeam_group_by"],
        ),
        (
            json!({"sequences": [{"query": QUERY, "group_by": []}]}),
            &["exabeam_group_by"],
        ),
        (json!({"severity": "High"}), &["exabeam_severity"]),
        (json!({"outcome": "webhook"}), &["exabeam_outcome"]),
        (json!({"email": {"recipients": []}}), &["exabeam_email"]),
        (
            json!({"email": {"recipients": ["soc"]}}),
            &["exabeam_email"],
        ),
        (
            json!({"email": {"recipients": ["a@b.io", "a@b.io"]}}),
            &["exabeam_email"],
        ),
        (
            json!({"email": {"recipients": ["soc@example.com"], "subject": " "}}),
            &["exabeam_email"],
        ),
        (
            json!({"email": {"recipients": ["soc@example.com"], "subject": "x"}}),
            &[],
        ),
        (
            json!({"email": {"recipients": ["soc@example.com"], "attach_csv": "yes"}}),
            &["exabeam_email"],
        ),
        (
            json!({"suppression": {"for": "2w", "group_by": ["user"]}}),
            &[],
        ),
        (json!({"suppression": {"for": "0m"}}), &["exabeam_duration"]),
        (
            json!({"suppression": {"for": "1h", "group_by": []}}),
            &["exabeam_group_by"],
        ),
        (json!({"delay": "3h"}), &[]),
        (json!({"delay": "7m"}), &[]),
        (json!({"delay": "181m"}), &["exabeam_duration"]),
        (json!({"delay": "1d"}), &["exabeam_duration"]),
        (
            json!({"delay": "99999999999999999999999m"}),
            &["exabeam_duration"],
        ),
        (
            json!({"schedule": [{"every": "week", "days": ["monday"], "from": "08:00Z", "to": "18:00Z"}]}),
            &[],
        ),
        (
            json!({"schedule": [{"every": "week", "days": ["mon"], "from": "08:00Z", "to": "18:00Z"}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "week", "days": ["monday", "monday"], "from": "08:00Z", "to": "18:00Z"}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "day", "from": "8am", "to": "18:00Z"}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "day", "from": "08:00Z", "to": "18:00Z", "days": [1]}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "last_day": true}]}),
            &[],
        ),
        (
            json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "last_day": "yes"}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "days": [0]}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "days": [1, 31]}]}),
            &[],
        ),
        (
            json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z"}]}),
            &["exabeam_schedule"],
        ),
        (
            json!({"schedule": [{
                "every": "days", "first": "monday", "last": "friday", "from": "06:00Z", "to": "20:00Z"
            }]}),
            &[],
        ),
        (
            json!({"schedule": [{
                "every": "days", "first": "monday", "last": "fri", "from": "06:00Z", "to": "20:00Z"
            }]}),
            &["exabeam_schedule"],
        ),
        (json!({"schedule": []}), &["exabeam_schedule"]),
        (json!({"name": "x".repeat(129)}), &["exabeam_name_length"]),
        (json!({"name": "x".repeat(128)}), &[]),
        (json!({"name": "é".repeat(128)}), &[]),
    ];
    for (keys, expected) in cases {
        let expected: BTreeSet<&str> = expected.iter().copied().collect();
        assert_eq!(codes(&keys), expected, "{keys}");
    }
}

#[test]
fn each_code_is_reported_at_its_spec_path() {
    let block = block(&json!({
        "sequences": [
            {"query": " "},
            {"query": QUERY, "group_by": [], "threshold": {"function": "x", "within": "1h"}},
        ],
        "severity": "High",
        "outcome": "webhook",
        "email": {"recipients": []},
        "suppression": {"for": "1x", "group_by": []},
        "delay": "5m",
        "schedule": [{"every": "hour", "from": "08:00Z", "to": "09:00Z"}],
        "name": "x".repeat(200),
    }));
    let mut found = errors(&block);
    found.sort();
    let mut expected = vec![
        pair("exabeam_sequences", &["sequences", "0", "query"]),
        pair("exabeam_group_by", &["sequences", "1", "group_by"]),
        pair(
            "exabeam_threshold_function",
            &["sequences", "1", "threshold"],
        ),
        pair("exabeam_correlation", &["correlation"]),
        pair("exabeam_severity", &["severity"]),
        pair("exabeam_outcome", &["outcome"]),
        pair("exabeam_email", &["email"]),
        pair("exabeam_duration", &["suppression", "for"]),
        pair("exabeam_group_by", &["suppression", "group_by"]),
        pair("exabeam_duration", &["delay"]),
        pair("exabeam_schedule", &["schedule", "0"]),
        pair("exabeam_name_length", &["name"]),
    ];
    expected.sort();
    assert_eq!(found, expected);
    let known: BTreeSet<&str> = constraint_codes().collect();
    assert!(found.iter().all(|(code, _)| known.contains(code.as_str())));
}

#[test]
fn the_messages_name_the_values() {
    let findings = block_findings(&json_node(&block(&json!({
        "severity": "High",
        "outcome": ["x"],
        "sequences": threshold(&json!({"function": "median"})),
        "delay": "5m",
    }))));
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "\"median\" is not an Exabeam function: count, unique_count, value, max, min, sum, average",
            "\"High\" is not an Exabeam severity: none, low, medium, high, critical (lower case)",
            "[\"x\"] is not alert, case or none",
            "delay is 7 to 180 minutes, written in m or h: 7m to 180m, 1h to 3h",
        ]
    );
    let findings = block_findings(&json_node(&block(&json!({
        "sequences": threshold(&json!({"operator": "in", "value": [1]})),
        "name": "é".repeat(130),
    }))));
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "count takes the operator more_than or less_than, not \"in\"",
            "the Exabeam rule name is 130 characters, more than 128: set a shorter \
             configurations.exabeam.name",
        ]
    );
    let findings = block_findings(&json_node(&block(&json!({
        "sequences": threshold(&json!({"function": "value", "field": "f", "operator": null})),
    }))));
    assert_eq!(
        findings[0].message,
        "value takes the operator in or not_in, not None"
    );
    let findings = block_findings(&json_node(&block(&json!({
        "sequences": threshold(&json!({"function": "max", "field": "f", "value": "x"})),
    }))));
    assert_eq!(findings[0].message, "max more_than compares with a number");
    let findings = block_findings(&json_node(&block(&json!({
        "schedule": [{"every": "day", "from": "08:00Z", "to": "18:00Z", "last": "x", "days": [1]}],
    }))));
    assert_eq!(
        findings[0].message,
        "a day recurrence does not take days, last"
    );
}

#[test]
fn threshold_and_window_paths() {
    let block = block(&json!({
        "sequences": [
            {
                "query": "user IN \"Privileged Accounts\"",
                "threshold": {"function": "count", "operator": "more_than", "value": 1, "within": "1w"},
            },
            {"query": QUERY},
        ],
        "correlation": {"within": "PT1H", "group_by": ["a", "a"]},
    }));
    let mut found = errors(&block);
    found.sort();
    assert_eq!(
        found,
        vec![
            pair(
                "exabeam_context_table_trigger",
                &["sequences", "0", "threshold"]
            ),
            pair("exabeam_duration", &["correlation", "within"]),
            pair(
                "exabeam_duration",
                &["sequences", "0", "threshold", "within"]
            ),
            pair("exabeam_group_by", &["correlation", "group_by"]),
        ]
    );
}

#[test]
fn a_model_dump_validates_again() {
    let node = yaml_block("rule-exabeam-sequence-1.0.yaml");
    let mut cx = Context::new();
    let first = ExabeamConfig::from_node(&node, &mut cx).unwrap();
    let dumped = serde_json::to_value(&first).unwrap();
    assert_eq!(dumped["suppression"], Json::Null);
    assert_eq!(dumped["schedule"][0]["from"], json!("06:00Z"));
    let mut cx = Context::new();
    let again = ExabeamConfig::from_node(&json_node(&dumped), &mut cx).unwrap();
    assert_eq!(again, first);
    // Every optional key written as null is the key left out.
    let mut with_nulls = dumped.clone();
    with_nulls["delay"] = Json::Null;
    with_nulls["sequences"][0]["threshold"] = Json::Null;
    assert_eq!(block_findings(&json_node(&with_nulls)), Vec::new());
}

#[test]
fn an_unknown_key_fails_load() {
    assert_eq!(
        errors(&block(&json!({"tags": ["x"]}))),
        vec![pair("extra_forbidden", &["tags"])]
    );
}

#[test]
fn status_is_required() {
    let mut without = base();
    without.as_object_mut().map(|map| map.remove("status"));
    assert_eq!(errors(&without), vec![pair("missing", &["status"])]);
}

#[test]
fn the_garde_check_runs_the_constraints() {
    use garde::Validate;
    let node = yaml_block("rule-exabeam-threshold-1.0.yaml");
    let mut cx = Context::new();
    let mut config = ExabeamConfig::from_node(&node, &mut cx).unwrap();
    assert!(config.validate_with(&crate::Pins::default()).is_ok());
    config.delay = Some("5m".to_owned());
    let error = config.validate_with(&crate::Pins::default()).unwrap_err();
    assert!(error.to_string().contains("exabeam_duration"), "{error}");
    config.delay = None;
    config.sequences.clear();
    assert!(config.validate_with(&crate::Pins::default()).is_err());
}

#[test]
fn durations() {
    for (value, units, parsed) in [
        ("30m", "mhd", Some((30, 'm'))),
        ("4h", "mhd", Some((4, 'h'))),
        ("2w", "mhdw", Some((2, 'w'))),
        ("2w", "mhd", None),
        ("0m", "mhd", None),
        ("1h30m", "mhd", None),
        ("PT1H", "mhd", None),
        ("1 h", "mhd", None),
        ("99999999999999999999m", "m", Some((u64::MAX, 'm'))),
    ] {
        assert_eq!(duration(value, units), parsed, "{value}");
    }
    assert_eq!(
        codes(&json!({"sequences": threshold(&json!({"within": 30}))})),
        BTreeSet::from(["exabeam_duration"])
    );
    assert_eq!(delay_minutes("3h"), Some(180));
    assert_eq!(delay_minutes("1d"), None);
    assert_eq!(unit_name('w'), "weeks");
}

#[test]
fn context_tables() {
    for (query, found) in [
        ("user IN \"Privileged Accounts\"", true),
        ("src_ip in \"Admin Users\".\"IP Address\"", true),
        ("user IN 'Privileged Accounts'", true),
        (
            "activity_type:\"app-login\" AND NOT user IN \"Service Accounts\"",
            true,
        ),
        ("IN \"x\"", true),
        ("message:\"log IN \\\"x\\\"\"", false),
        ("message:\"sign IN\" AND user:\"x\"", false),
        ("LOGIN:\"x\"", false),
        ("a.IN \"x\"", false),
        ("activity_type:\"app-login\"", false),
    ] {
        assert_eq!(uses_context_table(query), found, "{query}");
    }
}

#[test]
fn a_list_or_map_under_every_is_exabeam_schedule() {
    for every in [json!(["day"]), json!({"day": 1})] {
        let found = errors(&block(&json!({
            "schedule": [{"every": every, "from": "08:00Z", "to": "17:00Z"}],
            "severity": "High",
        })));
        assert!(found.contains(&pair("exabeam_schedule", &["schedule", "0"])));
        assert!(found.contains(&pair("exabeam_severity", &["severity"])));
    }
}

#[test]
fn the_python_names_of_keyword_keys_are_unknown_keys() {
    assert_eq!(
        errors(&block(&json!({"suppression": {"for_": "1h"}}))),
        vec![pair("exabeam_duration", &["suppression", "for"])]
    );
    assert!(
        !errors(&block(&json!({
            "schedule": [{"every": "day", "from_": "08:00Z", "to": "09:00Z"}]
        })))
        .is_empty()
    );
}

#[test]
fn a_null_attach_csv_or_correlation_group_by_is_the_key_left_out() {
    let two = json!([{"query": QUERY}, {"query": QUERY}]);
    let block = block(&json!({
        "sequences": two,
        "correlation": {"within": "15m", "group_by": null},
        "email": {"recipients": ["soc@example.com"], "attach_csv": null},
    }));
    let mut cx = Context::new();
    let config = ExabeamConfig::from_node(&json_node(&block), &mut cx).unwrap();
    assert!(config.correlation.unwrap().group_by.is_none());
    assert!(config.email.unwrap().attach_csv.is_none());
}

#[test]
fn nested_unknown_keys_fail_as_unknown_keys_at_their_path() {
    let threshold = json!({"function": "count", "operator": "more_than", "value": 1, "within": "5m", "extra": 1});
    let two = json!([{"query": QUERY}, {"query": QUERY}]);
    let cases = [
        (
            json!({"sequences": [{"query": QUERY, "extra": 1}]}),
            vec!["sequences", "0", "extra"],
        ),
        (
            json!({"sequences": [{"query": QUERY, "threshold": threshold}]}),
            vec!["sequences", "0", "threshold", "extra"],
        ),
        (
            json!({"suppression": {"for": "1h", "unit": "h"}}),
            vec!["suppression", "unit"],
        ),
        (
            json!({"sequences": two, "correlation": {"within": "15m", "extra": 1}}),
            vec!["correlation", "extra"],
        ),
        (
            json!({"email": {"recipients": ["a@b.co"], "cc": []}}),
            vec!["email", "cc"],
        ),
        (
            json!({"schedule": [{"every": "day", "from": "8:00Z", "to": "18:00Z", "tz": "UTC"}]}),
            vec!["schedule", "0", "tz"],
        ),
    ];
    for (keys, path) in cases {
        assert_eq!(
            errors(&block(&keys)),
            vec![pair("extra_forbidden", &path)],
            "{keys}"
        );
    }
    let wrong_day_key =
        json!({"every": "day", "from": "8:00Z", "to": "18:00Z", "days": ["monday"]});
    assert_eq!(
        errors(&block(&json!({"schedule": [wrong_day_key]}))),
        vec![pair("exabeam_schedule", &["schedule", "0"])]
    );
}

#[test]
fn a_suppression_that_is_not_a_table_is_reported_at_for() {
    assert_eq!(
        errors(&block(&json!({"suppression": "1h"}))),
        vec![pair("exabeam_duration", &["suppression", "for"])]
    );
    assert_eq!(
        errors(&block(&json!({"suppression": {"group_by": ["user"]}}))),
        vec![pair("exabeam_duration", &["suppression", "for"])]
    );
}

#[test]
fn shapes_the_checks_refuse_without_a_crash() {
    for keys in [
        json!({"sequences": "x"}),
        json!({"sequences": [1]}),
        json!({"sequences": [{"query": QUERY, "threshold": 3}]}),
        json!({"sequences": [{"query": QUERY, "threshold": {"function": "count", "operator": "more_than", "value": 1, "within": "1m", "field": 5}}]}),
        json!({"sequences": [{"query": QUERY}, {"query": QUERY}], "correlation": "15m"}),
        json!({"email": "soc@example.com"}),
        json!({"schedule": "daily"}),
        json!({"schedule": [{"every": "month", "from": "00:00Z", "to": "23:59Z", "days": "1"}]}),
    ] {
        assert!(!codes(&keys).is_empty(), "{keys}");
    }
    assert_eq!(block_findings(&json_node(&json!("x"))), Vec::new());
    let mut no_status = base();
    no_status["status"] = Json::Null;
    no_status["delay"] = json!("5m");
    // Without a status the constraints wait for the field's own error.
    assert!(
        errors(&no_status)
            .iter()
            .all(|(code, _)| !code.starts_with("exabeam_"))
    );
    assert_eq!(code_message("nope"), "");
    assert_eq!(
        name_length_finding("abc").field_path(),
        vec!["name".to_owned()]
    );
}

#[test]
fn literal_values_round_trip() {
    for function in [
        ExabeamFunction::Count,
        ExabeamFunction::UniqueCount,
        ExabeamFunction::Value,
        ExabeamFunction::Max,
        ExabeamFunction::Min,
        ExabeamFunction::Sum,
        ExabeamFunction::Average,
    ] {
        assert_eq!(
            serde_json::to_value(function).unwrap(),
            json!(function.as_str())
        );
    }
    for operator in [
        ExabeamOperator::MoreThan,
        ExabeamOperator::LessThan,
        ExabeamOperator::In,
        ExabeamOperator::NotIn,
    ] {
        assert_eq!(
            serde_json::to_value(operator).unwrap(),
            json!(operator.as_str())
        );
    }
    for severity in [
        ExabeamSeverity::NoSeverity,
        ExabeamSeverity::Low,
        ExabeamSeverity::Medium,
        ExabeamSeverity::High,
        ExabeamSeverity::Critical,
    ] {
        assert_eq!(
            serde_json::to_value(severity).unwrap(),
            json!(severity.as_str())
        );
    }
    for outcome in [
        ExabeamOutcome::Alert,
        ExabeamOutcome::Case,
        ExabeamOutcome::NoOutcome,
    ] {
        assert_eq!(
            serde_json::to_value(outcome).unwrap(),
            json!(outcome.as_str())
        );
    }
    for every in [
        ExabeamEvery::Day,
        ExabeamEvery::Week,
        ExabeamEvery::Month,
        ExabeamEvery::Days,
    ] {
        assert_eq!(serde_json::to_value(every).unwrap(), json!(every.as_str()));
    }
    assert_eq!(
        SCHEMA,
        <ExabeamConfig as crate::objects::platform::PlatformBlock>::SCHEMA_IDENTIFIER
    );
}

#[test]
fn every_constraint_code_is_an_engine_code_with_a_description() {
    for code in constraint_codes() {
        assert!(
            opentide_core::codes::ALL.contains(&code),
            "{code} is not in opentide_core::codes::ALL"
        );
        assert!(opentide_core::codes::describe(code).is_some(), "{code}");
        assert!(!code_message(code).is_empty(), "{code}");
    }
}

fn rule_node(value: &Json) -> Node {
    json_node(value)
}

fn rule_with(name: &str, block: &Json) -> Json {
    json!({"name": name, "configurations": {"exabeam": block}})
}

#[test]
fn names_resolve_from_the_block_then_the_rule() {
    let enabled = json!({"enabled": true, "name": "Block name"});
    assert_eq!(
        rule_exabeam_name(&rule_node(&rule_with("Rule", &enabled)), true).as_deref(),
        Some("Block name")
    );
    let unnamed = json!({"enabled": true, "name": ""});
    assert_eq!(
        rule_exabeam_name(&rule_node(&rule_with("Rule", &unnamed)), true).as_deref(),
        Some("Rule")
    );
    let disabled = json!({"enabled": false});
    assert_eq!(
        rule_exabeam_name(&rule_node(&rule_with("Rule", &disabled)), true),
        None
    );
    assert_eq!(
        rule_exabeam_name(&rule_node(&rule_with("Rule", &disabled)), false).as_deref(),
        Some("Rule")
    );
    assert_eq!(
        rule_exabeam_name(&rule_node(&json!({"name": "x"})), false),
        None
    );
    assert_eq!(
        rule_exabeam_name(
            &rule_node(&json!({"configurations": {"exabeam": "x"}})),
            false
        ),
        None
    );
}

#[test]
fn duplicate_names_compare_case_insensitively_among_enabled_blocks() {
    let a = rule_node(&rule_with("Failed logins", &json!({"enabled": true})));
    let b = rule_node(&rule_with(
        "Other",
        &json!({"enabled": true, "name": "FAILED LOGINS"}),
    ));
    let c = rule_node(&rule_with("Failed logins", &json!({"enabled": false})));
    let d = rule_node(&rule_with("Unique", &json!({"enabled": true})));
    let long = rule_node(&rule_with(&"x".repeat(129), &json!({"enabled": false})));
    let named = rule_node(&rule_with(
        &"y".repeat(129),
        &json!({"enabled": true, "name": "short"}),
    ));
    let rules = [
        ("a", &a),
        ("b", &b),
        ("c", &c),
        ("d", &d),
        ("long", &long),
        ("named", &named),
    ];
    let found = name_findings(&rules, ["a", "b", "c", "d", "long", "named", "missing"]);
    let summary: Vec<(&str, &str)> = found.iter().map(|f| (f.uuid.as_str(), f.code)).collect();
    assert_eq!(
        summary,
        [
            ("a", "exabeam_name_duplicate"),
            ("b", "exabeam_name_duplicate"),
            ("long", "exabeam_name_length"),
        ]
    );
    assert_eq!(
        found[0].message,
        "Exabeam rule name \"Failed logins\" is also the name of rule(s) b, compared \
         case-insensitively; Exabeam rule names are unique"
    );
    assert_eq!(found[0].value.as_deref(), Some("Failed logins"));
    assert_eq!(
        found[2].message,
        "the Exabeam rule name (the rule name) is 129 characters, more than 128"
    );
    // Only the rules in scope are reported, against every rule.
    assert_eq!(name_findings(&rules, ["b"]).len(), 1);
}

#[test]
fn advisories_of_a_block() {
    let silent = rule_node(&rule_with("r", &json!({"outcome": "none"})));
    let found = advisories(&silent);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, OUTCOME_SILENT);
    assert_eq!(
        found[0].field_path,
        ["configurations", "exabeam", "outcome"]
    );
    let emailed = rule_node(&rule_with(
        "r",
        &json!({"outcome": "none", "email": {"recipients": ["a@b.co"]}}),
    ));
    assert!(advisories(&emailed).is_empty());
    let null_email = rule_node(&rule_with("r", &json!({"outcome": "none", "email": null})));
    assert_eq!(advisories(&null_email).len(), 1);

    let ordered = |within: &str| {
        rule_node(&rule_with(
            "r",
            &json!({
                "sequences": [
                    {"query": "a"},
                    {"query": "b", "threshold": {"within": "10m"}},
                ],
                "correlation": {"within": within},
            }),
        ))
    };
    // 1 (any match) + 10 + 1 between = 12 minutes.
    let found = advisories(&ordered("12m"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, CORRELATION_WINDOW);
    assert_eq!(
        found[0].message,
        "correlation.within 12m is not more than the 12 minutes the ordered sequences need \
         (their windows, one minute for each any-match sequence, and one minute between \
         sequences): make it more than 12m"
    );
    assert!(advisories(&ordered("13m")).is_empty());
    assert!(advisories(&ordered("1h")).is_empty());
    assert!(
        advisories(&ordered("1h30m")).is_empty(),
        "a bad window is a constraint error"
    );
    let bad_threshold = rule_node(&rule_with(
        "r",
        &json!({
            "sequences": [{"query": "a", "threshold": {"within": "x"}}, {"query": "b"}],
            "correlation": {"within": "1m"},
        }),
    ));
    assert!(advisories(&bad_threshold).is_empty());
    assert!(advisories(&rule_node(&json!({"name": "r"}))).is_empty());
    let sequences = match &json_node(&json!([{"query": "a"}, "x", {"threshold": 3}])).value {
        Value::Seq(items) => items.clone(),
        _ => Vec::new(),
    };
    assert_eq!(ordered_minutes(&sequences), None);
    let sequences = match &json_node(&json!([{"query": "a"}, "x"])).value {
        Value::Seq(items) => items.clone(),
        _ => Vec::new(),
    };
    assert_eq!(ordered_minutes(&sequences), Some(3));
}
