//! `DatadogConfig` and its constraint codes (RFC
//! `docs/internal/rfc-datadog-cloud-siem.md` §5.9): each block is a JSON
//! value, read as the node the YAML would give, and each finding is held at
//! its code and its path.

use std::collections::BTreeSet;

use serde_json::{Value as Json, json};

use super::*;
use crate::from_node::FromNode;
use crate::objects::platform::json_node;

/// A fixture of `tests/fixtures/datadog/`, compiled in (the crate does no I/O).
fn fixture(name: &str) -> &'static str {
    macro_rules! fixtures {
        ($($file:literal),* $(,)?) => {
            match name {
                $($file => include_str!(concat!("../../../../../../tests/fixtures/datadog/", $file)),)*
                other => panic!("no fixture {other}"),
            }
        };
    }
    fixtures!(
        "rule-datadog-threshold-1.0.yaml",
        "rule-datadog-minimal-1.0.yaml",
        "rule-datadog-new-value-1.0.yaml",
        "rule-datadog-impossible-travel-1.0.yaml",
        "rule-datadog-anomaly-1.0.yaml",
        "rule-datadog-distinct-1.0.yaml",
        "invalid/rule-datadog-condition-number-first.yaml",
        "invalid/rule-datadog-window.yaml",
        "invalid/rule-datadog-sequence.yaml",
        "invalid/rule-datadog-tag.yaml",
    )
}

fn base() -> Json {
    json!({
        "enabled": true,
        "schema": "platform::datadog::1.0",
        "status": "STAGING",
        "queries": [{"query": "source:okta @evt.outcome:FAILURE"}],
        "cases": [{"condition": "a > 5"}],
    })
}

fn block(keys: &Json) -> Json {
    let mut out = base();
    for (key, value) in keys.as_object().unwrap_or(&serde_json::Map::new()) {
        out[key] = value.clone();
    }
    out
}

fn findings(keys: &Json) -> Vec<(&'static str, Vec<String>)> {
    block_findings(&json_node(&block(keys)))
        .into_iter()
        .map(|finding| (finding.code, finding.field_path()))
        .collect()
}

fn codes(keys: &Json) -> BTreeSet<&'static str> {
    block_codes(&json_node(&block(keys)))
}

fn at(path: &[&str]) -> Vec<String> {
    path.iter().map(|part| (*part).to_owned()).collect()
}

fn yaml_block(name: &str) -> std::sync::Arc<Node> {
    let document = crate::node::load(fixture(name)).unwrap();
    let root = document.root().unwrap().clone();
    root.get("configurations")
        .and_then(|configurations| configurations.get("datadog"))
        .unwrap()
        .clone()
}

#[test]
fn the_rfc_s_blocks_validate() {
    for name in [
        "rule-datadog-threshold-1.0.yaml",
        "rule-datadog-minimal-1.0.yaml",
        "rule-datadog-new-value-1.0.yaml",
        "rule-datadog-impossible-travel-1.0.yaml",
        "rule-datadog-anomaly-1.0.yaml",
        "rule-datadog-distinct-1.0.yaml",
    ] {
        let node = yaml_block(name);
        assert_eq!(block_findings(&node), Vec::new(), "{name}");
        let mut cx = Context::new();
        let value = DatadogConfig::from_node(&node, &mut cx);
        assert_eq!(cx.into_errors(), Vec::new(), "{name}");
        assert!(value.is_some(), "{name}");
    }
}

#[test]
fn each_invalid_fixture_fails_with_its_code() {
    for (name, code) in [
        (
            "rule-datadog-condition-number-first.yaml",
            "datadog_condition",
        ),
        ("rule-datadog-window.yaml", "datadog_duration"),
        ("rule-datadog-sequence.yaml", "datadog_method_unsupported"),
        ("rule-datadog-tag.yaml", "datadog_tag"),
    ] {
        let node = yaml_block(&format!("invalid/{name}"));
        let mut cx = Context::new();
        assert!(DatadogConfig::from_node(&node, &mut cx).is_none(), "{name}");
        let found: BTreeSet<String> = cx
            .into_errors()
            .iter()
            .map(|error| error.kind.pydantic_type().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(found, BTreeSet::from([code.to_owned()]), "{name}");
    }
}

#[test]
fn each_finding_is_its_own_error_at_its_path() {
    let raw = block(&json!({
        "detection": {"window": "7m"},
        "tags": ["Team:x"],
        "cases": [{"condition": "a > 5", "severity": "urgent"}],
    }));
    let mut cx = Context::new();
    assert!(DatadogConfig::from_node(&json_node(&raw), &mut cx).is_none());
    let mut errors: Vec<(String, Vec<String>)> = cx
        .into_errors()
        .iter()
        .map(|error| {
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                error.field_path(),
            )
        })
        .collect();
    errors.sort();
    assert_eq!(
        errors,
        vec![
            ("datadog_duration".to_owned(), at(&["detection", "window"])),
            (
                "datadog_severity".to_owned(),
                at(&["cases", "0", "severity"])
            ),
            ("datadog_tag".to_owned(), at(&["tags", "0"])),
        ]
    );
}

#[test]
fn method_unsupported() {
    for method in [
        "sequence",
        "signal_correlation",
        "Threshold",
        "anomaly_detection",
    ] {
        assert_eq!(
            findings(&json!({"detection": {"method": method}})),
            vec![("datadog_method_unsupported", at(&["detection", "method"]))],
            "{method}"
        );
    }
    assert!(codes(&json!({"detection": {"method": 3}})).contains("datadog_method_unsupported"));
}

#[test]
fn durations() {
    for window in ["0", "1m", "5m", "1h", "12h", "1d"] {
        assert_eq!(
            codes(&json!({
                "detection": {"window": window},
                "signal": {"keep_alive": "1d", "max_duration": "1d"},
            })),
            BTreeSet::new(),
            "{window}"
        );
    }
    assert_eq!(codes(&json!({"detection": {"window": 0}})), BTreeSet::new());
    for window in [
        json!("7m"),
        json!("2d"),
        json!(300),
        json!("5 m"),
        json!(""),
    ] {
        assert_eq!(
            findings(&json!({"detection": {"window": window}})),
            vec![("datadog_duration", at(&["detection", "window"]))],
            "{window}"
        );
    }
    // learning, per method.
    let new_value = |learning: &str| {
        json!({
            "queries": [{"query": "x", "new_value": ["@a"]}],
            "detection": {"method": "new_value", "learning": learning, "forget_after": "7d"},
            "cases": [{}],
        })
    };
    assert_eq!(codes(&new_value("0d")), BTreeSet::new());
    assert_eq!(codes(&new_value("30d")), BTreeSet::new());
    for bad in ["3h", "31d", "07d", "-1d", "1w"] {
        assert_eq!(
            findings(&new_value(bad)),
            vec![("datadog_duration", at(&["detection", "learning"]))],
            "{bad}"
        );
    }
    let anomaly = |learning: &str| {
        json!({
            "detection": {"method": "anomaly", "learning": learning},
            "cases": [{"condition": "a > 0.9"}],
        })
    };
    assert_eq!(codes(&anomaly("14d")), BTreeSet::new());
    assert_eq!(codes(&anomaly("1h")), BTreeSet::new());
    assert_eq!(codes(&anomaly("3d")), BTreeSet::from(["datadog_duration"]));
    let travel = |learning: &str| json!({"detection": {"method": "impossible_travel", "learning": learning}, "cases": [{}]});
    assert_eq!(codes(&travel("1d")), BTreeSet::new());
    assert_eq!(codes(&travel("0d")), BTreeSet::from(["datadog_duration"]));
    // forget_after and bucket.
    assert_eq!(
        findings(&json!({
            "queries": [{"query": "x", "new_value": ["@a"]}],
            "detection": {"method": "new_value", "forget_after": "0d"},
            "cases": [{}],
        })),
        vec![("datadog_duration", at(&["detection", "forget_after"]))]
    );
    assert_eq!(
        findings(&json!({
            "detection": {"method": "anomaly", "bucket": "2h"},
            "cases": [{"condition": "a > 0.9"}],
        })),
        vec![("datadog_duration", at(&["detection", "bucket"]))]
    );
    // keep_alive and max_duration take the window's values.
    assert_eq!(
        findings(&json!({"signal": {"keep_alive": "2d", "max_duration": "45m"}})),
        vec![
            ("datadog_duration", at(&["signal", "keep_alive"])),
            ("datadog_duration", at(&["signal", "max_duration"])),
        ]
    );
}

#[test]
fn window_order() {
    assert_eq!(
        findings(&json!({
            "detection": {"window": "1h"},
            "signal": {"keep_alive": "30m"},
        })),
        vec![("datadog_window_order", at(&["signal", "keep_alive"]))]
    );
    assert_eq!(
        findings(&json!({"detection": {"window": "12h"}})),
        vec![("datadog_window_order", at(&["detection", "window"]))],
        "12h is longer than the default keep_alive of 1h"
    );
    assert_eq!(
        findings(&json!({
            "detection": {"window": "1d"},
            "signal": {"keep_alive": "1d", "max_duration": "12h"},
        })),
        vec![("datadog_window_order", at(&["signal", "max_duration"]))]
    );
    assert_eq!(
        codes(&json!({"detection": {"window": "1h"}, "signal": {"keep_alive": "1h"}})),
        BTreeSet::new()
    );
}

#[test]
fn query_names() {
    assert_eq!(
        findings(&json!({
            "queries": [{"name": "Failed-Logins", "query": "x"}],
            "cases": [{"condition": "a > 1"}],
        }))[0],
        ("datadog_query_name", at(&["queries", "0", "name"]))
    );
    assert_eq!(
        findings(&json!({
            "queries": [{"name": "x", "query": "a"}, {"name": "x", "query": "b"}],
            "cases": [{"condition": "x > 1"}],
        })),
        vec![("datadog_query_name", at(&["queries", "1", "name"]))]
    );
    // An unnamed query is `a` by position; a query named `a` after it clashes.
    assert_eq!(
        findings(&json!({
            "queries": [{"query": "x"}, {"name": "a", "query": "y"}],
            "cases": [{"condition": "a > 1"}],
        })),
        vec![("datadog_query_name", at(&["queries", "1", "name"]))]
    );
    assert_eq!(
        findings(&json!({
            "queries": [{"name": "n", "query": "x", "new_value": ["@a"]}],
            "detection": {"method": "new_value", "forget_after": "7d"},
            "cases": [{}],
        })),
        vec![("datadog_query_name", at(&["queries", "0", "name"]))]
    );
    assert_eq!(
        super::query_names(&json_node(&block(&json!({
            "queries": [{"query": "x"}, {"name": "second", "query": "y"}, {"query": "z"}]
        })))),
        vec!["a", "second", "c"]
    );
}

#[test]
fn measures() {
    assert_eq!(
        findings(&json!({
            "queries": [{"query": "x", "count_distinct": "@a", "sum": "@b"}],
        })),
        vec![("datadog_measure", at(&["queries", "0", "sum"]))]
    );
    assert_eq!(
        findings(&json!({"queries": [{"query": "x", "new_value": ["@a"]}]})),
        vec![("datadog_measure", at(&["queries", "0", "new_value"]))],
        "new_value without method: new_value"
    );
    assert_eq!(
        findings(&json!({
            "queries": [{"query": "x"}],
            "detection": {"method": "new_value", "forget_after": "7d"},
            "cases": [{}],
        })),
        vec![("datadog_measure", at(&["queries", "0"]))],
        "method: new_value without new_value"
    );
    for fields in [json!([]), json!(["@a", "@b", "@c", "@d", "@e", "@f"])] {
        assert_eq!(
            findings(&json!({
                "queries": [{"query": "x", "new_value": fields}],
                "detection": {"method": "new_value", "forget_after": "7d"},
                "cases": [{}],
            })),
            vec![("datadog_measure", at(&["queries", "0", "new_value"]))]
        );
    }
    assert_eq!(
        findings(&json!({
            "queries": [{"query": "x", "max": "@duration"}],
            "detection": {"method": "impossible_travel"},
            "cases": [{}],
        })),
        vec![("datadog_measure", at(&["queries", "0", "max"]))]
    );
}

#[test]
fn detection_options() {
    assert_eq!(
        findings(&json!({"detection": {"bucket": "5m"}})),
        vec![("datadog_detection_option", at(&["detection", "bucket"]))]
    );
    assert_eq!(
        findings(
            &json!({"detection": {"method": "new_value"}, "queries": [{"query": "x", "new_value": ["@a"]}], "cases": [{}]})
        ),
        vec![("datadog_detection_option", at(&["detection"]))],
        "new_value without forget_after"
    );
    assert_eq!(
        findings(&json!({
            "detection": {"method": "impossible_travel", "tolerance": 3},
            "cases": [{}],
        })),
        vec![("datadog_detection_option", at(&["detection", "tolerance"]))]
    );
    assert_eq!(
        findings(&json!({
            "detection": {"method": "anomaly", "tolerance": 6},
            "cases": [{"condition": "a > 0.9"}],
        })),
        vec![("datadog_detection_option", at(&["detection", "tolerance"]))]
    );
    // An impossible travel block may set neither learning nor
    // detect_ip_transitions (RFC §5.4).
    assert_eq!(
        codes(&json!({"detection": {"method": "impossible_travel"}, "cases": [{}]})),
        BTreeSet::new()
    );
}

#[test]
fn signal_group_by() {
    let queries = json!([{"query": "x", "group_by": ["@usr.email"]}]);
    assert_eq!(
        codes(&json!({"queries": queries, "signal": {"group_by": ["@usr.email"]}})),
        BTreeSet::new()
    );
    assert_eq!(
        findings(&json!({"queries": queries, "signal": {"group_by": ["@usr.email", "@usr.id"]}})),
        vec![("datadog_signal_group_by", at(&["signal", "group_by", "1"]))]
    );
}

#[test]
fn conditions() {
    let case = |condition: &str| json!({"cases": [{"condition": condition}]});
    assert_eq!(
        findings(&case("3 < a")),
        vec![("datadog_condition", at(&["cases", "0", "condition"]))]
    );
    assert_eq!(
        findings(&case("fail > 1")),
        vec![("datadog_condition", at(&["cases", "0", "condition"]))],
        "no query fail"
    );
    assert_eq!(
        findings(&json!({"cases": [{"severity": "high"}]})),
        vec![("datadog_condition", at(&["cases", "0"]))],
        "threshold needs a condition"
    );
    let anomaly = |condition: &str| json!({"detection": {"method": "anomaly"}, "cases": [{"condition": condition}]});
    assert_eq!(codes(&anomaly("a > 0.995")), BTreeSet::new());
    assert_eq!(
        codes(&anomaly("a > 5")),
        BTreeSet::from(["datadog_condition"])
    );
    assert_eq!(
        codes(&anomaly("a > 1")),
        BTreeSet::from(["datadog_condition"])
    );
    assert_eq!(
        codes(&anomaly("a < 0.5")),
        BTreeSet::from(["datadog_condition"])
    );
    assert_eq!(codes(&case("a < 5")), BTreeSet::new(), "threshold takes <");
    // new_value and impossible travel cases need no condition.
    assert_eq!(
        codes(
            &json!({"detection": {"method": "impossible_travel"}, "cases": [{"severity": "low"}]})
        ),
        BTreeSet::new()
    );
    assert_eq!(codes(&case("a > 1 || a > 2 && a > 3")), BTreeSet::new());
}

#[test]
fn tags() {
    for good in ["team:identity", "env:prod", "a", "x/y.z-w_v:1"] {
        assert_eq!(codes(&json!({"tags": [good]})), BTreeSet::new(), "{good}");
    }
    let long = format!("a{}", "b".repeat(200));
    for bad in [
        "Team:Identity",
        "1team",
        ":x",
        "team identity",
        "équipe",
        long.as_str(),
    ] {
        assert_eq!(
            findings(&json!({"tags": ["ok", bad]})),
            vec![("datadog_tag", at(&["tags", "1"]))],
            "{bad}"
        );
    }
}

#[test]
fn the_mixed_condition_is_a_warning() {
    let rule = json!({"configurations": {"datadog": block(&json!({
        "queries": [{"query": "a"}, {"query": "b"}, {"query": "c"}],
        "cases": [
            {"condition": "a > 1 || b > 1 && c > 1"},
            {"condition": "a > 1 || b > 1"},
        ],
    }))}});
    let found = advisories(&json_node(&rule));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, CONDITION_MIXED);
    assert_eq!(
        found[0].field_path,
        at(&["configurations", "datadog", "cases", "0", "condition"])
    );
}

#[test]
fn every_code_has_a_message() {
    for code in constraint_codes() {
        assert!(!code_message(code).is_empty(), "{code}");
        assert!(code.starts_with("datadog_"), "{code}");
    }
}

#[test]
fn a_garde_validation_reports_the_first_finding() {
    let node = yaml_block("rule-datadog-threshold-1.0.yaml");
    let mut cx = Context::new();
    let model = DatadogConfig::from_node(&node, &mut cx).unwrap();
    assert!(garde::Validate::validate_with(&model, &Pins::default()).is_ok());
}
