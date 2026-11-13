//! The platform blocks' tests, ported from the oracle's
//! `tests/test_platforms/test_elastic_model.py`,
//! `tests/test_platforms/test_sysdig_model.py`,
//! `tests/test_models/test_platform*.py` and
//! `tests/test_models/test_sentinel_attack.py`: each block is a Python dict
//! there, a JSON value here, read as the node the YAML would give.

use garde::Validate;
use serde_json::{Value as Json, json};

use super::*;
use crate::Pins;

/// The block's errors, as `str(ValidationError)` would show them: each
/// error's path and message.
fn errors(platform: &str, block: &Json) -> String {
    match parse_platform_config(platform, &json_node(block)) {
        Ok(_) => String::new(),
        Err(ParseError::Invalid(errors)) => errors
            .iter()
            .map(|error| format!("{}: {}", error.field_path().join("."), error.message))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(ParseError::UnknownPlatform(message)) => message,
    }
}

fn valid(platform: &str, block: &Json) -> PlatformConfig {
    match parse_platform_config(platform, &json_node(block)) {
        Ok(config) => config,
        Err(error) => panic!("{block}: {error:?}"),
    }
}

fn merged(base: &Json, overrides: &Json) -> Json {
    let mut out = base.clone();
    for (key, value) in overrides.as_object().unwrap() {
        out[key] = value.clone();
    }
    out
}

// ---------------------------------------------------------------------------
// The registry, the shared fields, QueryText.
// ---------------------------------------------------------------------------

#[test]
fn the_registry_is_closed_and_in_the_containers_order() {
    let keys: Vec<&str> = PLATFORM_CONFIG_MODELS
        .iter()
        .map(|entry| entry.key)
        .collect();
    assert_eq!(keys, crate::objects::RuleConfigurations::PLATFORMS);
    for entry in PLATFORM_CONFIG_MODELS {
        assert_eq!(entry.schema, format!("platform::{}::1.0", entry.key));
    }
    assert_eq!(registered_model("sysdig").unwrap().model, "SysdigConfig");
    assert_eq!(registered_model("sentinal"), None);
    assert_eq!(SysdigConfig::platform(), "sysdig");
    assert_eq!(DefenderConfig::platform(), "defender_for_endpoint");
    assert_eq!(
        parse_platform_config("sentinal", &json_node(&json!({}))),
        Err(ParseError::UnknownPlatform(
            "Unknown platform \"sentinal\"".to_owned()
        ))
    );
}

#[test]
fn a_block_names_its_own_schema_or_none() {
    let block = json!({"status": "STAGING", "query": "q", "schema": "platform::splunk::1.0"});
    assert!(matches!(valid("splunk", &block), PlatformConfig::Splunk(_)));
    let wrong = merged(&block, &json!({"schema": "splunk::2.1"}));
    assert_eq!(
        errors("splunk", &wrong),
        "schema: Value error, unknown platform schema \"splunk::2.1\": this block's schema is \
         \"platform::splunk::1.0\""
    );
    let other = merged(&block, &json!({"schema": "platform::sentinel::1.0"}));
    assert!(errors("splunk", &other).contains("this block's schema is \"platform::splunk::1.0\""));
    let PlatformConfig::Splunk(splunk) = valid("splunk", &merged(&block, &json!({"schema": null})))
    else {
        unreachable!()
    };
    assert_eq!(splunk.platform_schema, None);
    // `populate_by_name`: the field's own name reads too.
    let PlatformConfig::Splunk(splunk) = valid(
        "splunk",
        &json!({"status": "S", "query": "q", "platform_schema": "platform::splunk::1.0"}),
    ) else {
        unreachable!()
    };
    assert_eq!(
        splunk.platform_schema.as_deref(),
        Some("platform::splunk::1.0")
    );
}

#[test]
fn status_is_required_on_every_block() {
    for entry in PLATFORM_CONFIG_MODELS {
        let found = errors(entry.key, &json!({}));
        assert!(
            found.contains("status: Field required"),
            "{}: {found}",
            entry.key
        );
    }
}

#[test]
fn every_query_text_refuses_a_blank_query() {
    for (platform, block) in [
        ("splunk", json!({"status": "S"})),
        ("carbon_black_cloud", json!({"status": "S"})),
        (
            "crowdstrike",
            json!({"status": "S", "details": {"trigger": "t", "outcome": "o"},
                   "schedule": {"frequency": "1h", "lookback": "1h"}}),
        ),
        (
            "sentinel",
            json!({"status": "S", "scheduling": {}, "alert": {}}),
        ),
        (
            "defender_for_endpoint",
            json!({"status": "S", "alert": {"category": "c"}, "impacted_entities": {},
                   "scheduling": "NRT"}),
        ),
    ] {
        for blank in ["", "   ", "\n\t", "\u{1c}", "\u{a0}"] {
            let found = errors(platform, &merged(&block, &json!({"query": blank})));
            assert_eq!(
                found, "query: Value error, query must not be empty",
                "{platform}"
            );
        }
        assert_eq!(
            errors(platform, &merged(&block, &json!({"query": "x"}))),
            ""
        );
    }
    assert_eq!(check_query_text(" x "), Ok(()));
}

#[test]
fn legacy_keys_are_declared_empty_and_the_pre_pass_keeps_the_block() {
    assert_eq!(legacy_keys("ElasticConfig"), &[]);
    assert_eq!(legacy_keys("SysdigConfig"), &[]);
    assert_eq!(legacy_keys("SentinelConfig"), &[]);
    let block = json_node(&json!({"status": "S", "interval": "5m"}));
    let filled = fill_legacy_keys("ElasticConfig", &block);
    assert!(crate::objects::any::same(&filled, &block));
}

#[test]
fn legacy_external_id_keys_are_superseded_by_external_id_in_rule() {
    for key in ["rule_id", "rule_id_bundle", "rule_id::prod"] {
        assert!(is_legacy_external_id_key(key), "{key}");
        let path = [
            "configurations".to_owned(),
            "splunk".to_owned(),
            key.to_owned(),
        ];
        assert!(is_superseded(&path), "{key}");
    }
    for key in ["rule", "rule_ids", "id"] {
        assert!(!is_legacy_external_id_key(key), "{key}");
    }
    let deeper: Vec<String> = ["configurations", "splunk", "rule_id", "x"]
        .map(str::to_owned)
        .to_vec();
    assert!(!is_superseded(&deeper));
}

#[test]
fn named_checks_are_registered_by_name() {
    assert_eq!(
        named_check("elastic_rule_shape").unwrap().model,
        "ElasticConfig"
    );
    assert_eq!(
        named_check("sysdig_rule_shape").unwrap().model,
        "SysdigConfig"
    );
    assert!(named_check("splunk_rule_shape").is_none());
    let codes: BTreeSet<&str> = ["b", "a"].into_iter().collect();
    assert_eq!(
        codes_message("ElasticConfig", &codes),
        "ElasticConfig validation failed with code(s): a, b"
    );
}

// ---------------------------------------------------------------------------
// elastic_rule_shape (`test_elastic_model.py`).
// ---------------------------------------------------------------------------

const ELASTIC: &str = "configurations.elastic";

#[test]
fn elastic_omitted_status_is_the_missing_field() {
    let found = errors(
        "elastic",
        &json!({"type": "query", "query": "process.name: *", "index": ["logs-*"]}),
    );
    assert_eq!(found, "status: Field required");
    let _ = ELASTIC;
}

#[test]
fn elastic_invalid_rfc_block_reports_all_three_codes() {
    let found = errors(
        "elastic",
        &json!({"enabled": true, "schema": "platform::elastic::1.0", "status": "STAGING",
                "type": "esql", "language": "kuery", "query": "FROM logs-* | LIMIT 10",
                "index": ["logs-*"], "suppression": {"duration": "1h"}}),
    );
    assert_eq!(
        found,
        ": Value error, ElasticConfig validation failed with code(s): esql_source, language, \
         suppression_shape"
    );
}

#[test]
fn elastic_constraint_codes() {
    for (code, block) in [
        (
            "type_block",
            json!({"type": "query", "query": "x", "threshold": {"field": [], "value": 1}}),
        ),
        (
            "type_block",
            json!({"type": "query", "query": "x", "interval": "5m"}),
        ),
        (
            "type_block",
            json!({"type": "query", "query": "x", "alert_suppression": {"duration": "1h"}}),
        ),
        (
            "language",
            json!({"type": "eql", "query": "x", "language": "kuery"}),
        ),
        (
            "esql_source",
            json!({"type": "esql", "query": "FROM x", "data_view_id": "d"}),
        ),
        (
            "index_xor_data_view",
            json!({"type": "query", "query": "x", "index": ["a"], "data_view_id": "d"}),
        ),
        (
            "index_list",
            json!({"type": "query", "query": "x", "index": "logs-*"}),
        ),
        (
            "suppression_shape",
            json!({"type": "threshold", "query": "x",
            "threshold": {"field": [], "value": 1},
            "suppression": {"group_by": ["a"], "duration": "1h"}}),
        ),
        (
            "new_terms_fields",
            json!({"type": "new_terms", "query": "x",
            "new_terms": {"fields": ["a", "b", "c", "d"], "history_window_start": "7d"}}),
        ),
        (
            "threshold_fields",
            json!({"type": "threshold", "query": "x", "threshold": {"field": [], "value": 0}}),
        ),
        (
            "risk_score",
            json!({"type": "query", "query": "x", "risk": {"score": 101}}),
        ),
        (
            "duration",
            json!({"type": "query", "query": "x", "scheduling": {"interval": "5min", "lookback": "1m"}}),
        ),
        (
            "filter_shape",
            json!({"type": "query", "query": "x", "filters": [{"field": "a", "value": "b", "meta": {}}]}),
        ),
        (
            "exception_type",
            json!({"type": "query", "query": "x", "exceptions": {"lists": [
            {"id": "1", "list_id": "l1", "namespace_type": "single", "type": "invalid_type"}]}}),
        ),
        (
            "response_action",
            json!({"type": "query", "query": "x", "actions": {"respond": [{"endpoint": "reboot-now"}]}}),
        ),
    ] {
        let block = merged(&json!({"status": "STAGING"}), &block);
        let codes = elastic::block_codes(&json_node(&block));
        assert!(codes.contains(code), "{code}: {block} gave {codes:?}");
        assert!(errors("elastic", &block).contains(code), "{code}");
    }
}

#[test]
fn elastic_machine_learning_job_id_passthrough() {
    for job_id in [json!("rare_process_by_host"), json!(["job_one", "job_two"])] {
        let PlatformConfig::Elastic(config) = valid(
            "elastic",
            &json!({"status": "STAGING", "type": "machine_learning",
                    "machine_learning": {"job_id": job_id, "anomaly_threshold": 50}}),
        ) else {
            unreachable!()
        };
        assert_eq!(
            serde_json::to_value(config.machine_learning.unwrap().job_id).unwrap(),
            job_id
        );
    }
}

fn elastic_base() -> Json {
    json!({"status": "STAGING", "type": "query", "query": "process.name: *"})
}

#[test]
fn elastic_rejects_with_a_code_not_a_crash() {
    for (overrides, code) in [
        (
            json!({"actions": {"respond": [{"osquery": {"timeout": 60}}]}}),
            "response_action",
        ),
        (
            json!({"actions": {"respond": [{"endpoint": "isolate", "bogus": 1}]}}),
            "response_action",
        ),
        (
            json!({"actions": {"respond": [{"action_type_id": ".osquery", "params": {}}]}}),
            "response_action",
        ),
        (json!({"filters": [{}]}), "filter_shape"),
        (json!({"filters": [{"meta": {}}]}), "filter_shape"),
        (
            json!({"filters": [{"meta": {"negate": false}, "query": {"match_all": {}}, "negate": true}]}),
            "filter_shape",
        ),
        (json!({"severity": "Hgh"}), "severity"),
        (json!({"severity": {"default": "urgent"}}), "severity"),
        (json!({"suppression": "1h"}), "suppression_shape"),
        (
            json!({"suppression": {"group_by": "host.name"}}),
            "suppression_shape",
        ),
        (
            json!({"type": "threshold", "threshold": {"value": "x"}, "suppression": {"duration": "1h"}}),
            "threshold_fields",
        ),
        (
            json!({"type": "new_terms", "new_terms": {"fields": "user.name", "history_window_start": "14d"}}),
            "new_terms_fields",
        ),
    ] {
        let block = merged(&elastic_base(), &overrides);
        assert!(errors("elastic", &block).contains(code), "{code}: {block}");
    }
}

#[test]
fn elastic_accepts_the_alert_severity_vocabulary() {
    for severity in [
        json!("Informational"),
        json!("low"),
        json!("High"),
        json!({"default": "Critical"}),
    ] {
        valid(
            "elastic",
            &merged(&elastic_base(), &json!({"severity": severity})),
        );
    }
}

#[test]
fn elastic_empty_duration_reports_duration() {
    for overrides in [
        json!({"scheduling": {"interval": ""}}),
        json!({"scheduling": {"lookback": ""}}),
        json!({"suppression": {"group_by": ["host.name"], "duration": ""}}),
        json!({"type": "threshold", "threshold": {"field": ["host.name"], "value": 5},
               "suppression": {"duration": ""}}),
        json!({"type": "new_terms", "new_terms": {"fields": ["user.name"], "history_window_start": ""}}),
    ] {
        let block = merged(&elastic_base(), &overrides);
        assert!(errors("elastic", &block).contains("duration"), "{block}");
    }
}

#[test]
fn elastic_non_object_scheduling_is_a_shape_error() {
    for scheduling in [json!("5m"), json!(["5m"]), json!(5)] {
        let found = errors(
            "elastic",
            &merged(&elastic_base(), &json!({"scheduling": scheduling})),
        );
        assert!(found.contains("scheduling"), "{found}");
        assert!(!found.contains("duration"), "{found}");
    }
}

#[test]
fn elastic_non_ascii_digits_report_duration() {
    for overrides in [
        json!({"scheduling": {"interval": "\u{ff15}m"}}),
        json!({"scheduling": {"lookback": "\u{663}h"}}),
        json!({"suppression": {"group_by": ["host.name"], "duration": "PT\u{661}H"}}),
    ] {
        let block = merged(&elastic_base(), &overrides);
        assert!(errors("elastic", &block).contains("duration"), "{block}");
    }
}

#[test]
fn elastic_round_trips_through_its_serialised_form() {
    let block = merged(
        &elastic_base(),
        &json!({"scheduling": {"interval": "5m"}, "severity": {"default": "High"},
                "risk": 30, "integration": ["windows", {"package": "endpoint"}],
                "suppression": {"group_by": ["host.name"]}}),
    );
    let PlatformConfig::Elastic(config) = valid("elastic", &block) else {
        unreachable!()
    };
    let again = serde_json::to_value(&config).unwrap();
    let PlatformConfig::Elastic(reread) = valid("elastic", &again) else {
        unreachable!()
    };
    assert_eq!(reread, config);
    assert!(config.validate_with(&Pins::default()).is_ok());
}

// ---------------------------------------------------------------------------
// sysdig_rule_shape (`test_sysdig_model.py`).
// ---------------------------------------------------------------------------

fn rule() -> Json {
    json!({"status": "STAGING", "condition": "spawned_process and container"})
}

fn tuning() -> Json {
    json!({"status": "STAGING", "append_to_rule": "Terminal shell in container"})
}

#[test]
fn sysdig_specification_invalid_fixture_reports_both_codes() {
    let block = merged(
        &tuning(),
        &json!({"condition": "and not proc.pname = sshd", "output": "Shell spawned",
                "priority": "ERROR",
                "exceptions": [{"name": "misaligned", "fields": ["proc.name", "proc.pname"], "comps": ["="]}]}),
    );
    let found = errors("sysdig", &block);
    assert!(found.contains("sysdig_tuning_keys"), "{found}");
    assert!(found.contains("sysdig_exception_shape"), "{found}");
}

#[test]
fn sysdig_omitted_status_is_the_missing_field_not_a_code() {
    assert_eq!(
        errors("sysdig", &json!({"condition": "x"})),
        "status: Field required"
    );
}

#[test]
fn sysdig_each_constraint_reports_its_code() {
    let (r, t) = (rule(), tuning());
    for (code, block) in [
        ("sysdig_rule_shape", json!({"status": "STAGING"})),
        (
            "sysdig_rule_shape",
            json!({"status": "STAGING", "condition": "   "}),
        ),
        ("sysdig_rule_shape", t.clone()),
        ("sysdig_rule_shape", merged(&t, &json!({"exceptions": []}))),
        (
            "sysdig_rule_shape",
            merged(&t, &json!({"append_to_rule": " ", "condition": "and x"})),
        ),
        (
            "sysdig_tuning_keys",
            merged(&t, &json!({"condition": "and x", "source": "syscall"})),
        ),
        (
            "sysdig_tuning_keys",
            merged(&t, &json!({"condition": "and x", "policies": ["p"]})),
        ),
        (
            "sysdig_tuning_keys",
            merged(&t, &json!({"condition": "and x", "name": "Renamed"})),
        ),
        (
            "sysdig_priority",
            merged(&r, &json!({"priority": "SEVERE"})),
        ),
        ("sysdig_source", merged(&r, &json!({"source": "K8s-Audit"}))),
        (
            "sysdig_exception_shape",
            merged(&r, &json!({"exceptions": [{"name": "", "fields": "a"}]})),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": "a", "comps": "="}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": "a", "values": [["x"]]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a", "b"], "values": [["x"]]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a"], "comps": ["like"]}]}),
            ),
        ),
        (
            "sysdig_definition_name",
            merged(&r, &json!({"lists": [{"name": "my-list", "items": ["a"]}]})),
        ),
        (
            "sysdig_definition_name",
            merged(&r, &json!({"macros": [{"name": "and", "condition": "x"}]})),
        ),
        (
            "sysdig_definition_duplicate",
            merged(
                &r,
                &json!({"macros": [{"name": "dup", "condition": "x"}],
            "lists": [{"name": "dup", "items": ["a"]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": "a", "comps": ["in"]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": "a", "comps": "exists"}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a"], "comps": ["in oneof"]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a"], "comps": ["startswith  anyof"]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a"], "values": [[{"k": "v"}]]}]}),
            ),
        ),
        (
            "sysdig_exception_shape",
            merged(
                &r,
                &json!({"exceptions": [{"name": "e", "fields": ["a"], "values": [[["x", ["y"]]]]}]}),
            ),
        ),
        (
            "sysdig_definition_order",
            merged(
                &r,
                &json!({"condition": "loop_a", "macros": [
            {"name": "loop_a", "condition": "loop_b"}, {"name": "loop_b", "condition": "x.y = 1"}]}),
            ),
        ),
        (
            "sysdig_definition_order",
            merged(
                &r,
                &json!({"macros": [{"name": "self", "condition": "self and x.y = 1"}]}),
            ),
        ),
        (
            "sysdig_list_in_value",
            merged(
                &r,
                &json!({"lists": [{"name": "shells", "items": ["bash"]}],
            "exceptions": [{"name": "e", "fields": ["proc.name"], "values": [["shells"]]}]}),
            ),
        ),
        (
            "sysdig_list_in_value",
            merged(
                &r,
                &json!({"lists": [{"name": "shells", "items": ["bash"]}],
            "exceptions": [{"name": "e", "fields": "proc.cmdline", "values": ["run shells"]}]}),
            ),
        ),
    ] {
        let codes = sysdig::block_codes(&json_node(&block));
        assert!(codes.contains(code), "{code}: {block} gave {codes:?}");
        assert!(errors("sysdig", &block).contains(code), "{code}");
    }
}

#[test]
fn sysdig_valid_blocks_pass() {
    let (r, t) = (rule(), tuning());
    for block in [
        merged(&r, &json!({"priority": "info"})),
        merged(&r, &json!({"priority": "Informational"})),
        merged(&r, &json!({"source": "k8s_audit"})),
        merged(
            &t,
            &json!({"exceptions": [{"name": "e", "fields": "proc.name", "values": ["a", "b"]}]}),
        ),
        merged(&t, &json!({"condition": "and not proc.pname = x"})),
        merged(
            &r,
            &json!({"exceptions": [{"name": "e", "fields": ["proc.name", "fd.name"],
            "comps": ["=", "pmatch"], "values": [["bash", ["/etc", "/tmp"]]]}]}),
        ),
        merged(
            &r,
            &json!({"exceptions": [{"name": "values_later", "fields": ["proc.name"]}]}),
        ),
    ] {
        let PlatformConfig::Sysdig(config) = valid("sysdig", &block) else {
            unreachable!()
        };
        assert!(config.validate_with(&Pins::default()).is_ok(), "{block}");
    }
    let PlatformConfig::Sysdig(tuned) =
        valid("sysdig", &merged(&t, &json!({"condition": "and x"})))
    else {
        unreachable!()
    };
    assert!(tuned.is_tuning());
}

#[test]
fn sysdig_unknown_and_external_id_keys_are_rejected() {
    let found = errors(
        "sysdig",
        &merged(&rule(), &json!({"override": {"condition": "append"}})),
    );
    assert_eq!(found, "override: Extra inputs are not permitted");
    let found = errors(
        "sysdig",
        &merged(&rule(), &json!({"rule_id_bundle": {"tenant": 1}})),
    );
    assert_eq!(found, "rule_id_bundle: Extra inputs are not permitted");
    for key in ["required_engine_version", "required_plugin_versions"] {
        assert!(errors("sysdig", &merged(&rule(), &json!({key: "0.39.0"}))).contains(key));
    }
}

#[test]
fn sysdig_exception_forms_falco_accepts_validate() {
    for exceptions in [
        json!([{"name": "e", "fields": "a"}, {"name": "e", "fields": "b"}]),
        json!([{"name": "e", "fields": ["a", "a"], "values": [["x", "y"]]}]),
        json!([{"name": "e", "fields": ["a", "b"], "comps": ["=", "in"], "values": [["x", "y"]]}]),
        json!([{"name": "e", "fields": ["a", "b", "c"], "comps": ["exists", " startswith oneof ", "== allof"],
                "values": [["x", ["p", "q"], "z"]]}]),
        json!([{"name": "e", "fields": "a", "comps": "contains anyof", "values": ["x", "y"]}]),
        json!([{"name": "e", "fields": "a", "comps": " pmatch ", "values": ["/tmp"]}]),
        json!([{"name": "e", "fields": ["a"], "comps": ["<"], "values": [[1]]}]),
    ] {
        valid(
            "sysdig",
            &merged(&rule(), &json!({"exceptions": exceptions})),
        );
    }
}

#[test]
fn sysdig_list_order_is_never_a_model_error() {
    for lists in [
        json!([{"name": "l1", "items": ["l2", "bash"]}, {"name": "l2", "items": ["zsh"]}]),
        json!([{"name": "l1", "items": ["bash", "l1"]}]),
    ] {
        valid(
            "sysdig",
            &merged(
                &rule(),
                &json!({"condition": "proc.name in (l1)", "lists": lists}),
            ),
        );
    }
}

#[test]
fn sysdig_a_block_list_in_an_exception_value_validates_where_falco_expands_it() {
    valid(
        "sysdig",
        &merged(
            &rule(),
            &json!({"lists": [{"name": "shells", "items": ["bash", "sh"]}],
            "exceptions": [
                {"name": "single", "fields": "proc.name", "values": ["shells", "zsh"]},
                {"name": "listop", "fields": ["proc.name"], "comps": ["in"], "values": [["shells"]]},
                {"name": "member", "fields": ["proc.name"], "comps": ["in"], "values": [[["shells"]]]},
            ]}),
        ),
    );
}

#[test]
fn sysdig_minimum_engine_version() {
    for version in [0, 17, 35] {
        let PlatformConfig::Sysdig(config) = valid(
            "sysdig",
            &merged(&rule(), &json!({"minimum_engine_version": version})),
        ) else {
            unreachable!()
        };
        assert_eq!(config.minimum_engine_version, Some(version));
    }
    for version in [
        json!("17"),
        json!("0.39.0"),
        json!(0.37),
        json!(-1),
        json!(true),
    ] {
        let found = errors(
            "sysdig",
            &merged(&rule(), &json!({"minimum_engine_version": version})),
        );
        assert!(
            found.starts_with("minimum_engine_version: "),
            "{version}: {found}"
        );
    }
    assert_eq!(
        errors(
            "sysdig",
            &merged(&rule(), &json!({"minimum_engine_version": -1}))
        ),
        "minimum_engine_version: Input should be greater than or equal to 0"
    );
}

// ---------------------------------------------------------------------------
// garde: the same checks on a block built in memory.
// ---------------------------------------------------------------------------

#[test]
fn garde_runs_the_named_checks_and_the_field_checks() {
    let PlatformConfig::Sysdig(mut sysdig) = valid("sysdig", &rule()) else {
        unreachable!()
    };
    assert!(sysdig.validate_with(&Pins::default()).is_ok());
    sysdig.priority = Some("LOUD".to_owned());
    sysdig.minimum_engine_version = Some(-1);
    let report = sysdig
        .validate_with(&Pins::default())
        .unwrap_err()
        .to_string();
    assert!(
        report.contains("SysdigConfig validation failed with code(s): sysdig_priority"),
        "{report}"
    );
    assert!(report.contains("greater than or equal to 0"), "{report}");

    let PlatformConfig::Elastic(mut elastic) = valid("elastic", &elastic_base()) else {
        unreachable!()
    };
    elastic.risk = Some(elastic::RiskChoice::Score(101));
    elastic.query = Some(" ".to_owned());
    elastic.platform_schema = Some("platform::splunk::1.0".to_owned());
    let report = elastic
        .validate_with(&Pins::default())
        .unwrap_err()
        .to_string();
    assert!(report.contains("risk_score"), "{report}");
    assert!(report.contains("query must not be empty"), "{report}");
    assert!(report.contains("unknown platform schema"), "{report}");

    let PlatformConfig::Sentinel(mut sentinel) = valid(
        "sentinel",
        &json!({"status": "S", "query": "q", "scheduling": {}, "alert": {}}),
    ) else {
        unreachable!()
    };
    sentinel.alert.techniques = Some(vec![sentinel::SentinelTechnique("T9999".to_owned())]);
    sentinel.scheduling.frequency = Some("hourly".to_owned());
    let report = sentinel
        .validate_with(&Pins::default())
        .unwrap_err()
        .to_string();
    assert!(
        report.contains("is not an ATT&CK v18 technique"),
        "{report}"
    );
    assert!(report.contains("Duration \"hourly\""), "{report}");
}

// ---------------------------------------------------------------------------
// Sentinel (`test_sentinel_attack.py`, the known gap on durations).
// ---------------------------------------------------------------------------

fn sentinel_with(alert: &Json, scheduling: &Json) -> Json {
    json!({"status": "S", "query": "q", "scheduling": scheduling, "alert": alert})
}

#[test]
fn sentinel_techniques_are_attack_v18_ids() {
    valid(
        "sentinel",
        &sentinel_with(
            &json!({"techniques": ["T1059", "T1059.001", "T0800"]}),
            &json!({}),
        ),
    );
    let found = errors(
        "sentinel",
        &sentinel_with(&json!({"techniques": ["T9999"]}), &json!({})),
    );
    assert_eq!(
        found,
        "alert.techniques.0: \"T9999\" is not an ATT&CK v18 technique or sub-technique id, which \
         is what Sentinel is aligned to"
    );
    let found = errors(
        "sentinel",
        &sentinel_with(&json!({"techniques": ["t1086"]}), &json!({})),
    );
    assert!(found.contains("ATT&CK retired T1086"), "{found}");
}

#[test]
fn sentinel_frequency_must_be_a_duration_deploy_converts() {
    for frequency in ["PT1H", "1h", "1h10m", "P1D", ""] {
        valid(
            "sentinel",
            &sentinel_with(
                &json!({}),
                &json!({"frequency": frequency, "lookback": "PT2H"}),
            ),
        );
    }
    let found = errors(
        "sentinel",
        &sentinel_with(&json!({}), &json!({"frequency": "hourly"})),
    );
    assert_eq!(
        found,
        "scheduling.frequency: Value error, Duration \"hourly\" is not an ISO 8601 duration \
         (PT1H, PT30M, P1D) or a shorthand duration (30m, 1h, 1d, 1h10m)"
    );
    assert!(
        errors(
            "sentinel",
            &sentinel_with(&json!({"suppression": "soon"}), &json!({}))
        )
        .starts_with("alert.suppression: Value error, Duration \"soon\"")
    );
    valid(
        "sentinel",
        &sentinel_with(&json!({"suppression": false}), &json!({})),
    );
    valid(
        "sentinel",
        &sentinel_with(&json!({"suppression": "PT5H"}), &json!({})),
    );
}

// ---------------------------------------------------------------------------
// Bounds: a crafted block cannot make a named check run away.
// ---------------------------------------------------------------------------

#[test]
fn lists_that_double_at_each_step_stay_bounded() {
    // l0 = [a, a], l1 = [l0, l0], ... l59 = [l58, l58]: 2^60 items unbounded.
    let mut lists = vec![json!({"name": "l0", "items": ["a", "a"]})];
    for index in 1..60 {
        let earlier = format!("l{}", index - 1);
        lists.push(json!({"name": format!("l{index}"), "items": [earlier, earlier]}));
    }
    let block = merged(
        &rule(),
        &json!({"lists": lists, "macros": [{"name": "m", "condition": "proc.name in (l59)"}],
                "exceptions": [{"name": "e", "fields": ["proc.name"], "comps": ["in"], "values": [["l59"]]}]}),
    );
    let started = std::time::Instant::now();
    assert!(sysdig::block_codes(&json_node(&block)).is_empty());
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn a_block_larger_than_the_budget_is_left_to_the_conversion() {
    let document = crate::node::load(
        "a: &a [x, x, x, x, x, x, x, x, x, x]\n\
         b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n\
         c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n\
         d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n\
         e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n\
         block:\n  status: S\n  priority: LOUD\n  tags: *e\n",
    )
    .unwrap();
    let block = document.root().unwrap().get("block").unwrap();
    assert!(!within_budget(block));
    assert!(sysdig::block_codes(block).is_empty());
    // The conversion reports the block's own errors, within its budget.
    let Err(ParseError::Invalid(errors)) = parse_platform_config("sysdig", block) else {
        panic!("the block converted");
    };
    assert!(!errors.is_empty());
}

/// An optional `Literal` is Pydantic's `anyOf [literal, null]`: its `enum`
/// holds the literal's values only, never a `null` (the schema diff
/// against the oracle, `cargo xtask schema diff`).
#[test]
fn an_optional_literal_keeps_null_out_of_its_enum() {
    let schema = serde_json::to_value(schemars::schema_for!(ElasticConfig)).unwrap();
    let language = &schema["properties"]["language"];
    assert_eq!(
        language["anyOf"],
        json!([{"type": "string", "enum": ["kuery", "lucene"]}, {"type": "null"}]),
        "{language}"
    );
    let threat = &schema["$defs"]["ElasticThreatMatch"]["properties"]["language"];
    assert_eq!(threat["anyOf"], language["anyOf"], "{threat}");
}

#[test]
fn sysdig_items_are_the_text_the_file_writes() {
    for (written, text) in sysdig::ITEM_TEXT_CASES {
        let document = crate::node::load(&format!("[{written}]")).unwrap();
        let root = document.root().unwrap();
        let Value::Seq(items) = &root.value else {
            panic!("{written}")
        };
        assert_eq!(sysdig::item_text(&items[0]), *text, "{written}");
    }
}

#[test]
fn sysdig_a_null_exception_value_is_refused() {
    for values in [
        json!(["sh", null]),
        json!([["sh", null]]),
        json!([["sh", ["a", null]]]),
    ] {
        let fields = if values[0].is_array() {
            json!(["proc.name", "proc.pname"])
        } else {
            json!("proc.name")
        };
        let found = errors(
            "sysdig",
            &merged(
                &rule(),
                &json!({"exceptions": [{"name": "e", "fields": fields, "values": values}]}),
            ),
        );
        assert!(
            found.contains(&format!(": {}", sysdig::NULL_VALUE)),
            "{values}: {found}"
        );
    }
    assert_eq!(
        errors(
            "sysdig",
            &merged(
                &rule(),
                &json!({"exceptions": [{"name": "e", "fields": "proc.name", "values": ["sh", null]}]})
            )
        ),
        format!("exceptions.0.values.1: {}", sysdig::NULL_VALUE)
    );
}
