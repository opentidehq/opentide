//! The Exabeam compiler (exabeam-1.0), ported from 0.28.0's
//! `tests/test_platforms/test_exabeam_compile.py`: the request bodies of
//! `tests/fixtures/exabeam/*.api.json`, as data and in the specification's
//! key order, and each derivation.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::exabeam::{
    self, compile_rule, create_request, derive_description, live_search_request, search_body,
    threshold_value, time_unit, update_request,
};
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const RULE_ID: &str = "016dbc1d-a727-43df-a143-9546dcc81a5a";
const UUID: &str = "11111111-2222-4333-8444-555555555555";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/exabeam")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap()
}

fn workspace(rule: &str) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", rule.to_owned());
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

/// Runs `f` on the compile context and the rule of the workspace holding
/// `text`, whose UUID is `uuid`.
fn with_rule<T>(
    text: &str,
    uuid: &str,
    f: impl FnOnce(&opentide_compile::Context<'_>, &Rule) -> T,
) -> T {
    let workspace = workspace(text);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", uuid).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    f(&cx, &rule)
}

fn uuid_of(text: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned()
}

/// A rule whose `exabeam` block has `block` (YAML, indented under the block)
/// besides the base keys, and `top` at the rule's root.
fn block_rule(block: &str, top: &str) -> String {
    format!(
        "name: Failed logins\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.0\n  version: 1\n  \
         created: \"2026-01-01\"\n  modified: \"2026-01-02\"\n  tlp: clear\n  author: Detection \
         Engineering\ndescription: Failed logins.\n{top}configurations:\n  exabeam:\n    enabled: \
         true\n    schema: platform::exabeam::1.0\n    status: STAGING\n{block}"
    )
}

const ONE_SEQUENCE: &str = "    sequences:\n    - query: activity_type:\"app-login\"\n";

fn tenant(test_mode: bool) -> Json {
    serde_json::from_value::<Json>(serde_json::json!({
        "name": "exabeam-eu",
        "setup": {"region": "eu", "test_mode": test_mode},
    }))
    .unwrap()
}

fn json(value: &Json) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn keys(value: &Json) -> Vec<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn body(text: &str, strategy: StatusStrategy, tenant: Option<&Json>) -> Json {
    with_rule(text, &uuid_of(text), |cx, rule| {
        compile_rule(cx, rule, strategy, tenant).unwrap().body
    })
}

#[test]
fn the_fixtures_as_data_and_in_order() {
    for (golden, source, method, strategy) in [
        (
            "rule-exabeam-threshold-1.0.create.api.json",
            "rule-exabeam-threshold-1.0.yaml",
            "POST",
            StatusStrategy::Release,
        ),
        (
            "rule-exabeam-threshold-1.0.update.api.json",
            "rule-exabeam-threshold-1.0.yaml",
            "PUT",
            StatusStrategy::Release,
        ),
        (
            "rule-exabeam-threshold-1.0.disable.api.json",
            "rule-exabeam-threshold-1.0.yaml",
            "PUT",
            StatusStrategy::Disablement,
        ),
        (
            "rule-exabeam-sequence-1.0.create.api.json",
            "rule-exabeam-sequence-1.0.yaml",
            "POST",
            StatusStrategy::Release,
        ),
    ] {
        let text = fixture(source);
        let request = with_rule(&text, &uuid_of(&text), |cx, rule| {
            let compiled = compile_rule(cx, rule, strategy, Some(&tenant(false))).unwrap();
            if method == "POST" {
                create_request(&compiled)
            } else {
                update_request(&compiled, RULE_ID)
            }
        });
        let expected: serde_json::Value = serde_json::from_str(&fixture(golden)).unwrap();
        assert_eq!(json(&request), expected, "{golden}");
        // The order of the specification's Compiled body table.
        let body = request.get("body").unwrap();
        let expected_order: Vec<String> = fixture(golden)
            .lines()
            .filter_map(|line| line.strip_prefix("    \"")) // the body's own keys
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_owned)
            .collect();
        assert_eq!(keys(body), expected_order, "{golden}");
    }
}

#[test]
fn the_live_fixture() {
    let text = fixture("rule-exabeam-threshold-1.0.yaml");
    let query = with_rule(&text, &uuid_of(&text), |_, rule| {
        rule.block("exabeam")
            .unwrap()
            .get("sequences")
            .unwrap()
            .clone()
    });
    let Json::Array(sequences) = query else {
        panic!()
    };
    let query = sequences[0].get("query").and_then(Json::as_str).unwrap();
    let now: jiff::Timestamp = "2026-11-11T12:00:00Z".parse().unwrap();
    let request = live_search_request(query, now);
    let expected: serde_json::Value =
        serde_json::from_str(&fixture("rule-exabeam-threshold-1.0.validate.api.json")).unwrap();
    assert_eq!(json(&request), expected);
}

#[test]
fn the_smallest_block() {
    let body = body(
        &fixture("block-exabeam.yaml"),
        StatusStrategy::Release,
        None,
    );
    assert_eq!(
        keys(&body),
        [
            "name",
            "description",
            "severity",
            "enabled",
            "testMode",
            "sequencesConfig",
            "suppressConfig",
            "delayConfig",
        ]
    );
    assert_eq!(
        json(body.get("sequencesConfig").unwrap()),
        serde_json::json!({
            "sequences": [{
                "query": "activity_type:\"process-create\" AND process_name:\"mshta.exe\"",
                "condition": {"triggerOnAnyMatch": true, "groupByOption": false, "groupBy": []},
            }],
            "outcomes": {
                "sendAlertTriage": true,
                "createCase": false,
                "sendEmail": false,
                "alertTriage": {"name": "Exabeam correlation rule block"},
            },
        })
    );
    let description = body.get("description").and_then(Json::as_str).unwrap();
    assert!(description.ends_with("\n\nopentide: 00000000-0000-4000-8003-000000000070"));
    assert!(!description.contains("ATT&CK"));
    assert_eq!(body.get("severity").and_then(Json::as_str), Some("medium"));
}

#[test]
fn severity() {
    for (block, top, severity) in [
        (
            "    severity: none\n",
            "response:\n  alert_severity: Critical\n",
            "none",
        ),
        ("", "response:\n  alert_severity: Informational\n", "none"),
        ("", "response:\n  alert_severity: Low\n", "low"),
        ("", "response:\n  alert_severity: Unheard\n", "medium"),
        ("", "", "medium"),
    ] {
        let body = body(
            &block_rule(&format!("{ONE_SEQUENCE}{block}"), top),
            StatusStrategy::Release,
            None,
        );
        assert_eq!(
            body.get("severity").and_then(Json::as_str),
            Some(severity),
            "{block}{top}"
        );
    }
}

#[test]
fn test_mode_block_then_tenant_then_false() {
    let rule = block_rule(ONE_SEQUENCE, "");
    let test_mode = |text: &str, tenant: Option<&Json>| {
        body(text, StatusStrategy::Release, tenant)
            .get("testMode")
            .cloned()
            .unwrap()
    };
    assert_eq!(test_mode(&rule, None), Json::Bool(false));
    assert_eq!(test_mode(&rule, Some(&tenant(true))), Json::Bool(true));
    let forced = block_rule(&format!("{ONE_SEQUENCE}    test_mode: false\n"), "");
    assert_eq!(test_mode(&forced, Some(&tenant(true))), Json::Bool(false));
}

#[test]
fn name_and_outcomes() {
    let rule = block_rule(
        &format!(
            "{ONE_SEQUENCE}    name: Exabeam name\n    outcome: none\n    email:\n      \
             recipients: [soc@example.com]\n      subject: Look\n"
        ),
        "",
    );
    let named = body(&rule, StatusStrategy::Release, None);
    assert_eq!(
        named.get("name").and_then(Json::as_str),
        Some("Exabeam name")
    );
    assert_eq!(
        json(
            named
                .get("sequencesConfig")
                .and_then(|config| config.get("outcomes"))
                .unwrap()
        ),
        serde_json::json!({
            "sendAlertTriage": false,
            "createCase": false,
            "sendEmail": true,
            "email": {"recipients": ["soc@example.com"], "subject": "Look", "attachCsv": false},
        })
    );
    let rule = block_rule(&format!("{ONE_SEQUENCE}    outcome: case\n"), "");
    let case = body(&rule, StatusStrategy::Release, None);
    assert_eq!(
        json(
            case.get("sequencesConfig")
                .and_then(|config| config.get("outcomes"))
                .unwrap()
        ),
        serde_json::json!({
            "sendAlertTriage": false,
            "createCase": true,
            "sendEmail": false,
            "case": {"description": "Failed logins"},
        })
    );
}

#[test]
fn description_collapses_whitespace() {
    let text = block_rule(ONE_SEQUENCE, "techniques:\n- T1110.003\n").replace(
        "description: Failed logins.",
        "description: \"Two\\n  lines\\tof text.\\n\"",
    );
    let description = with_rule(&text, UUID, derive_description);
    assert_eq!(
        description,
        format!("Two lines of text.\n\nATT&CK: T1110.003\nopentide: {UUID}")
    );
}

#[test]
fn threshold_value_suppression_delay_and_schedule() {
    let rule = block_rule(
        "    sequences:\n    - query: activity_type:\"network-session\"\n      threshold:\n        \
         function: value\n        field: dest_ip\n        operator: not_in\n        value: \
         [0.0.0.0, 1.1.1.1]\n        within: 1d\n    suppression:\n      for: 2w\n    delay: \
         2h\n    schedule:\n    - every: day\n      from: \"00:00Z\"\n      to: \"23:59Z\"\n    \
         - every: week\n      days: [monday, friday]\n      from: \"08:00Z\"\n      to: \
         \"18:00Z\"\n    - every: month\n      days: [1, 15]\n      from: \"00:00Z\"\n      to: \
         \"06:00Z\"\n    - every: days\n      first: monday\n      last: friday\n      from: \
         \"06:00Z\"\n      to: \"20:00Z\"\n",
        "",
    );
    let body = json(&body(&rule, StatusStrategy::Release, None));
    let condition = &body["sequencesConfig"]["sequences"][0]["condition"];
    assert_eq!(condition["value"], "0.0.0.0,1.1.1.1");
    assert_eq!(condition["subject"], "field");
    assert_eq!(condition["field"], "dest_ip");
    assert_eq!(condition["time"], 1);
    assert_eq!(condition["unit"], "days");
    assert_eq!(
        body["suppressConfig"],
        serde_json::json!({"suppressOption": true, "suppressTime": 2, "suppressUnit": "weeks"})
    );
    assert_eq!(
        body["delayConfig"],
        serde_json::json!({"delay": true, "delayTimeInMinutes": 120})
    );
    assert_eq!(
        body["scheduleConfig"]["recurrences"],
        serde_json::json!([
            {"recurrenceType": "DAILY", "startTime": "00:00Z", "endTime": "23:59Z"},
            {
                "recurrenceType": "WEEKLY", "startTime": "08:00Z", "endTime": "18:00Z",
                "daysOfWeek": ["MONDAY", "FRIDAY"],
            },
            {
                "recurrenceType": "MONTHLY", "startTime": "00:00Z", "endTime": "06:00Z",
                "daysInMonth": [1, 15], "lastDayOfMonth": false,
            },
            {
                "recurrenceType": "CUSTOM", "startTime": "06:00Z", "endTime": "20:00Z",
                "dayFrom": "MONDAY", "dayTo": "FRIDAY",
            },
        ])
    );
}

#[test]
fn threshold_values() {
    let parse = |text: &str| serde_json::from_str::<Json>(text).unwrap();
    for (value, text) in [
        ("3", "3"),
        ("2.5", "2.5"),
        ("2.0", "2"),
        ("[0.5, 2.0]", "0.5,2"),
        ("null", ""),
        ("[\"a\", 1]", "a,1"),
    ] {
        assert_eq!(threshold_value(Some(&parse(value))), text, "{value}");
    }
    assert_eq!(threshold_value(None), "");
}

#[test]
fn time_unit_refuses_a_non_duration() {
    assert_eq!(
        time_unit(&Json::Str("90m".into()), "mhd").unwrap(),
        (Json::Int(90), "minutes")
    );
    let error = time_unit(&Json::Str("1h30m".into()), "mhd").unwrap_err();
    assert!(error.reason.contains("not a duration"), "{}", error.reason);
    assert!(time_unit(&Json::Str("99999999999999999999m".into()), "m").is_err());
}

#[test]
fn search_body_writes_utc() {
    let start: jiff::Timestamp = "2026-01-01T13:00:00+01:00".parse().unwrap();
    let end: jiff::Timestamp = "2026-01-01T12:30:00Z".parse().unwrap();
    let body = search_body(" q ", start, end, 5, &["host".to_owned()]);
    assert_eq!(
        json(&body),
        serde_json::json!({
            "filter": "q",
            "fields": ["host"],
            "startTime": "2026-01-01T12:00:00Z",
            "endTime": "2026-01-01T12:30:00Z",
            "limit": 5,
        })
    );
}

#[test]
fn a_rule_without_a_block_is_refused() {
    let text = block_rule(ONE_SEQUENCE, "");
    let text = text.replace("  exabeam:", "  exabeam_other:");
    let error = with_rule(&text, UUID, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, None).unwrap_err()
    });
    assert!(
        error.reason.contains("has no exabeam block"),
        "{}",
        error.reason
    );
    assert!(
        error
            .reason
            .starts_with("Exabeam New-Scale SIEM cannot compile this rule")
    );
}

#[test]
fn two_sequences_need_a_correlation_to_compile() {
    let text = block_rule("    sequences:\n    - query: a\n    - query: b\n", "");
    let error = with_rule(&text, UUID, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, None).unwrap_err()
    });
    assert!(
        error.reason.contains("need correlation"),
        "{}",
        error.reason
    );
}

#[test]
fn the_deployment_follows_the_status() {
    let text = block_rule(ONE_SEQUENCE, "");
    let compiled = with_rule(&text, UUID, |cx, rule| {
        exabeam::compile_deployment(cx, rule, Some(&tenant(true))).unwrap()
    });
    assert_eq!(compiled.name, "Failed logins");
    assert_eq!(compiled.uuid, UUID);
    assert!(!compiled.has_schedule());
    assert_eq!(compiled.body.get("enabled"), Some(&Json::Bool(true)));
    assert_eq!(compiled.body.get("testMode"), Some(&Json::Bool(true)));
    let unknown = text.replace("status: STAGING", "status: NOPE");
    let error = with_rule(&unknown, UUID, |cx, rule| {
        exabeam::compile_deployment(cx, rule, None).unwrap_err()
    });
    assert_eq!(error.code, "compile_failed");
}

/// A status that is not a string is named in its JSON form, `true` or
/// `null` when missing, never Python's `True` or `None` (#1068).
#[test]
fn a_status_is_named_in_its_json_form() {
    for (status, named) in [("    status: true\n", "true"), ("", "null")] {
        let text = block_rule(ONE_SEQUENCE, "").replace("    status: STAGING\n", status);
        let error = with_rule(&text, UUID, |cx, rule| {
            exabeam::compile_deployment(cx, rule, None).unwrap_err()
        });
        assert_eq!(error.code, "compile_failed");
        assert!(error.reason.contains(named), "{}", error.reason);
        assert!(
            !error.reason.contains("True") && !error.reason.contains("None"),
            "{}",
            error.reason
        );
    }
}
