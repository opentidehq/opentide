//! The Datadog compiler (RFC `docs/internal/rfc-datadog-cloud-siem.md` §7):
//! the request body of `tests/fixtures/datadog/*.api.json`, as data and in
//! the RFC's key order, and each derivation: the methods' options, the
//! derived message and tags, the preview strategy and the aliases.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::datadog::{
    self, compile_rule, create_request, live_search_request, search_body, update_request,
    validation_request,
};
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/datadog")
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

fn uuid_of(text: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned()
}

fn with_rule<T>(text: &str, f: impl FnOnce(&opentide_compile::Context<'_>, &Rule) -> T) -> T {
    let workspace = workspace(text);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", &uuid_of(text)).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    f(&cx, &rule)
}

fn tenant() -> Json {
    serde_json::from_value::<Json>(serde_json::json!({
        "name": "datadog-eu",
        "setup": {
            "site": "datadoghq.eu",
            "tags": ["managed-by:opentide"],
            "notifications": {"soc": "@slack-soc-alerts"},
        },
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
    with_rule(text, |cx, rule| {
        compile_rule(cx, rule, strategy, tenant).unwrap().body
    })
}

/// A rule whose `datadog` block is `block` (YAML, indented under the block).
fn block_rule(block: &str, top: &str) -> String {
    format!(
        "name: Failed logins\nmetadata:\n  uuid: 11111111-2222-4333-8444-555555555555\n  \
         schema: rule::1.0\n  version: 1\n  created: \"2026-01-01\"\n  modified: \
         \"2026-01-02\"\n  tlp: clear\n  author: Detection Engineering\ndescription: Failed \
         logins.\n{top}configurations:\n  datadog:\n    schema: platform::datadog::1.0\n    \
         status: PRODUCTION\n{block}"
    )
}

/// The RFC's §7.2: the complete block's first deploy, on a tenant whose `soc`
/// alias is `@slack-soc-alerts`, byte for byte in the RFC's key order (the
/// fixture's tenant has no tags).
#[test]
fn the_complete_block_compiles_to_the_rfc_s_request() {
    let text = fixture("rule-datadog-threshold-1.0.yaml");
    let golden: Json =
        serde_json::from_str(&fixture("rule-datadog-threshold-1.0.create.api.json")).unwrap();
    let tenant: Json = serde_json::from_value(serde_json::json!({
        "name": "datadog-eu",
        "setup": {"site": "datadoghq.eu", "notifications": {"soc": "@slack-soc-alerts"}},
    }))
    .unwrap();
    let request = with_rule(&text, |cx, rule| {
        let compiled = datadog::compile_deployment(cx, rule, Some(&tenant)).unwrap();
        create_request(&compiled)
    });
    assert_eq!(json(&request), json(&golden));
    // The key order is the RFC's, at every level.
    let body = request.get("body").unwrap();
    assert_eq!(keys(body), keys(golden.get("body").unwrap()));
    let golden_body = golden.get("body").unwrap();
    assert_eq!(
        keys(body.get("options").unwrap()),
        keys(golden_body.get("options").unwrap())
    );
    for list in ["queries", "cases"] {
        let ours = body.get(list).unwrap().as_array().unwrap();
        let theirs = golden_body.get(list).unwrap().as_array().unwrap();
        assert_eq!(ours.len(), theirs.len());
        for (ours, theirs) in ours.iter().zip(theirs) {
            assert_eq!(keys(ours), keys(theirs), "{list}");
        }
    }
}

/// Under `PREVIEW` the same body has no notifications and the preview tag
/// (RFC §7.2, §8.3); the tenant's tags follow the derived ones.
#[test]
fn a_preview_deploy_notifies_nobody_and_says_so_in_a_tag() {
    let text = fixture("rule-datadog-threshold-1.0.yaml");
    let preview = body(&text, StatusStrategy::Preview, Some(&tenant()));
    assert_eq!(
        json(preview.get("cases").unwrap())[0]["notifications"],
        serde_json::json!([])
    );
    let tags = json(preview.get("tags").unwrap());
    let tags: Vec<&str> = tags
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(tags.last(), Some(&"opentide_strategy:preview"));
    assert!(tags.contains(&"managed-by:opentide"));
    let release = body(&text, StatusStrategy::Release, Some(&tenant()));
    assert!(
        !json(release.get("tags").unwrap())
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "opentide_strategy:preview")
    );
    let disabled = body(&text, StatusStrategy::Disablement, Some(&tenant()));
    assert_eq!(disabled.get("isEnabled"), Some(&Json::Bool(false)));
}

#[test]
fn an_alias_the_tenant_lacks_fails_and_a_dry_run_shows_a_placeholder() {
    let text = fixture("rule-datadog-threshold-1.0.yaml");
    let other: Json = serde_json::from_value(serde_json::json!({
        "name": "datadog-us", "setup": {"site": "datadoghq.com"},
    }))
    .unwrap();
    let error = with_rule(&text, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, Some(&other)).unwrap_err()
    });
    assert_eq!(error.code, "datadog_notification_alias");
    assert!(error.reason.contains("\"soc\""), "{}", error.reason);
    let dry = body(&text, StatusStrategy::Release, None);
    assert_eq!(
        json(dry.get("cases").unwrap())[0]["notifications"],
        serde_json::json!(["<tenant:notifications.soc>"])
    );
    // A raw handle is sent as written.
    let raw = block_rule(
        "    queries:\n      - query: source:x\n    cases:\n      - condition: a > 1\n        \
         notify: ['@pagerduty-sec']\n",
        "",
    );
    let compiled = body(&raw, StatusStrategy::Release, Some(&other));
    assert_eq!(
        json(compiled.get("cases").unwrap())[0]["notifications"],
        serde_json::json!(["@pagerduty-sec"])
    );
}

#[test]
fn a_block_tag_a_modifier_could_have_written_is_checked_as_sent() {
    let text = block_rule(
        "    queries:\n      - query: source:x\n    cases:\n      - condition: a > 1\n    tags: \
         [\"Upper:Case\"]\n",
        "",
    );
    let error = with_rule(&text, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, None).unwrap_err()
    });
    assert_eq!(error.code, "datadog_tag");
}

#[test]
fn a_tenant_tag_datadog_would_rewrite_fails() {
    let text = fixture("rule-datadog-minimal-1.0.yaml");
    let tenant: Json = serde_json::from_value(serde_json::json!({
        "name": "t", "setup": {"tags": ["Managed-By:opentide"]},
    }))
    .unwrap();
    let error = with_rule(&text, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, Some(&tenant)).unwrap_err()
    });
    assert_eq!(error.code, "datadog_tag");
}

/// The minimal block (RFC §5.1): the defaults fill the rest.
#[test]
fn the_minimal_block_takes_the_defaults() {
    let compiled = body(
        &fixture("rule-datadog-minimal-1.0.yaml"),
        StatusStrategy::Release,
        None,
    );
    let value = json(&compiled);
    assert_eq!(value["name"], "Console login failures");
    assert_eq!(
        value["queries"],
        serde_json::json!([{
            "name": "a",
            "query": "source:cloudtrail @evt.name:ConsoleLogin @evt.outcome:Failure",
            "dataSource": "logs", "aggregation": "count", "groupByFields": [], "distinctFields": [],
        }])
    );
    assert_eq!(
        value["cases"],
        serde_json::json!([{"name": "", "status": "info", "condition": "a > 5", "notifications": []}])
    );
    assert_eq!(
        value["options"],
        serde_json::json!({
            "detectionMethod": "threshold", "evaluationWindow": 300, "keepAlive": 3600,
            "maxSignalDuration": 86400, "decreaseCriticalityBasedOnEnv": false,
        })
    );
    assert!(value.get("groupSignalsBy").is_none());
    assert_eq!(value["hasExtendedTitle"], false);
    // The derived message (RFC §7.3).
    let message = value["message"].as_str().unwrap();
    assert!(
        message.starts_with("## Goal\nMore than five failed AWS console logins"),
        "{message}"
    );
    assert!(
        message.contains("## Strategy\n- Query `a` searches logs"),
        "{message}"
    );
    assert!(!message.contains("## Triage and response"), "{message}");
    assert_eq!(
        value["tags"],
        serde_json::json!([
            "source:cloudtrail",
            "security:attack",
            "opentide_uuid:00000000-0000-4000-8004-000000000001"
        ])
    );
}

#[test]
fn each_method_s_options_are_in_the_unit_their_property_takes() {
    let new_value = json(&body(
        &fixture("rule-datadog-new-value-1.0.yaml"),
        StatusStrategy::Release,
        None,
    ));
    assert_eq!(
        new_value["queries"][0],
        serde_json::json!({
            "query": "source:okta @evt.name:user.session.start @evt.outcome:SUCCESS",
            "dataSource": "logs", "aggregation": "new_value", "groupByFields": ["@usr.email"],
            "distinctFields": [], "metrics": ["@network.client.geoip.country.name"],
        }),
        "a new_value query has no name"
    );
    assert_eq!(new_value["options"]["detectionMethod"], "new_value");
    assert_eq!(
        new_value["options"]["newValueOptions"],
        serde_json::json!({"forgetAfter": 30, "learningMethod": "duration", "learningDuration": 7})
    );
    assert_eq!(new_value["cases"][0]["status"], "medium");
    assert!(new_value["cases"][0].get("condition").is_none());

    let travel = json(&body(
        &fixture("rule-datadog-impossible-travel-1.0.yaml"),
        StatusStrategy::Release,
        None,
    ));
    assert_eq!(travel["queries"][0]["aggregation"], "geo_data");
    assert_eq!(
        travel["queries"][0]["metrics"],
        serde_json::json!(["@network.client.geoip"])
    );
    assert_eq!(
        travel["options"]["impossibleTravelOptions"],
        serde_json::json!({"baselineUserLocations": true, "baselineUserLocationsDuration": 7}),
        "detectIpTransition is sent only when true"
    );

    let anomaly = json(&body(
        &fixture("rule-datadog-anomaly-1.0.yaml"),
        StatusStrategy::Release,
        None,
    ));
    assert_eq!(anomaly["options"]["detectionMethod"], "anomaly_detection");
    assert_eq!(anomaly["options"]["evaluationWindow"], 900);
    assert_eq!(
        anomaly["options"]["anomalyDetectionOptions"],
        serde_json::json!({"bucketDuration": 900, "learningDuration": 168}),
        "the unverified tolerance default is not sent"
    );

    let distinct = json(&body(
        &fixture("rule-datadog-distinct-1.0.yaml"),
        StatusStrategy::Release,
        None,
    ));
    assert_eq!(distinct["queries"][0]["aggregation"], "cardinality");
    assert_eq!(
        distinct["queries"][0]["distinctFields"],
        serde_json::json!(["@usr.email"])
    );
    assert!(distinct["queries"][0].get("metrics").is_none());
}

#[test]
fn the_other_measures_and_switches() {
    let text = block_rule(
        "    queries:\n      - query: source:x\n        from: signals\n        sum: \
         '@bytes'\n        keep_missing_groups: true\n      - query: source:y\n        max: \
         '@duration'\n    detection:\n      method: impossible_travel\n      \
         detect_ip_transitions: true\n    cases:\n      - severity: low\n",
        "",
    );
    // impossible_travel's aggregation wins over the measures the model
    // refuses; the compiler is held here on the switches only.
    let value = json(&body(&text, StatusStrategy::Release, None));
    assert_eq!(value["queries"][0]["dataSource"], "security_signals");
    assert_eq!(value["queries"][0]["hasOptionalGroupByFields"], true);
    assert!(
        value["queries"][1]
            .get("hasOptionalGroupByFields")
            .is_none()
    );
    assert_eq!(
        value["options"]["impossibleTravelOptions"],
        serde_json::json!({"baselineUserLocations": false, "detectIpTransition": true})
    );
    let sums = block_rule(
        "    queries:\n      - query: source:x\n        sum: '@bytes'\n      - query: \
         source:y\n        max: '@duration'\n    cases:\n      - condition: a > 1\n",
        "",
    );
    let value = json(&body(&sums, StatusStrategy::Release, None));
    assert_eq!(value["queries"][0]["aggregation"], "sum");
    assert_eq!(
        value["queries"][0]["metrics"],
        serde_json::json!(["@bytes"])
    );
    assert_eq!(value["queries"][1]["aggregation"], "max");
    assert_eq!(value["queries"][1]["name"], "b");
}

#[test]
fn the_severity_comes_from_the_case_then_the_rule() {
    for (top, case, expected) in [
        ("response:\n  alert_severity: Critical\n", "", "critical"),
        ("response:\n  alert_severity: Informational\n", "", "info"),
        ("", "", "info"),
        (
            "response:\n  alert_severity: Low\n",
            "        severity: high\n",
            "high",
        ),
    ] {
        let text = block_rule(
            &format!(
                "    queries:\n      - query: source:x\n    cases:\n      - condition: a > \
                 1\n{case}"
            ),
            top,
        );
        let value = json(&body(&text, StatusStrategy::Release, None));
        assert_eq!(value["cases"][0]["status"], expected, "{top}{case}");
    }
}

#[test]
fn the_derived_message_escapes_templates_and_holds_the_procedure() {
    let text = block_rule(
        "    queries:\n      - query: source:x\n    cases:\n      - name: many\n        \
         condition: a > 1\n",
        "response:\n  procedure:\n    analysis: Look at {{the user}}.\n",
    )
    .replace(
        "description: Failed logins.",
        "description: Uses {{x}} braces.",
    );
    let value = json(&body(&text, StatusStrategy::Release, None));
    let message = value["message"].as_str().unwrap();
    assert!(message.contains("Uses { {x} } braces."), "{message}");
    assert!(message.contains("- many: `a > 1`"), "{message}");
    assert!(
        message.contains("## Triage and response\n### analysis\nLook at { {the user} }."),
        "{message}"
    );
}

#[test]
fn the_calls_around_the_body() {
    let text = fixture("rule-datadog-minimal-1.0.yaml");
    with_rule(&text, |cx, rule| {
        let compiled = compile_rule(cx, rule, StatusStrategy::Release, None).unwrap();
        let validation = json(&validation_request(&compiled));
        assert_eq!(validation["method"], "POST");
        assert_eq!(
            validation["path"],
            "/api/v2/security_monitoring/rules/validation"
        );
        let update = json(&update_request(&compiled, "abc-def-ghi", Json::Int(4)));
        assert_eq!(update["method"], "PUT");
        assert_eq!(
            update["path"],
            "/api/v2/security_monitoring/rules/abc-def-ghi"
        );
        assert_eq!(update["body"]["version"], 4);
        assert!(
            update["body"].get("type").is_none(),
            "the update takes no type"
        );
        assert_eq!(update["body"]["name"], "Console login failures");
    });
}

#[test]
fn the_logs_search_bodies() {
    let start: jiff::Timestamp = "2026-11-27T10:00:00Z".parse().unwrap();
    let end: jiff::Timestamp = "2026-11-27T11:00:00Z".parse().unwrap();
    let value = json(&search_body(
        " source:okta ",
        start,
        end,
        50,
        &["main".to_owned()],
        Some("c1"),
    ));
    assert_eq!(
        value,
        serde_json::json!({
            "filter": {"query": "source:okta", "from": "2026-11-27T10:00:00Z",
                       "to": "2026-11-27T11:00:00Z", "indexes": ["main"]},
            "page": {"limit": 50, "cursor": "c1"},
            "sort": "-timestamp",
        })
    );
    let live = json(&live_search_request("source:okta", end));
    assert_eq!(live["path"], "/api/v2/logs/events/search");
    assert_eq!(live["body"]["filter"]["from"], "2026-11-27T10:59:00Z");
    assert_eq!(live["body"]["page"]["limit"], 1);
    assert_eq!(
        json(&search_body("x", start, end, 99_999, &[], None))["page"]["limit"],
        5000
    );
}
