//! The Graylog compiler on the repository's fixtures (`tests/fixtures/graylog`,
//! from 0.28.0): each `*.api.json` is the request a rule deploys on the
//! fixture tenant at one server version, compared as data. The other cases
//! are 0.28.0's `tests/test_platforms/test_graylog_compile.py`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every fixture opens and every workspace loads"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::graylog::{
    self, CompiledDefinition, PREVIEW_VERSION, Version, compile_definition, create_request,
    update_request, validate_body,
};
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(repo().join("tests/fixtures/graylog").join(name)).unwrap()
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

/// The fixture tenant (`tenant.toml`), as the compiler reads a tenant.
fn tenant() -> Json {
    let node = opentide_schema::configuration::toml::parse(&fixture("tenant.toml")).unwrap();
    let tenants = Json::from_node(&node);
    match tenants.get("tenants") {
        Some(Json::Array(tenants)) => tenants[0].clone(),
        _ => panic!("tenant.toml has a tenant"),
    }
}

fn uuid_of(rule: &str) -> String {
    let node = opentide_schema::node::load(rule).unwrap();
    let root = node.root().unwrap();
    Rule::new(root, None).uuid
}

/// What `rule` deploys on `tenant` (or offline) at `version`.
fn compiled(
    rule: &str,
    version: Version,
    tenant: Option<&Json>,
) -> Result<CompiledDefinition, (String, String)> {
    let workspace = workspace(rule);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", &uuid_of(rule)).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let setup = tenant.and_then(graylog::tenant_setup);
    let name = tenant
        .and_then(|tenant| tenant.get("name"))
        .and_then(Json::as_str);
    compile_definition(&cx, &rule, version, setup, name)
        .map_err(|error| (error.code.to_owned(), error.reason))
}

fn data(json: &Json) -> serde_json::Value {
    serde_json::from_str(&json.to_compact()).unwrap()
}

fn expected(name: &str) -> serde_json::Value {
    serde_json::from_str(&fixture(name)).unwrap()
}

const DEFINITION_ID: &str = "65f1c0de2a3b4c5d6e7f8091";

#[test]
fn every_create_request_equals_its_fixture() {
    let tenant = tenant();
    for (rule, version, name) in [
        (
            "rule-graylog-aggregation-1.0.yaml",
            Version(6, 3, 0),
            "rule-graylog-aggregation-1.0.6.3.create.api.json",
        ),
        (
            "rule-graylog-aggregation-1.0.yaml",
            Version(7, 0, 0),
            "rule-graylog-aggregation-1.0.7.0.create.api.json",
        ),
        (
            "rule-graylog-aggregation-1.0.yaml",
            Version(7, 2, 0),
            "rule-graylog-aggregation-1.0.7.2.create.api.json",
        ),
        (
            "rule-graylog-filter-1.1.yaml",
            Version(6, 3, 0),
            "rule-graylog-filter-1.1.6.3.create.api.json",
        ),
        (
            "rule-graylog-filter-1.1.yaml",
            Version(7, 1, 0),
            "rule-graylog-filter-1.1.7.1.create.api.json",
        ),
    ] {
        let compiled = compiled(&fixture(rule), version, Some(&tenant)).unwrap();
        assert_eq!(data(&create_request(&compiled)), expected(name), "{name}");
    }
}

#[test]
fn the_update_and_disable_requests_equal_their_fixtures() {
    let tenant = tenant();
    let compiled = compiled(
        &fixture("rule-graylog-aggregation-1.0.yaml"),
        Version(7, 2, 0),
        Some(&tenant),
    )
    .unwrap();
    assert_eq!(
        data(&update_request(&compiled, DEFINITION_ID, true)),
        expected("rule-graylog-aggregation-1.0.7.2.update.api.json")
    );
    assert_eq!(
        data(&update_request(&compiled, DEFINITION_ID, false)),
        expected("rule-graylog-aggregation-1.0.7.2.disable.api.json")
    );
}

#[test]
fn the_version_earns_warnings() {
    let tenant = tenant();
    let aggregation = fixture("rule-graylog-aggregation-1.0.yaml");
    let old = compiled(&aggregation, Version(7, 0, 0), Some(&tenant)).unwrap();
    let codes: Vec<&str> = old.warnings.iter().map(|(code, _)| *code).collect();
    assert_eq!(
        codes,
        [
            "graylog_field_unsupported_version",
            "graylog_field_unsupported_version"
        ]
    );
    assert_eq!(
        old.warnings[0].1,
        "summary is left out: Graylog 7.0.0 has no event summary template (7.1 and later)"
    );
    assert_eq!(
        old.warnings[1].1,
        "tags are left out: Graylog 7.0.0 has no definition tags (7.2 and later)"
    );
    assert!(
        compiled(&aggregation, Version(7, 2, 0), Some(&tenant))
            .unwrap()
            .warnings
            .is_empty()
    );
    let filter = compiled(
        &fixture("rule-graylog-filter-1.1.yaml"),
        Version(6, 3, 0),
        Some(&tenant),
    )
    .unwrap();
    assert_eq!(
        filter.warnings,
        [(
            "graylog_priority_collapsed",
            "Graylog 6.3.0 has no Informational priority: sent as Low (1)".to_owned()
        )]
    );
}

#[test]
fn offline_the_aliases_are_left_unresolved() {
    let compiled = compiled(
        &fixture("rule-graylog-aggregation-1.0.yaml"),
        PREVIEW_VERSION,
        None,
    )
    .unwrap();
    assert_eq!(
        compiled.unresolved,
        [
            ("streams", vec!["sysmon".to_owned()]),
            ("notifications", vec!["soc-slack".to_owned()])
        ]
    );
    let definition = Json::Object(compiled.definition.clone());
    assert_eq!(
        data(definition.get("config").unwrap().get("streams").unwrap()),
        serde_json::json!([])
    );
    assert_eq!(
        data(definition.get("notifications").unwrap()),
        serde_json::json!([])
    );
    // No tenant tags offline.
    assert_eq!(
        data(definition.get("tags").unwrap()),
        serde_json::json!([
            "office",
            "initial-access",
            "opentide",
            "opentide.00000000-0000-4000-8003-000000000060"
        ])
    );
    assert_eq!(
        compiled.uuid_tag().as_deref(),
        Some("opentide.00000000-0000-4000-8003-000000000060")
    );
}

#[test]
fn an_unknown_alias_is_graylog_alias_unknown() {
    let tenant = tenant();
    let rule = fixture("rule-graylog-aggregation-1.0.yaml").replace(
        "notifications: soc-slack",
        "notifications: [soc-slack, pager]",
    );
    let (code, reason) = compiled(&rule, PREVIEW_VERSION, Some(&tenant)).unwrap_err();
    assert_eq!(code, "graylog_alias_unknown");
    assert_eq!(
        reason,
        "tenant 'graylog-prod': notification alias(es) pager are not in the tenant's \
         notification_ids table"
    );
    let rule = fixture("rule-graylog-aggregation-1.0.yaml")
        .replace("streams: sysmon", "streams: [sysmon, edr]");
    let (code, reason) = compiled(&rule, PREVIEW_VERSION, Some(&tenant)).unwrap_err();
    assert_eq!(code, "graylog_alias_unknown");
    assert!(
        reason.ends_with("stream alias(es) edr are not in the tenant's stream_ids table"),
        "{reason}"
    );
}

#[test]
fn the_tenant_streams_stand_in_for_a_block_without_streams() {
    let tenant = tenant();
    let compiled = compiled(
        &fixture("block-graylog.yaml").replace("    streams: sysmon\n", ""),
        PREVIEW_VERSION,
        Some(&tenant),
    )
    .unwrap();
    let definition = Json::Object(compiled.definition.clone());
    let config = definition.get("config").unwrap();
    assert_eq!(
        data(config.get("streams").unwrap()),
        serde_json::json!(["65f0c0ffee0123456789abcd"])
    );
    // A filter with no schedule: every 5 minutes over 5 minutes, 100 events.
    assert_eq!(data(config.get("search_within_ms").unwrap()), 300_000);
    assert_eq!(data(config.get("execute_every_ms").unwrap()), 300_000);
    assert_eq!(data(config.get("event_limit").unwrap()), 100);
    assert_eq!(
        data(&validate_body(&compiled)),
        serde_json::json!({
            "query": "EventID:1 AND image_lc:/.*\\\\mshta\\.exe/",
            "streams": ["65f0c0ffee0123456789abcd"],
            "stream_categories": [],
            "timerange": {"type": "relative", "range": 300},
        })
    );
    // Medium, from the rule's response; the rule's name; no ATT&CK.
    assert_eq!(data(definition.get("priority").unwrap()), 2);
    assert_eq!(compiled.title, "Graylog platform block");
    assert_eq!(
        data(definition.get("tactics_techniques").unwrap()),
        serde_json::json!([])
    );
}

#[test]
fn the_block_name_priority_and_alert_win() {
    let rule = fixture("block-graylog.yaml").replace(
        "    streams: sysmon\n",
        "    name: Own title\n    priority: Critical\n    alert: false\n    backlog: 5\n    \
         grace_period: 0s\n    event_key: [host]\n    event_fields: {host: source}\n",
    );
    let compiled = compiled(&rule, PREVIEW_VERSION, None).unwrap();
    let definition = Json::Object(compiled.definition.clone());
    assert_eq!(compiled.title, "Own title");
    assert_eq!(data(definition.get("priority").unwrap()), 4);
    assert_eq!(data(definition.get("alert").unwrap()), false);
    assert_eq!(
        data(definition.get("notification_settings").unwrap()),
        serde_json::json!({"grace_period_ms": 0, "backlog_size": 5})
    );
    assert_eq!(
        data(definition.get("key_spec").unwrap()),
        serde_json::json!(["host"])
    );
}

#[test]
fn a_cron_schedule_without_a_time_zone_runs_in_utc() {
    let rule = fixture("rule-graylog-filter-1.1.yaml").replace(", timezone: Europe/Paris", "");
    let compiled = compiled(&rule, PREVIEW_VERSION, None).unwrap();
    let definition = Json::Object(compiled.definition.clone());
    let config = definition.get("config").unwrap();
    assert_eq!(data(config.get("cron_timezone").unwrap()), "UTC");
    assert_eq!(data(config.get("use_cron_scheduling").unwrap()), true);
}

#[test]
fn a_rule_without_a_graylog_block_fails() {
    let rule = fixture("block-graylog.yaml").replace("  graylog:", "  splunk:");
    let (code, reason) = compiled(&rule, PREVIEW_VERSION, None).unwrap_err();
    assert_eq!(code, "compile_failed");
    assert!(reason.contains("has no graylog block"), "{reason}");
}

/// `block-graylog.yaml` with `extra` (block lines, indented by 4) in place of
/// its `streams`.
fn block_rule(extra: &str) -> String {
    let extra: String = extra
        .lines()
        .flat_map(|line| ["    ", line, "\n"])
        .collect();
    fixture("block-graylog.yaml").replace("    streams: sysmon\n", &extra)
}

fn definition(compiled: &CompiledDefinition) -> serde_json::Value {
    data(&Json::Object(compiled.definition.clone()))
}

#[test]
fn tags_are_normalised_unique_and_capped() {
    let mut tenant = tenant();
    if let Json::Object(object) = &mut tenant
        && let Some(Json::Object(setup)) = object.get_mut("setup")
    {
        setup.insert("tags".into(), "extra".into());
    }
    let many: Vec<String> = (0..80).map(|n| format!("t{n}")).collect();
    let rule = block_rule(&format!("tags: [Office, office, {}]", many.join(", ")));
    let tags =
        definition(&compiled(&rule, PREVIEW_VERSION, Some(&tenant)).unwrap())["tags"].clone();
    let tags = tags.as_array().unwrap();
    assert_eq!(tags[0], "office");
    assert_eq!(tags.len(), 64);
    // The cap keeps the first 64 in the spec's order: the block's own come first.
    assert!(!tags.contains(&serde_json::json!("opentide")));
    let few = compiled(&block_rule("tags: Office"), PREVIEW_VERSION, Some(&tenant)).unwrap();
    assert_eq!(
        definition(&few)["tags"],
        serde_json::json!([
            "office",
            "opentide",
            "opentide.00000000-0000-4000-8003-000000000062",
            "extra"
        ])
    );
}

#[test]
fn a_block_attack_techniques_field_is_kept() {
    let rule = block_rule("event_fields: {attack_techniques: {template: custom}}")
        .replace("response:", "techniques:\n- T1059.001\nresponse:");
    let compiled = compiled(&rule, Version(6, 3, 5), None).unwrap();
    assert_eq!(
        definition(&compiled)["field_spec"]["attack_techniques"]["providers"][0]["template"],
        "custom"
    );
    assert!(
        definition(&compiled)["description"]
            .as_str()
            .unwrap()
            .ends_with("ATT&CK: T1059.001, TA0002")
    );
}

#[test]
fn without_attack_ids_the_description_has_no_attack_line() {
    let compiled = compiled(&block_rule(""), Version(6, 3, 5), None).unwrap();
    assert_eq!(
        definition(&compiled)["description"],
        "Graylog event definition: the smallest useful block, a filter."
    );
    assert!(
        definition(&compiled)["field_spec"]
            .get("attack_techniques")
            .is_none()
    );
}

#[test]
fn the_block_priority_wins_over_the_severity() {
    let rule =
        block_rule("priority: Low").replace("alert_severity: Medium", "alert_severity: Critical");
    assert_eq!(
        definition(&compiled(&rule, PREVIEW_VERSION, None).unwrap())["priority"],
        1
    );
    let rule = block_rule("").replace("response:\n  alert_severity: Medium\n", "");
    assert_eq!(
        definition(&compiled(&rule, PREVIEW_VERSION, None).unwrap())["priority"],
        2
    );
}

#[test]
fn the_block_streams_win_over_the_tenant_streams() {
    let tenant = tenant();
    let rule = block_rule("streams: windows-security\nstream_categories: edr");
    let compiled = compiled(&rule, PREVIEW_VERSION, Some(&tenant)).unwrap();
    assert_eq!(
        definition(&compiled)["config"]["streams"],
        serde_json::json!(["65f0c0ffee0123456789abce"])
    );
    assert_eq!(
        definition(&compiled)["config"]["stream_categories"],
        serde_json::json!(["edr"])
    );
}

#[test]
fn the_uuid_tag_is_named_on_7_2_only() {
    let tenant = tenant();
    let rule = fixture("rule-graylog-aggregation-1.0.yaml");
    assert!(
        compiled(&rule, Version(7, 1, 0), Some(&tenant))
            .unwrap()
            .uuid_tag()
            .is_none()
    );
    assert!(
        compiled(&rule, Version(7, 2, 0), Some(&tenant))
            .unwrap()
            .uuid_tag()
            .is_some()
    );
}

#[test]
fn no_body_carries_a_server_owned_property_or_a_create_id() {
    let tenant = tenant();
    for version in [
        Version(6, 3, 5),
        Version(7, 0, 16),
        Version(7, 1, 12),
        Version(7, 2, 2),
    ] {
        let compiled = compiled(
            &fixture("rule-graylog-aggregation-1.0.yaml"),
            version,
            Some(&tenant),
        )
        .unwrap();
        let body = data(&graylog::create_body(&compiled));
        let definition = body.get("entity").unwrap_or(&body);
        assert_eq!(definition["_scope"], "DEFAULT");
        for key in [
            "id",
            "state",
            "storage",
            "scheduler",
            "updated_at",
            "matched_at",
            "_entity_source",
        ] {
            assert!(definition.get(key).is_none(), "{version}: {key}");
        }
    }
}

#[test]
fn parse_version_cases() {
    for (text, expected) in [
        ("6.3.5+eaa4b5d", Some(Version(6, 3, 5))),
        ("7.2.2+94adc86", Some(Version(7, 2, 2))),
        ("7.1", Some(Version(7, 1, 0))),
        ("7.0.16-SNAPSHOT", Some(Version(7, 0, 16))),
        ("", None),
        ("seven", None),
    ] {
        assert_eq!(graylog::parse_version(text), expected, "{text}");
    }
}
