//! The Bitdefender GravityZone compiler (bitdefender-1.0, Deploy): the
//! JSON-RPC bodies of `tests/fixtures/bitdefender/*.api.json`, equal as data,
//! and the cases of 0.28.0's `tests/test_platforms/test_bitdefender_compile.py`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace and fixture here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::bitdefender::{
    self, GravityZoneRule, compile_rule, create_params, delete_params, derive_description,
    request_body, update_params,
};
use opentide_compile::deploy::Action;
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};
use serde_json::{Value, json};

const RULE_ID: &str = "6372b7a3897aaa77ee021642";
const UUID: &str = "11111111-2222-4333-8444-555555555555";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bitdefender")
}

/// A workspace holding `rules` (file name, text).
fn workspace(rules: &[(&str, String)]) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    for (name, text) in rules {
        fs.write(format!("/ws/objects/rules/{name}"), text.clone());
    }
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

/// Runs `f` with the context of a workspace holding the rule `text`, and the
/// rule.
fn with_rule<T>(
    text: String,
    uuid: &str,
    f: impl FnOnce(&opentide_compile::Context<'_>, &Rule) -> T,
) -> T {
    let workspace = workspace(&[("r.yaml", text)]);
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

fn fixture_rule(name: &str) -> (String, String) {
    let text = std::fs::read_to_string(fixtures().join(name)).unwrap();
    let uuid = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned();
    (text, uuid)
}

/// The fixture tenant, with `overrides` on its setup.
fn tenant(overrides: &Value) -> Json {
    let text = std::fs::read_to_string(fixtures().join("tenant.toml")).unwrap();
    let document: toml::Value = toml::from_str(&text).unwrap();
    let mut tenant = serde_json::to_value(&document["tenants"][0]).unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        tenant["setup"][key] = value.clone();
    }
    serde_json::from_value(tenant).unwrap()
}

/// A rule whose block is a Basic process rule, with `block` over it and
/// `top` beside it (`_block_rule`).
fn block_rule(block: &Value, top: &Value) -> String {
    let mut bitdefender = json!({
        "status": "STAGING",
        "detection": {
            "target": "process",
            "criteria": [{"field": "Process.Name", "is": "powershell.exe"}]
        }
    });
    for (key, value) in block.as_object().unwrap() {
        bitdefender[key] = value.clone();
    }
    let mut rule = json!({
        "name": "Encoded PowerShell",
        "metadata": {
            "uuid": UUID,
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-11-10",
            "modified": "2026-11-10",
            "tlp": "clear"
        },
        "description": "PowerShell\n  started.",
        "configurations": {"bitdefender": bitdefender}
    });
    for (key, value) in top.as_object().unwrap() {
        rule[key] = value.clone();
    }
    serde_json::to_string_pretty(&rule).unwrap()
}

fn compiled(
    block: &Value,
    top: &Value,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<GravityZoneRule, opentide_compile::CompileError> {
    with_rule(block_rule(block, top), UUID, |cx, rule| {
        compile_rule(cx, rule, strategy, tenant)
    })
}

fn data(json: &Json) -> Value {
    serde_json::to_value(json).unwrap()
}

#[test]
fn bodies_match_the_specification_goldens() {
    for (golden, source, method, strategy) in [
        (
            "rule-bitdefender-detection-1.0.create.api.json",
            "rule-bitdefender-detection-1.0.yaml",
            bitdefender::CREATE,
            StatusStrategy::Release,
        ),
        (
            "rule-bitdefender-detection-1.0.update.api.json",
            "rule-bitdefender-detection-1.0.yaml",
            bitdefender::UPDATE,
            StatusStrategy::Release,
        ),
        (
            "rule-bitdefender-detection-1.0.disable.api.json",
            "rule-bitdefender-detection-1.0.yaml",
            bitdefender::UPDATE,
            StatusStrategy::Disablement,
        ),
        (
            "rule-bitdefender-yara-1.0.create.api.json",
            "rule-bitdefender-yara-1.0.yaml",
            bitdefender::CREATE,
            StatusStrategy::Release,
        ),
    ] {
        let (text, uuid) = fixture_rule(source);
        let tenant = tenant(&json!({}));
        let body = with_rule(text, &uuid, |cx, rule| {
            let compiled = compile_rule(cx, rule, strategy, Some(&tenant)).unwrap();
            let params = if method == bitdefender::CREATE {
                create_params(&compiled)
            } else {
                update_params(&compiled, RULE_ID)
            };
            request_body(method, params)
        });
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(fixtures().join(golden)).unwrap())
                .unwrap();
        assert_eq!(data(&body), expected, "{golden}");
        // The key order is the oracle's too, as the request is built key by key.
        assert_eq!(
            serde_json::to_string(&data(&body)).unwrap(),
            serde_json::to_string(&expected).unwrap(),
            "{golden}"
        );
    }
}

#[test]
fn every_update_carries_the_whole_payload() {
    let (text, uuid) = fixture_rule("rule-bitdefender-detection-1.0.yaml");
    let tenant = tenant(&json!({}));
    let params = with_rule(text, &uuid, |cx, rule| {
        data(&update_params(
            &compile_rule(cx, rule, StatusStrategy::Release, Some(&tenant)).unwrap(),
            RULE_ID,
        ))
    });
    let keys: Vec<&String> = params.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "description",
            "name",
            "ruleId",
            "settings",
            "tags",
            "targets",
            "type"
        ]
    );
    let types: Vec<i64> = params["settings"]["automaticActions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["type"].as_i64().unwrap())
        .collect();
    assert_eq!(types, [1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn delete_names_the_rule_and_a_detection_type() {
    assert_eq!(
        data(&request_body(bitdefender::DELETE, delete_params(RULE_ID))),
        json!({"jsonrpc": "2.0", "method": "deleteCustomRule", "params": {"ruleId": RULE_ID, "type": 1}})
    );
}

#[test]
fn text_is_normalised() {
    let long = derive_description(&"word ".repeat(400));
    assert_eq!(long.chars().count(), 1024);
    assert!(long.ends_with('\u{2026}'));
    assert_eq!(derive_description("a\n   b\t c "), "a b c");
    assert_eq!(derive_description("  <x>"), "\u{2039}x\u{203A}");
}

#[test]
fn severity() {
    for (block, response, severity) in [
        (json!({"severity": "Low"}), Some("Critical"), 1),
        (json!({}), Some("Critical"), 3),
        (json!({}), Some("High"), 3),
        (json!({}), Some("Medium"), 2),
        (json!({}), Some("Low"), 1),
        (json!({}), Some("Informational"), 1),
        (json!({}), None, 2),
    ] {
        let top = response.map_or_else(
            || json!({}),
            |response| json!({"response": {"alert_severity": response}}),
        );
        let compiled = compiled(&block, &top, StatusStrategy::Release, None).unwrap();
        assert_eq!(
            compiled.settings["severity"],
            Json::Int(severity),
            "{block} {response:?}"
        );
    }
}

#[test]
fn tags_are_normalised_unique_and_at_least_two_characters() {
    let long = "y".repeat(200);
    let compiled = compiled(
        &json!({"tags": ["x", "office", "<tag>", "office", long]}),
        &json!({}),
        StatusStrategy::Release,
        Some(&tenant(&json!({"tags": ["office", "tenant"]}))),
    )
    .unwrap();
    assert_eq!(
        compiled.tags,
        [
            "office".to_owned(),
            "\u{2039}tag\u{203A}".to_owned(),
            "y".repeat(128),
            "opentide".to_owned(),
            format!("opentide:{UUID}"),
            "tenant".to_owned(),
        ]
    );
}

#[test]
fn shared_name_wins_and_alert_is_a_filter() {
    let compiled = compiled(
        &json!({
            "name": " 'Quoted' name",
            "detection": {
                "target": "process",
                "criteria": [{"field": "Process.Name", "is": "x.exe"}],
                "alert": "Suspicious process"
            }
        }),
        &json!({}),
        StatusStrategy::Release,
        None,
    )
    .unwrap();
    assert_eq!(compiled.name, "\u{2019}Quoted\u{2019} name");
    assert_eq!(
        data(&compiled.settings["filters"]),
        json!([{"field": "detection", "value": "Suspicious process"}])
    );
}

#[test]
fn yara_query_has_lf_endings_and_one_trailing_newline() {
    let block = json!({
        "detection": null,
        "yara": {"signature": "rule A {\r\n condition: true\r\n}", "on_access": true}
    });
    let release = compiled(&block, &json!({}), StatusStrategy::Release, None).unwrap();
    assert_eq!(
        release.settings["yaraQuery"],
        Json::Str("rule A {\n condition: true\n}\n".to_owned())
    );
    assert_eq!(release.settings["status"], Json::Int(1));
    let disabled = compiled(&block, &json!({}), StatusStrategy::Disablement, None).unwrap();
    assert_eq!(disabled.settings["status"], Json::Int(0));
    let off = json!({"detection": null, "yara": {"signature": "rule A { condition: true }", "on_access": false}});
    let on_demand = compiled(&off, &json!({}), StatusStrategy::Release, None).unwrap();
    assert_eq!(on_demand.settings["status"], Json::Int(0));
    // A YARA rule cannot kill a process: its actions leave type 4 out.
    let types: Vec<i64> = data(&on_demand.settings["automaticActions"])
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["type"].as_i64().unwrap())
        .collect();
    assert_eq!(types, [1, 2, 3, 5, 6, 7]);
}

#[test]
fn tenant_without_automatic_actions_omits_them() {
    let compiled = compiled(
        &json!({"actions": {"isolate": true}}),
        &json!({}),
        StatusStrategy::Release,
        Some(&tenant(&json!({"automatic_actions": false}))),
    )
    .unwrap();
    assert!(!compiled.settings.contains_key("automaticActions"));
}

#[test]
fn antimalware_scans_and_scopes_are_settings() {
    let compiled = compiled(
        &json!({"actions": {"antimalware_scan": "quick", "quarantine": {"include_parent": true}}}),
        &json!({}),
        StatusStrategy::Release,
        None,
    )
    .unwrap();
    let actions = data(&compiled.settings["automaticActions"]);
    assert_eq!(
        actions[4],
        json!({"type": 5, "enabled": true, "settings": {"type": 1}})
    );
    assert_eq!(
        actions[5],
        json!({"type": 6, "enabled": true, "settings": {"includeParent": true, "includeChildren": false}})
    );
}

#[test]
fn tenant_targets_companies_and_partner_company() {
    let company = "61827b8036492c2fc0718722";
    let tenant = tenant(&json!({
        "targets": {"companies": ["acme"]},
        "companies": {"acme": company},
        "company_id": "5b680f6fb1a43d860a7b23c8"
    }));
    let params = data(&create_params(
        &compiled(
            &json!({}),
            &json!({}),
            StatusStrategy::Release,
            Some(&tenant),
        )
        .unwrap(),
    ));
    assert_eq!(params["targets"], json!({"companiesIds": [company]}));
    assert_eq!(params["companyId"], json!("5b680f6fb1a43d860a7b23c8"));
    let body = create_params(
        &compiled(
            &json!({}),
            &json!({}),
            StatusStrategy::Release,
            Some(&tenant),
        )
        .unwrap(),
    );
    assert_eq!(
        body.as_object().unwrap().keys().last().map(String::as_str),
        Some("returnRuleId")
    );
}

#[test]
fn no_targets_means_the_whole_company() {
    let params = data(&create_params(
        &compiled(
            &json!({}),
            &json!({}),
            StatusStrategy::Release,
            Some(&tenant(&json!({"endpoint_tags": {}}))),
        )
        .unwrap(),
    ));
    assert!(params.get("targets").is_none());
}

#[test]
fn an_unknown_target_alias_fails_before_any_call() {
    for (targets, reason) in [
        (
            json!({"endpoint_tags": ["nowhere"]}),
            "tenant 'gravityzone-eu': endpoint tag alias(es) nowhere are not in the tenant's \
             endpoint_tags table",
        ),
        (
            json!({"companies": ["nowhere"]}),
            "tenant 'gravityzone-eu': company alias(es) nowhere are not in the tenant's \
             companies table",
        ),
    ] {
        let error = compiled(
            &json!({"targets": targets}),
            &json!({}),
            StatusStrategy::Release,
            Some(&tenant(&json!({}))),
        )
        .unwrap_err();
        assert_eq!(error.code, "bitdefender_target_unknown");
        assert_eq!(error.reason, reason);
        assert!(error.hint.unwrap().contains("endpoint_tags"));
    }
}

#[test]
fn an_update_leaves_nothing_to_the_stored_rule() {
    let compiled = compiled(
        &json!({}),
        &json!({}),
        StatusStrategy::Release,
        Some(&tenant(&json!({"endpoint_tags": {}}))),
    )
    .unwrap();
    let params = update_params(&compiled, RULE_ID);
    assert_eq!(data(&params)["targets"], json!({}));
    assert_eq!(data(&params)["settings"]["filters"], json!([]));
    let settings = params.get("settings").unwrap().as_object().unwrap();
    let last: Vec<&str> = settings.keys().map(String::as_str).collect();
    assert_eq!(&last[last.len() - 2..], ["filters", "automaticActions"]);
    let created = data(&create_params(&compiled));
    assert!(created.get("targets").is_none());
    assert!(created["settings"].get("filters").is_none());
}

#[test]
fn an_update_keeps_an_alert_filter_and_a_yara_rule_has_none() {
    let alert = compiled(
        &json!({"detection": {
            "target": "process",
            "criteria": [{"field": "Process.Name", "is": "x.exe"}],
            "alert": "Suspicious"
        }}),
        &json!({}),
        StatusStrategy::Release,
        None,
    )
    .unwrap();
    assert_eq!(
        data(&update_params(&alert, RULE_ID))["settings"]["filters"],
        json!([{"field": "detection", "value": "Suspicious"}])
    );
    let yara = compiled(
        &json!({"detection": null, "yara": {"signature": "rule A { condition: true }"}}),
        &json!({}),
        StatusStrategy::Release,
        None,
    )
    .unwrap();
    assert!(
        data(&update_params(&yara, RULE_ID))["settings"]
            .get("filters")
            .is_none()
    );
}

#[test]
fn without_a_tenant_aliases_are_never_sent_as_ids() {
    let text = block_rule(
        &json!({"targets": {"endpoint_tags": ["tier0-servers"]}}),
        &json!({}),
    );
    let (params, unresolved) = with_rule(text, UUID, |cx, rule| {
        (
            data(&create_params(
                &compile_rule(cx, rule, StatusStrategy::Release, None).unwrap(),
            )),
            bitdefender::unresolved_targets(rule).unwrap(),
        )
    });
    assert!(params.get("targets").is_none());
    assert_eq!(
        unresolved.map(|targets| data(&targets)),
        Some(json!({"endpoint_tags": ["tier0-servers"]}))
    );
    let none = with_rule(block_rule(&json!({}), &json!({})), UUID, |_, rule| {
        bitdefender::unresolved_targets(rule).unwrap()
    });
    assert!(none.is_none());
}

#[test]
fn an_empty_tenant_default_never_resolves_to_the_whole_company() {
    for default in [
        json!({}),
        json!({"endpoint_tags": []}),
        json!({"companies": null}),
    ] {
        let error = compiled(
            &json!({}),
            &json!({}),
            StatusStrategy::Release,
            Some(&tenant(&json!({"targets": default}))),
        )
        .unwrap_err();
        assert_eq!(error.code, "bitdefender_targets_shape", "{default}");
    }
}

#[test]
fn the_request_follows_the_action() {
    let (text, uuid) = fixture_rule("rule-bitdefender-detection-1.0.yaml");
    let tenant = tenant(&json!({}));
    let methods = with_rule(text, &uuid, |cx, rule| {
        [
            Action::Create,
            Action::Update(RULE_ID.to_owned()),
            Action::Delete(RULE_ID.to_owned()),
        ]
        .iter()
        .map(|action| {
            data(&bitdefender::request(cx, rule, &tenant, action).unwrap())["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
    });
    assert_eq!(
        methods,
        ["createCustomRule", "updateCustomRule", "deleteCustomRule"]
    );
}

#[test]
fn a_rule_without_a_block_is_a_compile_failure() {
    let text = serde_json::to_string(&json!({
        "name": "R",
        "metadata": {"uuid": UUID, "schema": "rule::1.0"},
        "configurations": {"sysdig": {"status": "STAGING", "condition": "x"}}
    }))
    .unwrap();
    let error = with_rule(text, UUID, |cx, rule| {
        compile_rule(cx, rule, StatusStrategy::Release, None).unwrap_err()
    });
    assert_eq!(error.code, "compile_failed");
    assert!(error.reason.contains("has no bitdefender block"));
}
