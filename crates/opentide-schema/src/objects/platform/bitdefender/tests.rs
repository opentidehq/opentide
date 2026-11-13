//! `BitdefenderConfig` and its constraint codes (bitdefender-1.0,
//! Constraints): the cases of 0.28.0's
//! `tests/test_platforms/test_bitdefender_model.py` and of the language
//! server's `bitdefender_spec.rs`, on the model. The YARA signature's codes
//! are the YARA lane's, with their cases.

use std::sync::Arc;

use serde_json::{Value as Json, json};

use super::*;
use crate::error::ErrorKind;
use crate::from_node::{Context, FromNode};
use crate::objects::platform::json_node;

const YARA: &str = "rule A {\n  strings:\n    $a = \"evil\"\n  condition:\n    $a\n}\n";

fn process() -> Json {
    json!({"target": "process", "criteria": [{"field": "Process.Name", "is": "x.exe"}]})
}

fn yara() -> Json {
    json!({"signature": YARA})
}

fn block(keys: &Json) -> Json {
    let mut block = json!({
        "enabled": true,
        "schema": "platform::bitdefender::1.0",
        "status": "STAGING",
    });
    for (key, value) in keys.as_object().unwrap() {
        block[key] = value.clone();
    }
    block
}

fn detection(target: &str, criteria: &Json) -> Json {
    json!({"target": target, "criteria": criteria})
}

fn read(block: &Json) -> (Option<BitdefenderConfig>, Vec<crate::SchemaError>) {
    let mut cx = Context::new();
    let value = BitdefenderConfig::from_node(&json_node(block), &mut cx);
    (value, cx.into_errors())
}

/// `(code, field_path)` for each finding, as validate reports them.
fn errors(block: &Json) -> Vec<(String, Vec<String>)> {
    let (_, errors) = read(block);
    errors
        .into_iter()
        .map(|error| {
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                error.field_path(),
            )
        })
        .collect()
}

fn codes(block: &Json) -> BTreeSet<String> {
    errors(block).into_iter().map(|(code, _)| code).collect()
}

fn valid(block: &Json) -> BitdefenderConfig {
    let (value, errors) = read(block);
    assert!(errors.is_empty(), "{errors:?}");
    value.unwrap()
}

use std::collections::BTreeSet;

fn path(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// A fixture of `tests/fixtures/bitdefender/`, compiled in: the crate does
/// no I/O, its tests included (`scripts/engine/check-io-free.sh`).
macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bitdefender/",
            $name
        ))
    };
}

/// The specification's valid fixtures.
const VALID: [(&str, &str); 3] = [
    ("block-bitdefender.yaml", fixture!("block-bitdefender.yaml")),
    (
        "rule-bitdefender-detection-1.0.yaml",
        fixture!("rule-bitdefender-detection-1.0.yaml"),
    ),
    (
        "rule-bitdefender-yara-1.0.yaml",
        fixture!("rule-bitdefender-yara-1.0.yaml"),
    ),
];

/// The specification's invalid fixtures, each with the code its header names.
const INVALID: [(&str, &str, &str); 4] = [
    (
        "rule-bitdefender-two-kinds.yaml",
        fixture!("invalid/rule-bitdefender-two-kinds.yaml"),
        "bitdefender_rule_kind",
    ),
    (
        "rule-bitdefender-criterion-field.yaml",
        fixture!("invalid/rule-bitdefender-criterion-field.yaml"),
        "bitdefender_criterion_field",
    ),
    (
        "rule-bitdefender-exclusion.yaml",
        fixture!("invalid/rule-bitdefender-exclusion.yaml"),
        "bitdefender_rule_kind",
    ),
    (
        "rule-bitdefender-kill-on-yara.yaml",
        fixture!("invalid/rule-bitdefender-kill-on-yara.yaml"),
        "bitdefender_action_scope",
    ),
];

/// The block of a fixture: `configurations.bitdefender`, or the document.
fn fixture_block(text: &str) -> Arc<crate::node::Node> {
    let document = crate::node::load(text).unwrap();
    let root = document.root().unwrap().clone();
    root.get("configurations")
        .map_or_else(|| root.clone(), |c| c.get("bitdefender").unwrap().clone())
}

fn fixture_codes(text: &str) -> BTreeSet<String> {
    let mut cx = Context::new();
    let _ = BitdefenderConfig::from_node(&fixture_block(text), &mut cx);
    cx.into_errors()
        .into_iter()
        .map(|error| error.kind.pydantic_type().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn the_specification_fixtures_validate() {
    for (name, text) in VALID {
        let mut cx = Context::new();
        let value = BitdefenderConfig::from_node(&fixture_block(text), &mut cx);
        assert!(cx.into_errors().is_empty(), "{name}");
        assert!(value.is_some(), "{name}");
    }
}

#[test]
fn the_specification_invalid_fixtures_report_their_code() {
    for (name, text, code) in INVALID {
        assert!(
            text.contains(&format!("Expected constraint code: {code}")),
            "{name}"
        );
        assert!(fixture_codes(text).contains(code), "{name}");
    }
}

#[test]
fn a_minimal_block_validates() {
    let block = valid(&block(&json!({"detection": process()})));
    assert_eq!(block.kind(), Kind::Detection);
    assert_eq!(
        valid(&super::tests::block(&json!({"yara": yara()}))).kind(),
        Kind::Yara
    );
}

#[test]
fn omitted_status_is_the_missing_field_not_a_code() {
    let found = errors(&json!({"detection": process()}));
    assert_eq!(found, [("missing".to_owned(), path(&["status"]))]);
}

fn each_constraint_case() -> Vec<(&'static str, Json)> {
    let mut with_target = process();
    with_target["target"] = json!("flow");
    let mut bitbucket = process();
    bitbucket["target"] = json!("bitbucket repository");
    let mut upper = process();
    upper["target"] = json!("Process");
    vec![
        ("bitdefender_rule_kind", block(&json!({}))),
        (
            "bitdefender_rule_kind",
            block(&json!({"detection": process(), "yara": yara()})),
        ),
        // `exclusion` is an unknown key, and no kind is set.
        (
            "bitdefender_rule_kind",
            block(&json!({"exclusion": process()})),
        ),
        (
            "bitdefender_target",
            block(&json!({"detection": with_target})),
        ),
        (
            "bitdefender_target",
            block(&json!({"detection": bitbucket})),
        ),
        ("bitdefender_target", block(&json!({"detection": upper}))),
        (
            "bitdefender_criterion_shape",
            block(&json!({"detection": detection("process", &json!([
                {"field": "Process.Name", "is": "a", "any": ["b"]}
            ]))})),
        ),
        (
            "bitdefender_criterion_shape",
            block(&json!({"detection": detection("process", &json!([{"field": "Process.Name"}]))})),
        ),
        (
            "bitdefender_criterion_shape",
            block(
                &json!({"detection": detection("process", &json!([{"field": "Process.Name", "any": []}]))}),
            ),
        ),
        (
            "bitdefender_criterion_shape",
            block(
                &json!({"detection": detection("process", &json!([{"field": "Process.Name", "is": ["a"]}]))}),
            ),
        ),
        (
            "bitdefender_criterion_shape",
            block(
                &json!({"detection": detection("process", &json!([{"field": "Process.Name", "contains": 4}]))}),
            ),
        ),
        (
            "bitdefender_criterion_field",
            block(
                &json!({"detection": detection("process", &json!([{"field": "File.Name", "is": "a"}]))}),
            ),
        ),
        (
            "bitdefender_criterion_relation",
            block(
                &json!({"detection": detection("process", &json!([{"field": "Process.MD5", "contains": "*a*"}]))}),
            ),
        ),
        (
            "bitdefender_criterion_relation",
            block(&json!({"detection": detection("registry", &json!([
                {"field": "Registry.Operation", "contains": "k*"}
            ]))})),
        ),
        (
            "bitdefender_criterion_value",
            block(&json!({"detection": detection("registry", &json!([
                {"field": "Registry.DataType", "is": "float"}
            ]))})),
        ),
        (
            "bitdefender_criterion_value",
            block(&json!({"detection": detection("connection", &json!([
                {"field": "Connection.DestinationPort", "any": [443, 70000]}
            ]))})),
        ),
        (
            "bitdefender_criterion_value",
            block(&json!({"detection": detection("connection", &json!([
                {"field": "Connection.SourcePort", "is": "443"}
            ]))})),
        ),
        (
            "bitdefender_criteria_combination",
            block(&json!({"detection": detection("file", &json!([
                {"field": "File.MD5", "is": "44d88612fea8a8f36de82e1278abb02f"},
                {"field": "File.CreatedBy.Name", "is": "a.exe"}
            ]))})),
        ),
        (
            "bitdefender_criteria_combination",
            block(&json!({"detection": detection("file", &json!([
                {"field": "File.Operation", "any": ["rename", "downloaded"]}
            ]))})),
        ),
        (
            "bitdefender_criteria_combination",
            block(&json!({"detection": detection("file", &json!([
                {"field": "File.CertificateSignedStatus", "is": "is_unsigned"}
            ]))})),
        ),
        (
            "bitdefender_criteria_combination",
            block(&json!({"detection": detection("connection", &json!([
                {"field": "Connection.Protocol", "is": "smb"}
            ]))})),
        ),
        (
            "bitdefender_criteria_combination",
            block(&json!({"detection": {
                "target": "file",
                "criteria": [{"field": "File.Operation", "is": "downloaded"}],
                "alert": "Suspicious download"
            }})),
        ),
        (
            "bitdefender_action_scope",
            block(&json!({
                "detection": detection("connection", &json!([
                    {"field": "Connection.Domain", "is": "x"},
                    {"field": "Connection.Protocol", "is": "smb"}
                ])),
                "actions": {"kill_process": true}
            })),
        ),
        (
            "bitdefender_action_scope",
            block(&json!({
                "detection": detection("registry", &json!([{"field": "Registry.Key", "is": "HKLM\\x"}])),
                "actions": {"quarantine": true}
            })),
        ),
        (
            "bitdefender_action_scope",
            block(&json!({"yara": yara(), "actions": {"kill_process": true}})),
        ),
        (
            "bitdefender_targets_shape",
            block(&json!({
                "detection": process(),
                "targets": {"endpoint_tags": ["a"], "companies": ["b"]}
            })),
        ),
        (
            "bitdefender_targets_shape",
            block(&json!({"detection": process(), "targets": {"companies": []}})),
        ),
        (
            "bitdefender_severity",
            block(&json!({"detection": process(), "severity": "Critical"})),
        ),
        (
            "bitdefender_severity",
            block(&json!({"detection": process(), "severity": "high"})),
        ),
    ]
}

#[test]
fn each_constraint_reports_its_code() {
    for (code, block) in each_constraint_case() {
        assert_eq!(codes(&block), BTreeSet::from([code.to_owned()]), "{block}");
    }
}

#[test]
fn catalogue_conforming_detections_validate() {
    for detection in [
        json!({"target": "process", "criteria": [{"field": "Process.CommandLine", "contains": "*-enc*"}]}),
        json!({"target": "file", "criteria": [{"field": "File.Operation", "any": ["rename", "write"]}]}),
        json!({"target": "file", "criteria": [
            {"field": "File.Name", "is": "a.exe"},
            {"field": "File.CertificateSignedStatus", "is": "is_unsigned"}
        ]}),
        json!({"target": "connection", "criteria": [
            {"field": "Connection.Domain", "contains": "*.example"},
            {"field": "Connection.Protocol", "is": "http/https"},
            {"field": "Connection.DestinationPort", "any": [80, 443]}
        ]}),
        json!({"target": "email", "criteria": [{"field": "Email.Sender", "is": "x@example.com"}], "alert": "Phishing"}),
        json!({"target": "connection", "criteria": [
            {"field": "Connection.Email.Subject", "contains": "*invoice*"},
            {"field": "Connection.Email.Operation", "is": "received"}
        ]}),
        json!({"target": "connection", "criteria": [{"field": "Connection.SourceUser", "is": "alice"}], "alert": "x"}),
        json!({"target": "connection", "criteria": [
            {"field": "Connection.Bucket.Name", "is": "backups"},
            {"field": "Connection.Bucket.Operation", "any": ["deleted", "download"]}
        ]}),
        json!({"target": "file", "criteria": [{"field": "File.Operation", "is": "downloaded"}]}),
        json!({"target": "file", "criteria": [{"field": "File.Name", "is": "a.exe"}], "alert": "Suspicious download"}),
    ] {
        valid(&block(&json!({"detection": detection})));
    }
}

#[test]
fn process_actions_follow_a_created_by_criterion() {
    let block = valid(&block(&json!({
        "detection": detection("registry", &json!([{"field": "Registry.CreatedBy.Name", "is": "reg.exe"}])),
        "actions": {"kill_process": {"include_parent": true}, "quarantine": true, "sandbox": true}
    })));
    let actions = block.actions.unwrap();
    assert_eq!(
        actions.kill_process,
        Some(ProcessAction::Scoped(BitdefenderProcessScope {
            include_parent: true,
            include_children: false
        }))
    );
    assert_eq!(actions.quarantine, Some(ProcessAction::On(true)));
    assert_eq!(actions.sandbox, Some(true));
}

#[test]
fn unknown_keys_fail() {
    let mut extra = process();
    extra["mode"] = json!("x");
    let found = errors(&block(&json!({"detection": extra})));
    assert_eq!(
        found,
        [("extra_forbidden".to_owned(), path(&["detection", "mode"]))]
    );
    let found = errors(&block(
        &json!({"yara": {"signature": YARA, "imports": ["pe"]}}),
    ));
    assert_eq!(
        found,
        [("extra_forbidden".to_owned(), path(&["yara", "imports"]))]
    );
}

#[test]
fn the_specification_1_1_rules() {
    for (code, criteria, target, alert) in [
        (
            "bitdefender_criterion_relation",
            json!([
                {"field": "File.Name", "is": "a.exe"},
                {"field": "File.CertificateSignedStatus", "any": ["is_signed"]}
            ]),
            "file",
            None,
        ),
        (
            "bitdefender_criterion_relation",
            json!([
                {"field": "Connection.Domain", "is": "x"},
                {"field": "Connection.Protocol", "any": ["smb"]}
            ]),
            "connection",
            None,
        ),
        (
            "bitdefender_criterion_relation",
            json!([{"field": "Registry.DataType", "any": ["dword"]}]),
            "registry",
            None,
        ),
        (
            "bitdefender_criterion_shape",
            json!([{"field": "Process.Name", "is": true}]),
            "process",
            None,
        ),
        (
            "bitdefender_criterion_shape",
            json!([{"field": "Process.Name", "any": ["a", false]}]),
            "process",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([
                {"field": "Connection.Bucket.Name", "is": "b"},
                {"field": "Connection.Role.Name", "is": "r"}
            ]),
            "connection",
            Some("x"),
        ),
        (
            "bitdefender_criteria_combination",
            json!([{"field": "Connection.Bucket.Name", "is": "b"}]),
            "connection",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([
                {"field": "Connection.Domain", "is": "x"},
                {"field": "Connection.Protocol", "is": "smb"},
                {"field": "Connection.URL", "is": "u"}
            ]),
            "connection",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([{"field": "Email.Sender", "is": "x"}]),
            "email",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([
                {"field": "Connection.URL", "is": "u"},
                {"field": "Connection.SMBDomain", "is": "d"}
            ]),
            "connection",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([{"field": "File.MD5", "is": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]),
            "file",
            None,
        ),
        (
            "bitdefender_criteria_combination",
            json!([
                {"field": "File.Name", "is": "a.exe"},
                {"field": "File.CertificateSigner", "is": "x"},
                {"field": "File.CertificateSignedStatus", "is": "is_unsigned"}
            ]),
            "file",
            None,
        ),
        (
            "bitdefender_criterion_value",
            json!([{"field": "Email.Operation", "is": "teleported"}]),
            "email",
            Some("x"),
        ),
    ] {
        let mut detection = detection(target, &criteria);
        if let Some(alert) = alert {
            detection["alert"] = json!(alert);
        }
        let block = block(&json!({"detection": detection}));
        assert_eq!(codes(&block), BTreeSet::from([code.to_owned()]), "{block}");
    }
    assert_eq!(
        codes(&block(&json!({"detection": process(), "targets": {}}))),
        BTreeSet::from(["bitdefender_targets_shape".to_owned()])
    );
}

/// The findings a case expects: each code at its path.
type Expected = Vec<(&'static str, Vec<String>)>;

#[test]
fn each_code_is_reported_at_its_field_path() {
    let mut flow = process();
    flow["target"] = json!("flow");
    let cases: Vec<(Json, Expected)> = vec![
        (
            block(&json!({})),
            vec![("bitdefender_rule_kind", Vec::new())],
        ),
        (
            block(&json!({"detection": flow})),
            vec![("bitdefender_target", path(&["detection", "target"]))],
        ),
        (
            block(&json!({"detection": detection("process", &json!([
                {"field": "Process.Name", "is": "a"},
                {"field": "Process.Hash", "is": "b"},
                {"field": "Process.Name"}
            ]))})),
            vec![
                (
                    "bitdefender_criterion_field",
                    path(&["detection", "criteria", "1"]),
                ),
                (
                    "bitdefender_criterion_shape",
                    path(&["detection", "criteria", "2"]),
                ),
            ],
        ),
        (
            block(&json!({"detection": {"target": "process", "criteria": []}})),
            vec![(
                "bitdefender_criterion_shape",
                path(&["detection", "criteria"]),
            )],
        ),
        (
            block(&json!({"detection": detection("connection", &json!([
                {"field": "Connection.Protocol", "is": "smb"}
            ]))})),
            vec![(
                "bitdefender_criteria_combination",
                path(&["detection", "criteria"]),
            )],
        ),
        (
            block(
                &json!({"detection": process(), "severity": "Critical", "targets": {"companies": []}}),
            ),
            vec![
                ("bitdefender_severity", path(&["severity"])),
                ("bitdefender_targets_shape", path(&["targets"])),
            ],
        ),
        (
            block(&json!({
                "detection": detection("registry", &json!([{"field": "Registry.Key", "is": "HKLM\\x"}])),
                "actions": {"isolate": true, "quarantine": true}
            })),
            vec![("bitdefender_action_scope", path(&["actions", "quarantine"]))],
        ),
    ];
    for (block, expected) in cases {
        let expected: Vec<(String, Vec<String>)> = expected
            .into_iter()
            .map(|(code, path)| (code.to_owned(), path))
            .collect();
        assert_eq!(errors(&block), expected, "{block}");
    }
}

#[test]
fn validate_reports_the_code_at_its_path_under_the_rule() {
    let block = fixture_block(INVALID[1].1);
    let mut cx = Context::new();
    cx.at_key("configurations", |cx| {
        cx.at_key("bitdefender", |cx| BitdefenderConfig::from_node(&block, cx))
    });
    let errors = cx.into_errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].code(crate::Surface::Object),
        "bitdefender_criterion_field"
    );
    assert_eq!(
        errors[0].field_path(),
        path(&[
            "configurations",
            "bitdefender",
            "detection",
            "criteria",
            "0"
        ])
    );
    assert_eq!(
        errors[0].message,
        "the field is not one of the target's in the criteria catalogue"
    );
}

#[test]
fn the_catalogue_lists_the_specification_connection_fields() {
    let connection: BTreeSet<&str> = criteria::criteria()
        .detection_fields("connection")
        .map(|field| field.name.as_str())
        .collect();
    let resources = [
        "File",
        "Application",
        "KeyVault",
        "Role",
        "Policy",
        "SharingLink",
        "Url",
        "SshKey",
        "LaunchTemplate",
        "ServicePrincipal",
        "UserGroup",
        "AutomationAccount",
        "AutomationAccountHook",
        "Api",
        "CertificateAuthority",
        "Bucket",
        "ConfluencePage",
        "JiraProject",
    ];
    let mut expected: BTreeSet<String> = resources
        .iter()
        .map(|resource| format!("Connection.{resource}.Name"))
        .collect();
    expected.extend(
        resources
            .iter()
            .chain(&["Email"])
            .map(|resource| format!("Connection.{resource}.Operation")),
    );
    expected.extend(
        [
            "Connection.SourceUser",
            "Connection.DestinationUser",
            "Connection.Email.Subject",
        ]
        .map(str::to_owned),
    );
    for name in &expected {
        assert!(connection.contains(name.as_str()), "{name}");
    }
    assert_eq!(connection.len(), 24 + expected.len());
}

#[test]
fn an_unknown_field_is_an_error_on_a_closed_target_and_a_warning_elsewhere() {
    let closed = block(
        &json!({"detection": detection("process", &json!([{"field": "Email.Sender", "is": "x"}]))}),
    );
    assert_eq!(
        errors(&closed),
        [(
            "bitdefender_criterion_field".to_owned(),
            path(&["detection", "criteria", "0"])
        )]
    );
    let open = json!({"target": "email", "criteria": [{"field": "Email.Nonexistent", "is": "x"}], "alert": "a"});
    valid(&block(&json!({"detection": open})));
    let rule = json!({"configurations": {"bitdefender": block(&json!({"detection": open}))}});
    let warned: Vec<(&str, Vec<String>)> = advisories::advisories(&json_node(&rule))
        .into_iter()
        .map(|advisory| (advisory.code, advisory.field_path))
        .collect();
    assert_eq!(
        warned,
        [(
            "bitdefender_criterion_field",
            path(&[
                "configurations",
                "bitdefender",
                "detection",
                "criteria",
                "0"
            ])
        )]
    );
}

#[test]
fn a_present_targets_key_that_is_not_a_list_never_widens_the_scope() {
    for targets in [
        json!({"endpoint_tags": null}),
        json!({"endpoint_tags": ["tier0"], "companies": null}),
        json!({"companies": "acme"}),
        json!({"endpoint_tags": []}),
        // bitdefender-1.0 (1.4): no blank alias in a block's targets.
        json!({"endpoint_tags": [" "]}),
        json!({"endpoint_tags": ["a", ""]}),
        json!({"companies": [" "]}),
        json!({"companies": ["acme", ""]}),
    ] {
        assert_eq!(
            errors(&block(&json!({"detection": process(), "targets": targets}))),
            [("bitdefender_targets_shape".to_owned(), path(&["targets"]))],
            "{targets}"
        );
    }
}

#[test]
fn a_dumped_block_validates_again() {
    let read = valid(&block(&json!({
        "detection": detection("process", &json!([{"field": "Process.Name", "any": ["a.exe"]}])),
        "targets": {"endpoint_tags": ["tier0"]},
        "actions": {"isolate": true}
    })));
    let dumped = serde_json::to_value(&read).unwrap();
    assert_eq!(dumped["targets"], json!({"endpoint_tags": ["tier0"]}));
    assert_eq!(
        dumped["detection"]["criteria"][0],
        json!({"field": "Process.Name", "any": ["a.exe"]})
    );
    assert_eq!(valid(&dumped), read);
    let pins = crate::Pins::default();
    assert!(garde::Validate::validate_with(&read, &pins).is_ok());
}

#[test]
fn garde_runs_the_named_check_on_a_block_built_in_memory() {
    let mut read = valid(&block(&json!({"detection": process()})));
    read.yara = Some(BitdefenderYara {
        signature: YARA.to_owned(),
        on_access: true,
    });
    let pins = crate::Pins::default();
    let report = garde::Validate::validate_with(&read, &pins).unwrap_err();
    assert!(
        report.to_string().contains("bitdefender_rule_kind"),
        "{report}"
    );
}

#[test]
fn the_alert_field_as_a_criterion_is_an_error_on_every_target() {
    for target in ["process", "email", "connection", "user connection"] {
        let block = block(
            &json!({"detection": detection(target, &json!([{"field": "detection", "is": "Suspicious"}]))}),
        );
        let (_, found) = read(&block);
        assert_eq!(found.len(), 1, "{target}");
        assert_eq!(
            found[0].kind,
            ErrorKind::Constraint("bitdefender_criterion_field")
        );
        assert_eq!(found[0].field_path(), path(&["detection", "criteria", "0"]));
        assert!(found[0].message.contains("alert"));
    }
}

#[test]
fn literal_true_actions_refuse_false() {
    let found = errors(&block(
        &json!({"detection": process(), "actions": {"isolate": false}}),
    ));
    assert_eq!(
        found,
        [("literal_error".to_owned(), path(&["actions", "isolate"]))]
    );
    let found = errors(&block(&json!({
        "detection": detection("file", &json!([{"field": "File.Name", "is": "a"}])),
        "actions": {"quarantine": "yes"}
    })));
    assert_eq!(
        found,
        [
            (
                "literal_error".to_owned(),
                path(&["actions", "quarantine", "literal[True]"])
            ),
            (
                "model_type".to_owned(),
                path(&["actions", "quarantine", "BitdefenderProcessScope"])
            ),
        ]
    );
}

#[test]
fn a_block_without_status_is_left_to_the_field() {
    // `status: null` skips the named check, as the oracle's before-validator does.
    let mut raw = block(&json!({}));
    raw["status"] = Json::Null;
    let found = errors(&raw);
    assert_eq!(found, [("string_type".to_owned(), path(&["status"]))]);
}

#[test]
fn names_are_normalised_and_cut() {
    assert_eq!(
        normalise("  <a> 'b' \"c\""),
        "\u{2039}a\u{203A} \u{2019}b\u{2019} \u{201D}c\u{201D}"
    );
    assert_eq!(gravityzone_name("rule", Some("")), "rule");
    assert_eq!(gravityzone_name("rule", Some("block")), "block");
    assert_eq!(
        gravityzone_name(&"é".repeat(200), None).chars().count(),
        128
    );
}

#[test]
fn the_schema_is_pydantics() {
    let schema = schemars::schema_for!(BitdefenderActions);
    let value = serde_json::to_value(&schema).unwrap();
    assert_eq!(
        value["properties"]["isolate"]["anyOf"],
        json!([{"const": true, "type": "boolean"}, {"type": "null"}])
    );
    assert_eq!(
        value["properties"]["kill_process"]["anyOf"][0],
        json!({"const": true, "type": "boolean"})
    );
    assert_eq!(
        value["properties"]["antimalware_scan"]["anyOf"][0],
        json!({"type": "string", "enum": ["quick", "full"]})
    );
    let criterion = serde_json::to_value(schemars::schema_for!(BitdefenderCriterion)).unwrap();
    assert!(criterion["properties"]["is"].is_object());
    assert!(criterion["properties"]["any"].is_object());
}
