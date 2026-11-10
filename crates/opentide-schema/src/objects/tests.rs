//! The object models' unit tests, ported from `tests/test_models/`
//! (`test_base.py`, `test_metadata.py`, `test_threat.py`,
//! `test_objective.py`, `test_rule_reviewed.py`); the oracle comparison of
//! every case is `tests/objects_table.rs`.

use garde::Validate;
use serde_json::{Value, json};

use super::*;
use crate::from_node::{self, Invalid};
use crate::node;
use crate::pins::Pins;

const RULE: &str = "name: Reviewed rule\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  \
                    schema: rule::1.1\n  version: 1\n  created: '2026-01-01'\n  \
                    modified: '2026-01-02'\n  tlp: clear\ndescription: desc\n";

fn read<T: crate::FromNode>(text: &str) -> Result<T, Vec<crate::SchemaError>> {
    from_node::from_document(&node::load(text).unwrap())
}

fn with_reviewed(value: &str) -> String {
    RULE.replace("  tlp: clear\n", &format!("  tlp: clear\n  reviewed: {value}\n"))
}

fn messages(errors: &[crate::SchemaError]) -> Vec<(String, Option<&'static str>, String)> {
    errors
        .iter()
        .map(|e| (e.field_path().join("."), e.kind.pydantic_type(), e.message.clone()))
        .collect()
}

// test_base.py

#[test]
fn a_field_carries_its_tide_keys_in_the_schema() {
    let schema = schemars::schema_for!(RuleV1_1).to_value();
    let properties = &schema["properties"];
    assert_eq!(properties["file"]["tide.template.hide"], true);
    assert_eq!(properties["description"]["tide.template.multiline"], true);
    assert_eq!(properties["response"]["tide.template.required"], true);
}

#[test]
fn each_revision_names_its_schema_identifier() {
    assert_eq!(RuleV1_0::SCHEMA_IDENTIFIER, "rule::1.0");
    assert_eq!(RuleV1_1::SCHEMA_IDENTIFIER, "rule::1.1");
    assert_eq!(ThreatVectorV1_0::SCHEMA_IDENTIFIER, "threat::1.0");
    assert_eq!(ObjectiveV1_0::SCHEMA_IDENTIFIER, "objective::1.0");
    for identifier in [
        RuleV1_0::SCHEMA_IDENTIFIER,
        RuleV1_1::SCHEMA_IDENTIFIER,
        ThreatVectorV1_0::SCHEMA_IDENTIFIER,
        ObjectiveV1_0::SCHEMA_IDENTIFIER,
    ] {
        assert!(checks::REGISTERED.contains(&identifier), "{identifier}");
    }
}

#[test]
fn field_roles_are_read_from_the_models() {
    let roles = |schema: Value| -> Vec<(String, FieldRole)> {
        role::fields_with_roles(&schema)
            .into_iter()
            .map(|(path, role)| (path.join("."), role))
            .collect()
    };
    assert_eq!(
        roles(schemars::schema_for!(RuleV1_1).to_value()),
        [
            ("configurations".to_owned(), FieldRole::Configurations),
            ("platforms".to_owned(), FieldRole::Configurations),
            ("techniques".to_owned(), FieldRole::Techniques),
        ]
    );
    assert_eq!(
        roles(schemars::schema_for!(ThreatVector).to_value()),
        [
            ("threat.actors".to_owned(), FieldRole::Actors),
            ("threat.mitre_attack".to_owned(), FieldRole::Techniques),
        ]
    );
    assert_eq!(
        roles(schemars::schema_for!(Objective).to_value()),
        [("objective.mitre_attack".to_owned(), FieldRole::Techniques)]
    );
}

// test_metadata.py

#[test]
fn public_reference_keys_are_numbers() {
    let references: ObjectReferences =
        read("public:\n  '1': ref\n  2: other\n  '+3': third\n").unwrap();
    let public = references.public.unwrap();
    assert_eq!(public[&1], "ref");
    assert_eq!(public[&2], "other");
    assert_eq!(public[&3], "third");
    let errors = read::<ObjectReferences>("public:\n  ' 4': x\n  1.5: y\n").unwrap_err();
    assert_eq!(
        messages(&errors),
        [
            (
                " 4.[key]".to_owned(),
                Some("int_parsing"),
                "Input should be a valid integer, unable to parse string as an integer".to_owned()
            ),
            (
                "1.5.[key]".to_owned(),
                Some("int_type"),
                "Input should be a valid integer".to_owned()
            ),
        ]
    );
}

#[test]
fn organisation_model() {
    let organisation: Organisation = read("uuid: u\nname: Org\n").unwrap();
    assert_eq!(organisation.name, "Org");
}

#[test]
fn the_schema_identifier_reads_by_alias_and_by_name_and_writes_as_schema() {
    for key in ["schema", "schema_id"] {
        let text = format!(
            "uuid: u\n{key}: objective::1.0\nversion: 1\ncreated: '2026-01-01'\n\
             modified: '2026-01-02'\ntlp: clear\n"
        );
        let metadata: ObjectMetadata = read(&text).unwrap();
        assert_eq!(metadata.schema_id, "objective::1.0");
        assert_eq!(metadata.schema(), "objective::1.0");
        let written = serde_json::to_value(&metadata).unwrap();
        assert_eq!(written["schema"], "objective::1.0");
        assert!(written.get("schema_id").is_none());
    }
    let schema = schemars::schema_for!(ObjectMetadata).to_value();
    assert!(schema["properties"].get("schema").is_some());
}

#[test]
fn an_unknown_schema_identifier_is_rejected() {
    let text = RULE.replace("rule::1.1", "rule:1.0");
    let errors = read::<RuleV1_1>(&text).unwrap_err();
    assert_eq!(
        messages(&errors),
        [(
            "metadata.schema".to_owned(),
            Some("value_error"),
            "Value error, unknown schema identifier: 'rule:1.0'".to_owned()
        )]
    );
}

#[test]
fn created_and_modified_are_strings() {
    let errors = read::<RuleV1_1>(&RULE.replace("'2026-01-01'", "20260101")).unwrap_err();
    assert_eq!(
        messages(&errors),
        [(
            "metadata.created".to_owned(),
            Some("string_type"),
            "Input should be a valid string".to_owned()
        )]
    );
    let rule: RuleV1_1 = read(&RULE.replace("'2026-01-01'", "2026-01-01 10:00:00")).unwrap();
    assert_eq!(rule.metadata.created, "2026-01-01 10:00:00");
}

// test_threat.py

const THREAT: &str = "name: TVM\ncriticality: High\nmetadata:\n  uuid: u\n  schema: threat::1.0\n  \
                      version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  tlp: clear\n\
                      threat:\n  description: d\n  severity: High\n  impact: [Data Breach]\n  \
                      leverage: [High]\n  viability: High\n  terrain: Endpoints.\n  \
                      surface: [OS::Windows::Desktop]\n  mitre_attack: [T1059]\n";

fn threat_with(field: &str, value: &str) -> String {
    let line = THREAT
        .lines()
        .find(|line| line.trim_start().starts_with(&format!("{field}:")))
        .map(|line| format!("{line}\n"));
    match line {
        Some(line) => THREAT.replace(&line, &format!("  {field}: {value}\n")),
        None => format!("{THREAT}  {field}: {value}\n"),
    }
}

#[test]
fn threat_vector_reads() {
    let threat: ThreatVector = read(THREAT).unwrap();
    assert_eq!(threat.threat.mitre_attack, ["T1059"]);
    assert_eq!(threat.metadata.schema_id, ThreatVectorV1_0::SCHEMA_IDENTIFIER);
}

#[test]
fn threat_actors_are_objects() {
    let text = threat_with(
        "actors",
        "\n    - name: att&ck::G0006\n      sighting: Simulated credential access.\n      \
         references: [https://attack.mitre.org/groups/G0006]",
    );
    let threat: ThreatVector = read(&text).unwrap();
    let actor = &threat.threat.actors.unwrap()[0];
    assert_eq!(actor.name, "att&ck::G0006");
    assert_eq!(actor.sighting.as_deref(), Some("Simulated credential access."));
    assert_eq!(
        actor.references.as_deref(),
        Some(&["https://attack.mitre.org/groups/G0006".to_owned()][..])
    );
    assert!(read::<ThreatVector>(&threat_with("actors", "[G0006]")).is_err());
}

#[test]
fn threat_cve_round_trips() {
    let threat: ThreatVector = read(&threat_with(
        "cve",
        "[CVE-2024-3094, GHSA-rxwq-x6h5-x525, GCVE-0-2024-3094]",
    ))
    .unwrap();
    assert_eq!(
        threat.threat.cve.unwrap(),
        ["CVE-2024-3094", "GHSA-rxwq-x6h5-x525", "GCVE-0-2024-3094"]
    );
}

#[test]
fn impact_and_leverage_keep_every_name() {
    let text = threat_with("impact", "[Data Breach, Identity Theft]");
    let text = text.replace("leverage: [High]", "leverage: [Elevation of privilege, Repudiation]");
    let threat: ThreatVector = read(&text).unwrap();
    assert_eq!(threat.threat.impact, ["Data Breach", "Identity Theft"]);
    assert_eq!(
        threat.threat.leverage,
        ["Elevation of privilege", "Repudiation"]
    );
}

#[test]
fn a_single_string_a_packed_string_an_empty_list_and_a_packed_item() {
    for field in ["impact", "leverage"] {
        let errors = read::<ThreatVector>(&threat_with(field, "Data Breach")).unwrap_err();
        assert_eq!(
            messages(&errors),
            [(
                format!("threat.{field}"),
                Some("vocab_list_type"),
                format!("must be a YAML list of {field} vocabulary names, not a single string")
            )]
        );
        let errors =
            read::<ThreatVector>(&threat_with(field, "Data Breach; Identity Theft")).unwrap_err();
        assert_eq!(
            errors[0].message,
            format!(
                "must be a YAML list of {field} vocabulary names, not a single string; list each \
                 name in 'Data Breach; Identity Theft' as its own item"
            )
        );
        let errors = read::<ThreatVector>(&threat_with(field, "[]")).unwrap_err();
        assert_eq!(
            messages(&errors),
            [(
                format!("threat.{field}"),
                Some("too_short"),
                "List should have at least 1 item after validation, not 0".to_owned()
            )]
        );
        let packed = "Elevation of privilege; Repudiation";
        let errors =
            read::<ThreatVector>(&threat_with(field, &format!("[Data Breach, '{packed}']")))
                .unwrap_err();
        assert_eq!(
            messages(&errors),
            [(
                format!("threat.{field}.1"),
                Some("vocab_packed_names"),
                format!(
                    "'{packed}' packs several vocabulary names into one string; list each name \
                     as its own item"
                )
            )]
        );
    }
}

#[test]
fn impact_and_leverage_are_non_empty_string_arrays_in_the_schema() {
    let schema = schemars::schema_for!(ThreatBody).to_value();
    for field in ["impact", "leverage"] {
        let property = &schema["properties"][field];
        assert_eq!(property["type"], "array");
        assert_eq!(property["items"], json!({"type": "string"}));
        assert_eq!(property["minItems"], 1);
        assert_eq!(property["tide.vocab"], true);
    }
}

// test_objective.py

const OBJECTIVE: &str = "name: Objective\nmetadata:\n  uuid: u\n  schema: objective::1.0\n  \
                         version: 1\n  created: '2026-01-01'\n  modified: '2026-01-02'\n  \
                         tlp: clear\nobjective:\n  priority: High\n  type: Threat\n  \
                         description: obj\n  composition:\n    strategy: synergetic\n    \
                         description: compose\n  signals:\n    - name: Signal\n      \
                         uuid: 00000000-0000-4000-8000-000000000099\n      description: sig\n      \
                         severity: Medium\n      methodology: analytics\n      entities: [host]\n      \
                         data:\n        availability: Complete\n        requirements: logs\n";

#[test]
fn detection_objective_reads() {
    let objective: Objective = read(OBJECTIVE).unwrap();
    assert_eq!(objective.objective.signals.len(), 1);
    assert_eq!(objective.objective.kind, "Threat");
    let written = serde_json::to_value(&objective).unwrap();
    assert_eq!(written["objective"]["type"], "Threat");
}

#[test]
fn a_root_composition_is_an_unknown_key() {
    let text = format!("{OBJECTIVE}composition:\n  strategy: synergetic\n  description: compose\n");
    let errors = read::<Objective>(&text).unwrap_err();
    assert_eq!(
        messages(&errors),
        [(
            "composition".to_owned(),
            Some("extra_forbidden"),
            "Extra inputs are not permitted".to_owned()
        )]
    );
}

// test_rule_reviewed.py

#[test]
fn rule_1_1_accepts_a_date_and_a_datetime() {
    let dated: RuleV1_1 = read(&with_reviewed("2026-09-01")).unwrap();
    let stamped: RuleV1_1 = read(&with_reviewed("2026-09-01T15:04:05Z")).unwrap();
    assert_eq!(dated.metadata.reviewed.as_deref(), Some("2026-09-01"));
    assert_eq!(
        stamped.metadata.reviewed.as_deref(),
        Some("2026-09-01T15:04:05Z")
    );
}

#[test]
fn rule_1_1_without_reviewed() {
    let rule: RuleV1_1 = read(RULE).unwrap();
    assert_eq!(rule.metadata.reviewed, None);
    for empty in ["''", "'   '", "null"] {
        let rule: RuleV1_1 = read(&with_reviewed(empty)).unwrap();
        assert_eq!(rule.metadata.reviewed, None, "{empty}");
    }
    let padded: RuleV1_1 = read(&with_reviewed("'  2026-09-01  '")).unwrap();
    assert_eq!(padded.metadata.reviewed.as_deref(), Some("2026-09-01"));
}

#[test]
fn rule_1_1_rejects_a_bad_review_date() {
    let errors = read::<RuleV1_1>(&with_reviewed("yesterday")).unwrap_err();
    assert_eq!(
        messages(&errors),
        [(
            "metadata.reviewed".to_owned(),
            Some("value_error"),
            "Value error, metadata.reviewed must be an ISO 8601 date (YYYY-MM-DD) or datetime"
                .to_owned()
        )]
    );
    let errors = read::<RuleV1_1>(&with_reviewed("2026-02-30")).unwrap_err();
    assert_eq!(
        messages(&errors),
        [(
            "metadata.reviewed".to_owned(),
            Some("value_error"),
            "Value error, metadata.reviewed is not a valid date or time: parameter 'day' with \
             value 30 is not in the required range of 1..=28"
                .to_owned()
        )]
    );
}

#[test]
fn rule_1_0_threat_and_objective_reject_reviewed() {
    let text = with_reviewed("2026-09-01").replace("rule::1.1", "rule::1.0");
    let errors = read::<RuleV1_0>(&text).unwrap_err();
    assert_eq!(errors[0].field_path(), ["metadata", "reviewed"]);
    assert_eq!(errors[0].kind.pydantic_type(), Some("extra_forbidden"));
    for schema in ["rule::1.0", "threat::1.0", "objective::1.0"] {
        let text = format!(
            "uuid: u\nschema: {schema}\nversion: 1\ncreated: '2026-01-01'\nmodified: '2026-01-02'\n\
             tlp: clear\nreviewed: 2026-09-01\n"
        );
        let errors = read::<ObjectMetadata>(&text).unwrap_err();
        assert_eq!(errors[0].field_path(), ["reviewed"], "{schema}");
    }
}

#[test]
fn the_schema_keeps_reviewed_on_1_1_only() {
    let current = schemars::schema_for!(RuleV1_1).to_value().to_string();
    let legacy = schemars::schema_for!(RuleV1_0).to_value().to_string();
    assert!(current.contains("reviewed"));
    assert!(!legacy.contains("reviewed"));
}

// garde: the same checks on a value built in memory.

#[test]
fn garde_runs_the_same_validators() {
    let pins = Pins::default();
    let rule: RuleV1_1 = read(&with_reviewed("2026-09-01")).unwrap();
    assert!(rule.validate_with(&pins).is_ok());
    let mut bad = rule.clone();
    bad.metadata.reviewed = Some("2026-02-30".to_owned());
    bad.metadata.schema_id = "rule::9.9".to_owned();
    let report = bad.validate_with(&pins).unwrap_err().to_string();
    assert!(report.contains("unknown schema identifier: 'rule::9.9'"), "{report}");
    assert!(report.contains("not a valid date or time"), "{report}");
    let mut untrimmed = rule;
    untrimmed.metadata.reviewed = Some(" 2026-09-01".to_owned());
    assert!(untrimmed.validate_with(&pins).is_err());

    let mut threat: ThreatVector = read(THREAT).unwrap();
    assert!(threat.validate_with(&pins).is_ok());
    threat.threat.impact = vec!["a; b".to_owned()];
    threat.threat.leverage = Vec::new();
    let report = threat.validate_with(&pins).unwrap_err().to_string();
    assert!(report.contains("packs several vocabulary names"), "{report}");
    assert!(report.contains("threat.leverage"), "{report}");
}

#[test]
fn validate_reads_then_checks() {
    let document = node::load(&with_reviewed("2026-09-01")).unwrap();
    assert!(from_node::validate::<RuleV1_1>(&document, &Pins::default()).is_ok());
    let document = node::load(&with_reviewed("never")).unwrap();
    assert!(matches!(
        from_node::validate::<RuleV1_1>(&document, &Pins::default()),
        Err(Invalid::Structure(_))
    ));
}

// The rule's helpers (`displayed_severity`, `alert_severity`).

#[test]
fn the_severity_a_page_shows() {
    let rule: RuleV1_1 = read(RULE).unwrap();
    assert_eq!(rule.displayed_severity(), None);
    assert_eq!(rule.alert_severity(), "Informational");
    let rule: RuleV1_1 = read(&format!("{RULE}severity: High\n")).unwrap();
    assert_eq!(rule.displayed_severity(), Some("High"));
    let rule: RuleV1_1 =
        read(&format!("{RULE}severity: High\nresponse:\n  playbook: p\n")).unwrap();
    assert_eq!(rule.displayed_severity(), Some("Informational"));
    let rule: RuleV1_1 =
        read(&format!("{RULE}response:\n  alert_severity: Critical\n")).unwrap();
    assert_eq!(rule.alert_severity(), "Critical");
}

#[test]
fn configurations_hold_each_block_in_order() {
    let text = format!(
        "{RULE}configurations:\n  sysdig: {{condition: x}}\n  sentinel: {{query: q}}\n"
    );
    let rule: RuleV1_1 = read(&text).unwrap();
    let configurations = rule.configurations.unwrap();
    let platforms: Vec<&str> = configurations.blocks().iter().map(|(p, _)| *p).collect();
    assert_eq!(platforms, ["sentinel", "sysdig"]);
    let errors = read::<RuleV1_1>(&format!("{RULE}configurations:\n  sentinal: {{}}\n")).unwrap_err();
    assert_eq!(errors[0].field_path(), ["configurations", "sentinal"]);
}

// Serialisation: YAML written from a model reads back the same model.

#[test]
fn a_model_round_trips_through_yaml() {
    let text = format!(
        "{RULE}techniques: [T1059]\nreferences:\n  public:\n    1: https://example.org\n\
         response:\n  procedure:\n    analysis: look\nconfigurations:\n  sentinel:\n    \
         query: |\n      SecurityEvent\n    status: STAGING\n"
    );
    let rule: RuleV1_1 = read(&text).unwrap();
    let written = node::to_yaml(&rule).unwrap();
    let again: RuleV1_1 = read(&written).unwrap();
    assert_eq!(again, rule);
    let threat: ThreatVector = read(&threat_with("killchain", "[Delivery]")).unwrap();
    let again: ThreatVector = read(&node::to_yaml(&threat).unwrap()).unwrap();
    assert_eq!(again, threat);
    let objective: Objective = read(OBJECTIVE).unwrap();
    let again: Objective = read(&node::to_yaml(&objective).unwrap()).unwrap();
    assert_eq!(again, objective);
}
