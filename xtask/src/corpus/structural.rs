//! `corpus faults --check --engine rust --only objects` (UC-1.3, #809; the
//! `structural` subset, UC-1.2, #808): the fault kinds whose findings are the
//! object models', checked against the oracle finding for finding: code,
//! field path, message, line, columns and `yaml_line`, byte for byte.
//!
//! The Rust engine's `validate` comes with UC-2.x. Until then this is the
//! narrowest runner the items' verification needs: each object file is read
//! with `opentide_schema::node` and converted with
//! `opentide_schema::from_node` into the object model its `metadata.schema`
//! names (`opentide_schema::objects`: `rule::1.0`, `rule::1.1`,
//! `threat::1.0`, `objective::1.0`). The platform blocks under
//! `configurations` are UC-1.4's (#810): they are read unchecked, and the
//! oracle's findings inside one are left out ([`in_platform_block`]).
//!
//! This module computes; [`super::cli`] writes the workspaces and runs the
//! oracle.

use opentide_schema::Surface;
use opentide_schema::from_node;
use opentide_schema::node;
use opentide_schema::objects::{ObjectiveV1_0, RuleConfigurations, RuleV1_0, RuleV1_1, ThreatVectorV1_0};
use serde_json::{Value as Json, json};

/// The structural fault kinds of `tests/corpora/faults.toml` (UC-1.2), each
/// with what makes it structural; [`OBJECTS`] adds the object models'
/// validators. The other `schema_validation` kinds are platform blocks
/// (`sysdig-constraint-*`: UC-1.4) or configuration files (`config-*`:
/// UC-1.5); `yaml-parse-empty` is the loader's decision about an empty
/// document (UC-2.x).
pub const STRUCTURAL: &[(&str, &str)] = &[
    (
        "schema-validation-description",
        "a required field is missing",
    ),
    (
        "schema-validation-threat-impact",
        "a vocabulary list written as one string (vocab_list_type)",
    ),
    (
        "schema-validation-reviewed-on-1-0",
        "a key the revision does not declare (extra_forbidden)",
    ),
    (
        "combo-uuid-and-schema",
        "a missing field beside a workspace finding",
    ),
    (
        "yaml-parse-rule",
        "the YAML does not parse (an unclosed flow)",
    ),
    ("yaml-parse-tab", "the YAML does not parse (a tab)"),
    (
        "reviewed-impossible-date",
        "a date that cannot exist is a YAML error",
    ),
    ("lint-yaml-parse", "the YAML does not parse, under lint"),
];

/// The object fault kinds (UC-1.3): [`STRUCTURAL`], and the kinds the object
/// models' validators decide.
pub const OBJECTS: &[(&str, &str)] = &[
    (
        "schema-validation-reviewed-word",
        "`metadata.reviewed` is not a date (its validator)",
    ),
    (
        "gap-reviewed-in-future",
        "a review dated in the future: nothing to report",
    ),
];

/// The kinds `--only <group>` names: `structural` ([`STRUCTURAL`]) or
/// `objects` ([`STRUCTURAL`] and [`OBJECTS`]).
pub fn group(name: &str) -> Option<Vec<&'static str>> {
    let structural = STRUCTURAL.iter().map(|(id, _)| *id);
    match name {
        GROUP => Some(structural.collect()),
        OBJECTS_GROUP => Some(structural.chain(OBJECTS.iter().map(|(id, _)| *id)).collect()),
        _ => None,
    }
}

/// Every kind this runner checks.
pub fn kinds() -> Vec<&'static str> {
    group(OBJECTS_GROUP).unwrap_or_default()
}

/// An intended difference between the oracle and the Rust conversion on one
/// fault kind: on each target file the oracle's findings are `oracle` and the
/// Rust conversion's are `rust` (JSON, as [`oracle_findings`] and
/// [`comparable`] give them). The runner fails when an entry no longer
/// applies, and when `changelog` is not in CHANGELOG.md.
#[derive(Debug, Clone, Copy)]
pub struct Approved {
    /// The fault kind.
    pub kind: &'static str,
    /// The oracle's findings on each target.
    pub oracle: &'static str,
    /// The Rust conversion's findings on each target.
    pub rust: &'static str,
    /// Why.
    pub reason: &'static str,
    /// The bold lead of the CHANGELOG.md entry that announces it.
    pub changelog: &'static str,
}

/// The intended differences (crates/opentide-schema/YAML.md lists the YAML
/// ones case by case).
pub const APPROVED: &[Approved] = &[Approved {
    kind: "reviewed-impossible-date",
    oracle: r#"[{"code":"yaml_parse"}]"#,
    rust: REVIEWED_IMPOSSIBLE_DATE,
    reason: "YAML 1.2 has no timestamp type: `reviewed: 2026-02-30` is a string, not a \
             YAML error, and the `reviewed` field's validator refuses it as a date that \
             does not exist (crates/opentide-schema/tests/oracle/objects_cases.toml, \
             `yaml-1-2-dates`)",
    changelog: "**Tide objects are read as YAML 1.2**",
}];

/// What the Rust model reports for `reviewed: 2026-02-30` (the fault kind
/// sets it on the line after `tlp`).
const REVIEWED_IMPOSSIBLE_DATE: &str = r#"[{"code":"schema_validation","column":13,"end_column":23,"end_line":10,"field_path":["metadata","reviewed"],"line":10,"message":"Value error, metadata.reviewed is not a valid date or time: parameter 'day' with value 30 is not in the required range of 1..=28","yaml_line":9}]"#;

/// The approved difference for `kind`, if any.
pub fn approved(kind: &str) -> Option<&'static Approved> {
    APPROVED.iter().find(|approved| approved.kind == kind)
}

/// The group `--only structural` names.
pub const GROUP: &str = "structural";

/// The group `--only objects` names.
pub const OBJECTS_GROUP: &str = "objects";

/// Whether a finding's field path is inside a platform block
/// (`configurations.<platform>…`): UC-1.4's (#810), not compared yet.
pub fn in_platform_block(field_path: &[String]) -> bool {
    field_path.len() >= 2
        && field_path[0] == "configurations"
        && RuleConfigurations::PLATFORMS.contains(&field_path[1].as_str())
}

/// The findings the Rust conversion gives one object file, as the CLI's JSON
/// prints them (`code`, `field_path`, `message`, `line`, `column`,
/// `end_line`, `end_column`, `yaml_line`); a file that does not parse is one
/// `yaml_parse` finding, compared on its code. `None`: not an object file
/// this runner has a model for.
pub fn check_object(path: &str, bytes: &[u8]) -> Option<Vec<Json>> {
    let family = if path.starts_with("objects/rules/") {
        "rule"
    } else if path.starts_with("objects/threats/") {
        "threat"
    } else if path.starts_with("objects/objectives/") {
        "objective"
    } else {
        return None;
    };
    Some(check_object_as(family, bytes))
}

/// [`check_object`] for a file of `family` (`rule`, `threat`, `objective`),
/// wherever it is.
pub fn check_object_as(family: &str, bytes: &[u8]) -> Vec<Json> {
    let Ok(document) = node::load_bytes(bytes) else {
        return vec![json!({ "code": "yaml_parse" })];
    };
    let schema = document
        .root()
        .and_then(|root| root.get("metadata"))
        .and_then(|metadata| metadata.get("schema"))
        .and_then(|schema| schema.value.as_str().map(str::to_owned));
    let errors = match (family, schema.as_deref()) {
        ("rule", Some("rule::1.0")) => from_node::from_document::<RuleV1_0>(&document).err(),
        ("rule", Some("rule::1.1")) => from_node::from_document::<RuleV1_1>(&document).err(),
        ("threat", Some("threat::1.0")) => {
            from_node::from_document::<ThreatVectorV1_0>(&document).err()
        }
        ("objective", Some("objective::1.0")) => {
            from_node::from_document::<ObjectiveV1_0>(&document).err()
        }
        // A missing or unknown identifier is the workspace's finding.
        _ => return Vec::new(),
    };
    errors
            .unwrap_or_default()
            .iter()
            .map(|error| {
                let span = error.span.as_ref();
                let line = span
                    .map(|span| span.line)
                    .or(error.yaml_line.map(|line| line + 1));
                json!({
                    "code": error.code(Surface::Object),
                    "field_path": error.field_path(),
                    "message": error.message,
                    "line": line,
                    "column": span.map(|span| span.column),
                    "end_line": span.map(|span| span.end_line),
                    "end_column": span.map(|span| span.end_column),
                    "yaml_line": error.yaml_line,
                    "kind": format!("{:?}", error.kind),
                })
            })
            .collect()
}

/// The oracle's findings for `path` that the Rust conversion owns
/// (`schema_validation` and `yaml_parse`, outside the platform blocks), in
/// the fields [`check_object`] gives (a `yaml_parse` by its code alone: its message is the loader's,
/// UC-2.x).
pub fn oracle_findings(document: &Json, path: &str) -> Vec<Json> {
    let mut out = Vec::new();
    let report = document.get("report");
    let items = report
        .and_then(|report| report.get("issues"))
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .chain(
            document
                .get("findings")
                .and_then(Json::as_array)
                .into_iter()
                .flatten(),
        );
    for item in items {
        let item_path = item
            .get("path")
            .or_else(|| item.get("file"))
            .and_then(Json::as_str);
        if item_path != Some(path) {
            continue;
        }
        match item.get("code").and_then(Json::as_str) {
            Some("yaml_parse") => out.push(json!({ "code": "yaml_parse" })),
            Some("schema_validation")
                if !in_platform_block(
                    &item["field_path"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|part| part.as_str().map(str::to_owned))
                        .collect::<Vec<_>>(),
                ) =>
            {
                out.push(json!({
                "code": "schema_validation",
                "field_path": item["field_path"],
                "message": item["message"],
                "line": item["line"],
                "column": item["column"],
                "end_line": item["end_line"],
                "end_column": item["end_column"],
                "yaml_line": item.get("yaml_line").cloned().unwrap_or(Json::Null),
                }));
            }
            _ => {}
        }
    }
    out
}

/// The Rust findings without the fields the oracle does not print.
pub fn comparable(findings: &[Json]) -> Vec<Json> {
    findings
        .iter()
        .map(|finding| {
            let mut finding = finding.clone();
            if let Some(map) = finding.as_object_mut() {
                map.remove("kind");
            }
            finding
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_missing_its_description() {
        let text = "name: n\nmetadata:\n  uuid: u\n  schema: rule::1.0\n  version: 1\n  \
                    created: 2026-01-01\n  modified: 2026-01-01\n  tlp: clear\n";
        let findings = check_object("objects/rules/r.yaml", text.as_bytes()).unwrap();
        assert_eq!(
            comparable(&findings),
            [json!({
                "code": "schema_validation",
                "field_path": ["description"],
                "message": "Field required",
                "line": 1,
                "column": 1,
                "end_line": 1,
                "end_column": 5,
                "yaml_line": null,
            })]
        );
    }

    #[test]
    fn a_file_that_does_not_parse_is_yaml_parse() {
        let findings = check_object("objects/rules/r.yaml", b"a: [unclosed\n").unwrap();
        assert_eq!(findings, [json!({ "code": "yaml_parse" })]);
        assert_eq!(check_object("configurations/x.toml", b""), None);
    }

    #[test]
    fn every_approved_difference_is_a_structural_kind_with_json_sides() {
        for approved in APPROVED {
            assert!(
                STRUCTURAL.iter().any(|(id, _)| *id == approved.kind),
                "{}",
                approved.kind
            );
            for side in [approved.oracle, approved.rust] {
                assert!(serde_json::from_str::<Json>(side).is_ok(), "{side}");
            }
        }
    }

    #[test]
    fn every_structural_kind_is_in_the_catalogue() {
        let catalogue = super::super::faults::Catalogue::parse(include_str!(
            "../../../tests/corpora/faults.toml"
        ))
        .unwrap();
        for (id, _) in STRUCTURAL.iter().chain(OBJECTS) {
            assert!(catalogue.kind(id).is_some(), "{id}");
        }
    }

    #[test]
    fn groups_name_their_kinds() {
        assert_eq!(group(GROUP).unwrap().len(), STRUCTURAL.len());
        assert_eq!(
            group(OBJECTS_GROUP).unwrap().len(),
            STRUCTURAL.len() + OBJECTS.len()
        );
        assert_eq!(group("platforms"), None);
    }

    #[test]
    fn an_objective_is_checked_and_a_platform_block_is_not_compared() {
        let text = "name: n\nmetadata:\n  uuid: u\n  schema: objective::1.0\n  version: 1\n  \
                    created: '2026-01-01'\n  modified: '2026-01-01'\n  tlp: clear\n";
        let findings = check_object("objects/objectives/o.yaml", text.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["field_path"], json!(["objective"]));
        assert!(in_platform_block(&["configurations".into(), "sysdig".into()]));
        assert!(in_platform_block(&[
            "configurations".into(),
            "sentinel".into(),
            "query".into()
        ]));
        assert!(!in_platform_block(&["configurations".into()]));
        assert!(!in_platform_block(&[
            "configurations".into(),
            "unknown".into()
        ]));
        let report = json!({"report": {"issues": [
            {"path": "objects/rules/r.yaml", "code": "schema_validation", "field_path": ["configurations", "sysdig"], "message": "m"},
            {"path": "objects/rules/r.yaml", "code": "schema_validation", "field_path": ["description"], "message": "Field required"},
        ]}});
        let found = oracle_findings(&report, "objects/rules/r.yaml");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["field_path"], json!(["description"]));
    }
}
