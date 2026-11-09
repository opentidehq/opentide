//! `corpus faults --check --engine rust --only structural` (UC-1.2, #808): the
//! fault kinds whose findings are the object model's structural errors,
//! checked against the oracle finding for finding: code, field path, message,
//! line, columns and `yaml_line`, byte for byte.
//!
//! The Rust engine's `validate` comes with UC-2.x. Until then this is the
//! narrowest runner the item's verification needs: each object file is read
//! with `opentide_schema::node` and converted with
//! `opentide_schema::from_node`, into the stand-in models below. They are the
//! oracle's `rule::1.0`, `rule::1.1` and `threat::1.0` field for field (names,
//! aliases, defaults, closure, the `mode="before"` validators that shape the
//! value), down to the blocks other items port: the platform blocks
//! (`configurations`, UC-1.4), `response` and `references.public` are taken
//! unchecked. UC-1.3 (#809) replaces them with the real models in
//! `opentide-schema`.
//!
//! This module computes; [`super::cli`] writes the workspaces and runs the
//! oracle.

use std::collections::BTreeMap;
use std::sync::Arc;

use opentide_schema::FromNode;
use opentide_schema::Surface;
use opentide_schema::from_node::{self, Context};
use opentide_schema::node::{self, Node, Value};
use serde_json::{Value as Json, json};

/// The fault kinds of `tests/corpora/faults.toml` this runner checks, each
/// with what makes it structural. The other `schema_validation` kinds are
/// constraints and validators (`sysdig-constraint-*`: UC-1.4;
/// `schema-validation-reviewed-word`: UC-1.3) or configuration files
/// (`config-*`: UC-1.5); `yaml-parse-empty` is the loader's decision about an
/// empty document (UC-2.x).
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
    rust: "[]",
    reason: "YAML 1.2 has no timestamp type: `reviewed: 2026-02-30` is a string, not a \
             YAML error. Checking that the date exists is the `reviewed` field's own \
             validator, which arrives with the real models (UC-1.3, #809); this runner's \
             stand-in model has none",
    changelog: "**Tide objects are read as YAML 1.2**",
}];

/// The approved difference for `kind`, if any.
pub fn approved(kind: &str) -> Option<&'static Approved> {
    APPROVED.iter().find(|approved| approved.kind == kind)
}

/// Whether `--only` names the structural group.
pub const GROUP: &str = "structural";

/// `metadata.reviewed` (`_coerce_reviewed`, a model validator UC-1.3 brings
/// over): `null` stays `None`, a string is trimmed and an empty one is `None`.
#[expect(
    clippy::option_option,
    reason = "the conversion's Option (it converted) around the field's Option (`None` or a text)"
)]
fn reviewed(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    match &node.value {
        Value::Null => Some(None),
        Value::Str(text) => {
            let text = text.trim();
            Some((!text.is_empty()).then(|| text.to_owned()))
        }
        _ => String::from_node(node, cx).map(Some),
    }
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct Organisation {
    uuid: String,
    name: String,
}

#[derive(Debug, FromNode)]
#[from_node(union)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
enum StrOrInt {
    #[from_node(tag = "str")]
    Str(String),
    #[from_node(tag = "int")]
    Int(i64),
}

#[derive(Debug, FromNode)]
#[from_node(union)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
enum StrOrList {
    #[from_node(tag = "str")]
    Str(String),
    #[from_node(tag = "list[str]")]
    List(Vec<String>),
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct ObjectMetadata {
    uuid: String,
    #[serde(rename = "schema", alias = "schema_id")]
    schema_id: String,
    version: StrOrInt,
    created: String,
    modified: String,
    tlp: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    contributors: Option<Vec<String>>,
    #[serde(default)]
    organisation: Option<Organisation>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct RuleMetadata {
    uuid: String,
    #[serde(rename = "schema", alias = "schema_id")]
    schema_id: String,
    version: StrOrInt,
    created: String,
    modified: String,
    tlp: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    contributors: Option<Vec<String>>,
    #[serde(default)]
    organisation: Option<Organisation>,
    #[serde(default)]
    #[from_node(with = "reviewed")]
    reviewed: Option<String>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct ObjectReferences {
    /// `coerce_public_keys` turns the keys into integers first: UC-1.3.
    #[serde(default)]
    public: Option<Arc<Node>>,
    #[serde(default)]
    internal: Option<BTreeMap<String, String>>,
    #[serde(default)]
    reports: Option<Vec<String>>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct ThreatActor {
    name: String,
    #[serde(default)]
    sighting: Option<String>,
    #[serde(default)]
    references: Option<Vec<String>>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct ThreatBody {
    description: String,
    severity: String,
    #[from_node(before = "from_node::require_vocab_list")]
    impact: Vec<String>,
    #[from_node(before = "from_node::require_vocab_list")]
    leverage: Vec<String>,
    viability: String,
    terrain: String,
    surface: Vec<String>,
    mitre_attack: Vec<String>,
    #[serde(default)]
    actors: Option<Vec<ThreatActor>>,
    #[serde(default)]
    killchain: Option<StrOrList>,
    #[serde(default)]
    chaining: Option<Vec<BTreeMap<String, String>>>,
    #[serde(default)]
    cve: Option<Vec<String>>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct ThreatVector {
    name: String,
    criticality: String,
    metadata: ObjectMetadata,
    threat: ThreatBody,
    #[serde(default)]
    references: Option<ObjectReferences>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[from_node(model = "DetectionRule")]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct RuleV1_0 {
    name: String,
    metadata: ObjectMetadata,
    description: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    techniques: Vec<String>,
    #[serde(default)]
    platforms: BTreeMap<String, BTreeMap<String, Arc<Node>>>,
    #[serde(default)]
    references: Option<ObjectReferences>,
    #[serde(default)]
    detection_model: Option<String>,
    /// `RuleResponse`: UC-1.3.
    #[serde(default)]
    response: Option<Arc<Node>>,
    /// The platform blocks: UC-1.4.
    #[serde(default)]
    configurations: Option<Arc<Node>>,
    #[serde(default)]
    file: Option<String>,
}

#[derive(Debug, FromNode)]
#[serde(deny_unknown_fields)]
#[from_node(model = "DetectionRule_v1_1")]
#[expect(dead_code, reason = "a stand-in model: only its conversion is used")]
struct RuleV1_1 {
    name: String,
    metadata: RuleMetadata,
    description: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    techniques: Vec<String>,
    #[serde(default)]
    platforms: BTreeMap<String, BTreeMap<String, Arc<Node>>>,
    #[serde(default)]
    references: Option<ObjectReferences>,
    #[serde(default)]
    detection_model: Option<String>,
    #[serde(default)]
    response: Option<Arc<Node>>,
    #[serde(default)]
    configurations: Option<Arc<Node>>,
    #[serde(default)]
    file: Option<String>,
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
    } else {
        return None;
    };
    let Ok(document) = node::load_bytes(bytes) else {
        return Some(vec![json!({ "code": "yaml_parse" })]);
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
            from_node::from_document::<ThreatVector>(&document).err()
        }
        // A missing or unknown identifier is the workspace's finding.
        _ => return Some(Vec::new()),
    };
    Some(
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
            .collect(),
    )
}

/// The oracle's findings for `path` that the Rust conversion owns
/// (`schema_validation` and `yaml_parse`), in the fields [`check_object`]
/// gives (a `yaml_parse` by its code alone: its message is the loader's,
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
            Some("schema_validation") => out.push(json!({
                "code": "schema_validation",
                "field_path": item["field_path"],
                "message": item["message"],
                "line": item["line"],
                "column": item["column"],
                "end_line": item["end_line"],
                "end_column": item["end_column"],
                "yaml_line": item.get("yaml_line").cloned().unwrap_or(Json::Null),
            })),
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
        for (id, _) in STRUCTURAL {
            assert!(catalogue.kind(id).is_some(), "{id}");
        }
    }
}
