//! The Bitdefender GravityZone block (`configurations.bitdefender`,
//! bitdefender-1.0): its constraint codes and advisories, reported natively so
//! the editor and `opentide validate` agree, and completion and hover from the
//! criteria catalogue.
//!
//! The catalogue (`catalogs/bitdefender/criteria.toml`) is generated from
//! Bitdefender's "Detection and exclusion criteria for Basic rules" by
//! `scripts/sync_bitdefender_criteria.py`. The codes, their conditions and
//! their field paths follow bitdefender-1.0 "Constraints" and "Advisories", and
//! `validate_bitdefender_block` in opentidehq/specifications'
//! `scripts/object_fixtures.py`, its reference checker. As on the Sysdig block,
//! a block without `status` reports only the missing field.
//! `bitdefender_name_duplicate` is a workspace check in opentide, not here;
//! `yara.signature` is the YARA engine's (#165).

use crate::yaml_path::YamlCursor;
use opentide_core::{CompletionItem, Diagnostic, codes};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const BLOCK: [&str; 2] = ["configurations", "bitdefender"];
const KINDS: [&str; 2] = ["detection", "yara"];
const RELATIONS: [&str; 3] = ["is", "contains", "any"];
const SEVERITIES: [&str; 3] = ["Low", "Medium", "High"];
const TARGET_KEYS: [&str; 2] = ["endpoint_tags", "companies"];
const STEP_KEYS: [&str; 2] = ["include_parent", "include_children"];
const SCAN_TYPES: [&str; 2] = ["quick", "full"];
/// GravityZone's limit on `settings.yaraQuery`.
const YARA_MAX_CHARS: usize = 30_000;

/// The automatic actions, in GravityZone `type` order, with what each takes
/// and where it is allowed (bitdefender-1.0, `actions`).
pub const ACTIONS: [(&str, &str); 7] = [
    (
        "isolate",
        "Isolate the endpoint (type 1). `true`. Basic and YARA rules.",
    ),
    (
        "collect_investigation_package",
        "Collect an investigation package (type 2). `true`. Basic and YARA rules.",
    ),
    (
        "sandbox",
        "Send the file to Sandbox Analyzer (type 3). `true`. Basic rules with a `process` or `file` target or a `*.CreatedBy.*` criterion; YARA rules.",
    ),
    (
        "kill_process",
        "Kill the process (type 4). `true`, or `{include_parent, include_children}`. Basic rules with a `process` or `file` target or a `*.CreatedBy.*` criterion.",
    ),
    (
        "antimalware_scan",
        "Run an antimalware scan (type 5). `quick` or `full`. Basic and YARA rules.",
    ),
    (
        "quarantine",
        "Quarantine the file (type 6). `true`, or `{include_parent, include_children}`. As `sandbox`.",
    ),
    (
        "risk_scan",
        "Run a risk scan (type 7). `true`. Basic and YARA rules.",
    ),
];

const RELATION_DOCS: [(&str, &str); 3] = [
    (
        "is",
        "Exact match: one string or integer. Sent as `relation: \"is\"`.",
    ),
    (
        "contains",
        "Substring, with `*` and `?` wildcards: one string. Sent as `relation: \"contains\"`. Not on enumerated fields or hashes.",
    ),
    (
        "any",
        "Any of the values: a non-empty list. Sent as `relation: \"any\"`.",
    ),
];

// --------------------------------------------------------------------------
// The criteria catalogue

/// `catalogs/bitdefender/criteria.toml`.
#[derive(Debug, Deserialize)]
pub struct Criteria {
    pub source: String,
    pub fetched: String,
    #[serde(default)]
    pub registry_hives: BTreeMap<String, String>,
    pub alert: AlertRow,
    #[serde(default)]
    pub rules: Vec<RuleRow>,
    pub targets: Vec<TargetRow>,
    pub fields: Vec<FieldRow>,
}

/// The alert criterion (`detection` in criteriaList, `alert` in the block).
#[derive(Debug, Deserialize)]
pub struct AlertRow {
    pub field: String,
    pub label: String,
    pub availability: String,
    pub relations: Vec<String>,
}

/// A rule over a whole criteria list.
#[derive(Debug, Deserialize)]
pub struct RuleRow {
    /// `no_sensor_mix`, `one_resource`, or `alert_or_operation`.
    pub kind: String,
    pub target: Option<String>,
    pub field: Option<String>,
    /// `xdr` (rules an XDR sensor evaluates) or `all`.
    pub scope: Option<String>,
    /// Whether the rule needs one of `alert` and the operation, or only
    /// refuses both.
    pub require: Option<bool>,
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TargetRow {
    pub name: String,
    pub detection: bool,
    pub exclusion: bool,
    /// bitdefender-1.0 states the field list: an unknown field is an error.
    pub closed: bool,
}

#[derive(Debug, Deserialize)]
pub struct FieldRow {
    pub name: String,
    pub target: String,
    pub label: String,
    pub availability: String,
    pub exclusion_availability: Option<String>,
    pub detection: bool,
    pub exclusion: bool,
    pub relations: Vec<String>,
    /// `string`, `hash`, `ip`, `email`, `port`, or `enum`.
    pub kind: String,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
    pub resource: Option<String>,
    #[serde(default)]
    pub requires_any: Vec<String>,
    #[serde(default)]
    pub detection_requires_any: Vec<String>,
    #[serde(default)]
    pub incompatible: Vec<String>,
    #[serde(default)]
    pub values: Vec<ValueRow>,
}

#[derive(Debug, Deserialize)]
pub struct ValueRow {
    pub name: String,
    pub availability: String,
    #[serde(default)]
    pub incompatible: Vec<String>,
}

impl Criteria {
    pub fn target(&self, name: &str) -> Option<&TargetRow> {
        self.targets.iter().find(|t| t.name == name)
    }

    pub fn field(&self, name: &str) -> Option<&FieldRow> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The fields of `target` a detection rule can use, in page order.
    pub fn detection_fields<'a>(&'a self, target: &'a str) -> impl Iterator<Item = &'a FieldRow> {
        self.fields
            .iter()
            .filter(move |f| f.target == target && f.detection)
    }
}

impl FieldRow {
    pub fn value(&self, name: &str) -> Option<&ValueRow> {
        self.values.iter().find(|v| v.name == name)
    }

    fn markdown(&self) -> String {
        let mut md = format!(
            "**{}** · {} · `{}`\n\n{} · {}",
            self.name,
            self.label,
            self.target,
            kind_text(self),
            sensors(&self.availability)
        );
        md.push_str(&format!("\n\nRelations: {}", ticked(&self.relations)));
        if !self.values.is_empty() {
            let values: Vec<String> = self
                .values
                .iter()
                .map(|v| {
                    if v.availability == self.availability {
                        format!("`{}`", v.name)
                    } else {
                        format!("`{}` ({})", v.name, sensors(&v.availability))
                    }
                })
                .collect();
            md.push_str(&format!("\n\nValues: {}", values.join(", ")));
        }
        if !self.requires_any.is_empty() {
            md.push_str(&format!(
                "\n\nNeeds one of {} in the same rule.",
                ticked(&self.requires_any)
            ));
        }
        if !self.detection_requires_any.is_empty() {
            md.push_str(&format!(
                "\n\nNeeds one of {} in the same rule (`detection` is `alert`).",
                ticked(&self.detection_requires_any)
            ));
        }
        if !self.incompatible.is_empty() {
            md.push_str(&format!("\n\nNot with {}.", ticked(&self.incompatible)));
        }
        if !self.detection {
            md.push_str("\n\nExclusion rules only.");
        }
        md
    }
}

fn ticked(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn kind_text(field: &FieldRow) -> String {
    match field.kind.as_str() {
        "port" => format!(
            "integer from {} to {}",
            field.minimum.unwrap_or(0),
            field.maximum.unwrap_or(65_535)
        ),
        "hash" => "hash (no `contains`)".into(),
        "ip" => "IP address".into(),
        "email" => "email address".into(),
        "enum" => "one of its values".into(),
        _ => "string".into(),
    }
}

fn sensors(availability: &str) -> &'static str {
    match availability {
        "edr" => "EDR only",
        "xdr" => "XDR only",
        _ => "EDR and XDR",
    }
}

/// The catalogue, parsed once per process.
pub fn criteria() -> &'static Criteria {
    static CATALOG: OnceLock<Criteria> = OnceLock::new();
    CATALOG.get_or_init(|| {
        toml::from_str(include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/catalogs/bitdefender/criteria.toml"
        )))
        .expect("catalogs/bitdefender/criteria.toml")
    })
}

// --------------------------------------------------------------------------
// Constraint codes and advisories

fn full_path<'a>(path: &[&'a str]) -> Vec<&'a str> {
    let mut full: Vec<&str> = BLOCK.to_vec();
    full.extend_from_slice(path);
    full
}

fn diagnostic(
    source: &str,
    error: bool,
    code: &'static str,
    message: String,
    path: &[&str],
) -> Diagnostic {
    let full = full_path(path);
    let range = crate::elastic::path_range(source, &full);
    let d = if error {
        Diagnostic::error(code, message, range)
    } else {
        Diagnostic::warning(code, message, range)
    };
    d.with_field_path(full.iter().map(|p| p.to_string()).collect())
}

fn err(source: &str, code: &'static str, message: String, path: &[&str]) -> Diagnostic {
    diagnostic(source, true, code, message, path)
}

fn warn(source: &str, code: &'static str, message: String, path: &[&str]) -> Diagnostic {
    diagnostic(source, false, code, message, path)
}

fn set(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null)) && v.and_then(Value::as_str) != Some("")
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        _ => String::new(),
    }
}

fn scalar(v: &Value) -> bool {
    !matches!(v, Value::Sequence(_) | Value::Mapping(_) | Value::Null)
}

/// One well-shaped criterion.
struct Criterion<'a> {
    index: usize,
    field: &'a str,
    relation: &'static str,
    values: Vec<&'a Value>,
}

/// `bitdefender_criterion_shape`: the criterion, or `None` with the finding.
fn shape<'a>(
    source: &str,
    entry: &'a Value,
    index: usize,
    out: &mut Vec<Diagnostic>,
) -> Option<Criterion<'a>> {
    let at = index.to_string();
    let path = ["detection", "criteria", at.as_str()];
    let bad = |message: &str, out: &mut Vec<Diagnostic>| {
        out.push(err(
            source,
            codes::BITDEFENDER_CRITERION_SHAPE,
            message.into(),
            &path,
        ));
    };
    let Some(map) = entry.as_mapping() else {
        bad(
            "a criterion is a mapping with `field` and one of `is`, `contains`, `any`",
            out,
        );
        return None;
    };
    let Some(field) = map.get("field").and_then(Value::as_str) else {
        bad("a criterion needs a `field`", out);
        return None;
    };
    let present: Vec<&'static str> = RELATIONS
        .into_iter()
        .filter(|r| map.contains_key(*r))
        .collect();
    let unknown = map
        .keys()
        .filter_map(Value::as_str)
        .find(|k| *k != "field" && !RELATIONS.contains(k));
    if let Some(key) = unknown {
        bad(
            &format!("`{key}` is not a criterion key: `field` and one of `is`, `contains`, `any`"),
            out,
        );
        return None;
    }
    let [relation] = present.as_slice() else {
        bad(
            "a criterion has exactly one of `is`, `contains`, `any`",
            out,
        );
        return None;
    };
    let value = map.get(*relation).expect("present");
    let values: Vec<&Value> = if *relation == "any" {
        match value.as_sequence() {
            Some(items) if !items.is_empty() => items.iter().collect(),
            _ => {
                bad("`any` takes a non-empty list", out);
                return None;
            }
        }
    } else if scalar(value) {
        vec![value]
    } else {
        bad(&format!("`{relation}` takes one value"), out);
        return None;
    };
    Some(Criterion {
        index,
        field,
        relation,
        values,
    })
}

/// `bitdefender_criterion_field`, `_relation`, and `_value` for one criterion.
fn criterion_checks(
    source: &str,
    target: Option<&TargetRow>,
    c: &Criterion,
    out: &mut Vec<Diagnostic>,
) {
    let catalogue = criteria();
    let at = c.index.to_string();
    let field_path = ["detection", "criteria", at.as_str(), "field"];
    let value_path = ["detection", "criteria", at.as_str(), c.relation];
    let row = catalogue.field(c.field);
    if let Some(target) = target {
        let belongs = row.filter(|r| r.target == target.name);
        let (problem, closed) = if c.field == catalogue.alert.field {
            (
                Some(format!(
                    "`{}` is the alert criterion: set the block's `alert` instead",
                    c.field
                )),
                true,
            )
        } else {
            match belongs {
                Some(r) if r.detection => (None, target.closed),
                Some(_) => (
                    Some(format!(
                        "`{}` is a `{}` field of exclusion rules only",
                        c.field, target.name
                    )),
                    target.closed,
                ),
                None => (
                    Some(format!(
                        "`{}` is not a `{}` field in the GravityZone criteria catalogue",
                        c.field, target.name
                    )),
                    target.closed,
                ),
            }
        };
        if let Some(message) = problem {
            out.push(diagnostic(
                source,
                closed,
                codes::BITDEFENDER_CRITERION_FIELD,
                message,
                &field_path,
            ));
        }
    }
    let Some(row) = row else {
        return;
    };
    if !row.relations.iter().any(|r| r == c.relation) {
        out.push(err(
            source,
            codes::BITDEFENDER_CRITERION_RELATION,
            format!(
                "`{}` takes {}, not `{}`",
                row.name,
                ticked(&row.relations),
                c.relation
            ),
            &value_path,
        ));
    } else if row.kind == "hash" && c.relation == "contains" {
        out.push(err(
            source,
            codes::BITDEFENDER_CRITERION_RELATION,
            format!(
                "`contains` is not allowed on the hash `{}`: use `is` or `any`",
                row.name
            ),
            &value_path,
        ));
    }
    if row.kind == "enum" {
        let bad: Vec<String> = c
            .values
            .iter()
            .filter(|v| !v.as_str().is_some_and(|s| row.value(s).is_some()))
            .map(|v| text_of(v))
            .collect();
        if !bad.is_empty() {
            let names: Vec<String> = row.values.iter().map(|v| v.name.clone()).collect();
            out.push(err(
                source,
                codes::BITDEFENDER_CRITERION_VALUE,
                format!(
                    "{} is not a `{}` value: {}",
                    bad.iter()
                        .map(|b| format!("`{b}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    row.name,
                    ticked(&names)
                ),
                &value_path,
            ));
        }
    }
    if row.kind == "port" {
        let (low, high) = (row.minimum.unwrap_or(0), row.maximum.unwrap_or(65_535));
        let ok = c
            .values
            .iter()
            .all(|v| v.as_i64().is_some_and(|n| (low..=high).contains(&n)));
        if !ok {
            out.push(err(
                source,
                codes::BITDEFENDER_CRITERION_VALUE,
                format!("`{}` is a port: an integer from {low} to {high}", row.name),
                &value_path,
            ));
        }
    }
}

/// The sensors a criterion needs: a field's own, narrowed by its values.
fn criterion_sensor(row: &FieldRow, c: &Criterion) -> Vec<(String, String)> {
    let mut out = vec![(row.availability.clone(), format!("`{}`", row.name))];
    for v in &c.values {
        if let Some(value) = v.as_str().and_then(|s| row.value(s)) {
            out.push((
                value.availability.clone(),
                format!("`{}: {}`", row.name, value.name),
            ));
        }
    }
    out
}

fn is_operation(name: &str) -> bool {
    name.rsplit('.').next() == Some("Operation")
}

/// `bitdefender_criteria_combination`: the catalogue's pairing rules.
fn combination(
    source: &str,
    target: &TargetRow,
    list: &[Criterion],
    alert: bool,
    out: &mut Vec<Diagnostic>,
) {
    let catalogue = criteria();
    let report = |message: String, path: &[&str], out: &mut Vec<Diagnostic>| {
        out.push(err(
            source,
            codes::BITDEFENDER_CRITERIA_COMBINATION,
            message,
            path,
        ));
    };
    let rows: Vec<(&Criterion, &FieldRow)> = list
        .iter()
        .filter_map(|c| catalogue.field(c.field).map(|r| (c, r)))
        .collect();
    let present = |name: &str| {
        if name == catalogue.alert.field {
            alert
        } else {
            list.iter().any(|c| c.field == name)
        }
    };
    let criteria_path = ["detection", "criteria"];
    // EDR-only and XDR-only criteria do not mix.
    let mut edr = None;
    let mut xdr = None;
    for (c, row) in &rows {
        for (sensor, what) in criterion_sensor(row, c) {
            match sensor.as_str() {
                "edr" => edr = edr.or(Some(what)),
                "xdr" => xdr = xdr.or(Some(what)),
                _ => {}
            }
        }
    }
    let xdr_rule = xdr.is_some();
    if let (Some(e), Some(x)) = (&edr, &xdr) {
        report(
            format!("{e} is EDR-only and {x} XDR-only: one rule cannot use both"),
            &criteria_path,
            out,
        );
    }
    for (c, row) in &rows {
        let at = c.index.to_string();
        let field_path = ["detection", "criteria", at.as_str(), "field"];
        if !row.requires_any.is_empty() && !row.requires_any.iter().any(|n| present(n)) {
            report(
                format!(
                    "`{}` needs {} in the same rule",
                    row.name,
                    one_of(&row.requires_any)
                ),
                &field_path,
                out,
            );
        }
        if !row.detection_requires_any.is_empty()
            && !row.detection_requires_any.iter().any(|n| present(n))
        {
            let names: Vec<String> = row
                .detection_requires_any
                .iter()
                .map(|n| {
                    if *n == catalogue.alert.field {
                        "alert".to_string()
                    } else {
                        n.clone()
                    }
                })
                .collect();
            report(
                format!("`{}` needs {} in the same rule", row.name, one_of(&names)),
                &field_path,
                out,
            );
        }
    }
    // Incompatible fields, each pair once, on the later criterion.
    for (j, (cj, rj)) in rows.iter().enumerate() {
        for (ci, ri) in &rows[..j] {
            if ri.incompatible.iter().any(|n| n == cj.field)
                || rj.incompatible.iter().any(|n| n == ci.field)
            {
                let at = cj.index.to_string();
                report(
                    format!(
                        "`{}` and `{}` cannot be criteria of the same rule",
                        ci.field, cj.field
                    ),
                    &["detection", "criteria", at.as_str(), "field"],
                    out,
                );
            }
        }
    }
    // Values that exclude a field.
    for (c, row) in &rows {
        for v in &c.values {
            let Some(value) = v.as_str().and_then(|s| row.value(s)) else {
                continue;
            };
            if let Some(other) = value.incompatible.iter().find(|n| present(n)) {
                let at = c.index.to_string();
                report(
                    format!(
                        "`{}: {}` cannot be used with `{other}` in the same rule",
                        row.name, value.name
                    ),
                    &["detection", "criteria", at.as_str(), c.relation],
                    out,
                );
            }
        }
    }
    let mut both_reported = false;
    for rule in &catalogue.rules {
        match rule.kind.as_str() {
            "one_resource" if rule.targets.contains(&target.name) => {
                let mut resources: Vec<&str> = Vec::new();
                for (_, row) in &rows {
                    if let Some(r) = row.resource.as_deref() {
                        if !resources.contains(&r) {
                            resources.push(r);
                        }
                    }
                }
                if resources.len() > 1 {
                    report(
                        format!(
                            "a `{}` rule names one XDR resource, not {}",
                            target.name,
                            resources
                                .iter()
                                .map(|r| format!("`{r}`"))
                                .collect::<Vec<_>>()
                                .join(" and ")
                        ),
                        &criteria_path,
                        out,
                    );
                }
            }
            "alert_or_operation" => {
                if rule.target.as_deref().is_some_and(|t| t != target.name) {
                    continue;
                }
                if rule.scope.as_deref() == Some("xdr") && !xdr_rule {
                    continue;
                }
                let operation = match rule.field.as_deref() {
                    Some(f) => list.iter().find(|c| c.field == f),
                    None => list.iter().find(|c| is_operation(c.field)),
                };
                if alert && operation.is_some() && !both_reported {
                    both_reported = true;
                    report(
                        format!(
                            "an XDR detection uses `alert` or the `{}` criterion, not both",
                            operation.map_or("", |c| c.field)
                        ),
                        &["detection", "alert"],
                        out,
                    );
                }
                if rule.require == Some(true) && !alert && operation.is_none() {
                    let field = rule.field.as_deref().unwrap_or("operation");
                    report(
                        format!(
                            "a `{}` detection needs `alert` or a `{field}` criterion",
                            target.name
                        ),
                        &criteria_path,
                        out,
                    );
                }
            }
            _ => {}
        }
    }
}

fn one_of(names: &[String]) -> String {
    match names {
        [one] => format!("`{one}`"),
        _ => format!("one of {}", ticked(names)),
    }
}

/// `bitdefender_action_scope`.
fn actions(
    source: &str,
    block: &Value,
    kind: Option<&str>,
    target: &str,
    created_by: bool,
    out: &mut Vec<Diagnostic>,
) {
    let Some(actions) = block.get("actions").filter(|v| !v.is_null()) else {
        return;
    };
    let Some(map) = actions.as_mapping() else {
        out.push(err(
            source,
            codes::BITDEFENDER_ACTION_SCOPE,
            "`actions` is a mapping of action names to values".into(),
            &["actions"],
        ));
        return;
    };
    let process_like = matches!(target, "process" | "file") || created_by;
    for (key, value) in map {
        let name = text_of(key);
        let path = ["actions", name.as_str()];
        let mut bad = |message: String| {
            out.push(err(source, codes::BITDEFENDER_ACTION_SCOPE, message, &path));
        };
        if !ACTIONS.iter().any(|(a, _)| *a == name) {
            bad(format!(
                "`{name}` is not a GravityZone automatic action: {}",
                ACTIONS
                    .iter()
                    .map(|(a, _)| format!("`{a}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        let value_ok = match name.as_str() {
            "antimalware_scan" => value.as_str().is_some_and(|s| SCAN_TYPES.contains(&s)),
            "kill_process" | "quarantine" => match value {
                Value::Bool(true) => true,
                Value::Mapping(m) => m.iter().all(|(k, v)| {
                    k.as_str().is_some_and(|k| STEP_KEYS.contains(&k)) && v.is_bool()
                }),
                _ => false,
            },
            _ => matches!(value, Value::Bool(true)),
        };
        if !value_ok {
            bad(match name.as_str() {
                "antimalware_scan" => "`antimalware_scan` is `quick` or `full`".into(),
                "kill_process" | "quarantine" => format!(
                    "`{name}` is `true`, or `{{include_parent: bool, include_children: bool}}`"
                ),
                _ => format!("`{name}` takes `true`"),
            });
            continue;
        }
        let allowed = match name.as_str() {
            "sandbox" | "quarantine" => kind != Some("detection") || process_like,
            "kill_process" => kind == Some("detection") && process_like,
            _ => true,
        };
        if !allowed {
            bad(if kind == Some("yara") {
                format!("`{name}` is a Basic rule action: a YARA rule cannot use it")
            } else {
                format!(
                    "`{name}` needs a `process` or `file` target or a `*.CreatedBy.*` criterion"
                )
            });
        }
    }
}

/// `bitdefender_targets_shape`.
fn targets_shape(source: &str, block: &Value, out: &mut Vec<Diagnostic>) {
    let Some(targets) = block.get("targets").filter(|v| !v.is_null()) else {
        return;
    };
    let ok = targets.as_mapping().is_some_and(|m| {
        let keys: Vec<&str> = TARGET_KEYS
            .into_iter()
            .filter(|k| m.contains_key(*k))
            .collect();
        keys.len() == 1
            && m.keys()
                .all(|k| k.as_str().is_some_and(|k| TARGET_KEYS.contains(&k)))
            && m.get(keys[0])
                .and_then(Value::as_sequence)
                .is_some_and(|s| !s.is_empty())
    });
    if !ok {
        out.push(err(
            source,
            codes::BITDEFENDER_TARGETS_SHAPE,
            "`targets` sets one non-empty list: `endpoint_tags` or `companies`".into(),
            &["targets"],
        ));
    }
}

/// Every constraint code and advisory of the block. `rule` is the whole
/// object, for `response.alert_severity`.
pub(crate) fn constraint_diagnostics(source: &str, rule: &Value, block: &Value) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !set(block.get("status")) {
        return out;
    }
    let catalogue = criteria();
    let kinds: Vec<&str> = KINDS
        .into_iter()
        .filter(|k| block.get(*k).is_some())
        .collect();
    if kinds.len() != 1 {
        out.push(err(
            source,
            codes::BITDEFENDER_RULE_KIND,
            if kinds.is_empty() {
                "a Bitdefender block sets `detection` (a Basic rule) or `yara` (a YARA rule); exclusion rules are not opentide rules".into()
            } else {
                "a Bitdefender block sets exactly one of `detection` and `yara`".into()
            },
            &[],
        ));
    }
    let kind = (kinds.len() == 1).then(|| kinds[0]);
    match block.get("severity").filter(|v| !v.is_null()) {
        Some(s) if !s.as_str().is_some_and(|s| SEVERITIES.contains(&s)) => {
            out.push(err(
                source,
                codes::BITDEFENDER_SEVERITY,
                format!(
                    "`{}` is not a GravityZone severity: `Low`, `Medium`, or `High`",
                    text_of(s)
                ),
                &["severity"],
            ));
        }
        None => {
            let alert = rule
                .get("response")
                .and_then(|r| r.get("alert_severity"))
                .and_then(Value::as_str);
            if let Some(level @ ("Critical" | "Informational")) = alert {
                let sent = if level == "Critical" { "High" } else { "Low" };
                out.push(warn(
                    source,
                    codes::BITDEFENDER_SEVERITY_COLLAPSED,
                    format!(
                        "GravityZone has three severities: `response.alert_severity: {level}` is sent as `{sent}`. Set `severity` to say so"
                    ),
                    &[],
                ));
            }
        }
        _ => {}
    }
    targets_shape(source, block, &mut out);

    let mut target_name = String::new();
    let mut created_by = false;
    if let Some(detection) = block.get("detection").filter(|v| v.is_mapping()) {
        target_name = detection
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let target = catalogue.target(&target_name).filter(|t| t.detection);
        if target.is_none() {
            let exclusion = catalogue.target(&target_name).is_some();
            out.push(err(
                source,
                codes::BITDEFENDER_TARGET,
                if exclusion {
                    format!("`{target_name}` is a target of exclusion rules only")
                } else {
                    format!("`{target_name}` is not a GravityZone detection target")
                },
                &["detection", "target"],
            ));
        }
        let alert = set(detection.get("alert"));
        let mut list = Vec::new();
        let mut shaped = true;
        match detection.get("criteria").and_then(Value::as_sequence) {
            Some(entries) if !entries.is_empty() => {
                for (index, entry) in entries.iter().enumerate() {
                    match shape(source, entry, index, &mut out) {
                        Some(c) => {
                            criterion_checks(source, target, &c, &mut out);
                            created_by |= c.field.contains(".CreatedBy.");
                            list.push(c);
                        }
                        None => shaped = false,
                    }
                }
            }
            _ => {
                shaped = false;
                out.push(err(
                    source,
                    codes::BITDEFENDER_CRITERION_SHAPE,
                    "`criteria` is a non-empty list".into(),
                    &["detection", "criteria"],
                ));
            }
        }
        if let (Some(target), true) = (target, shaped) {
            combination(source, target, &list, alert, &mut out);
        }
        advisories(source, &list, &mut out);
    }
    actions(source, block, kind, &target_name, created_by, &mut out);
    if let Some(signature) = block
        .get("yara")
        .and_then(|y| y.get("signature"))
        .and_then(Value::as_str)
    {
        let path = ["yara", "signature"];
        if !signature.is_ascii() {
            out.push(err(
                source,
                codes::BITDEFENDER_YARA_ASCII,
                "GravityZone takes ASCII characters only in a YARA signature".into(),
                &path,
            ));
        }
        let count = signature.chars().count();
        if count > YARA_MAX_CHARS {
            out.push(err(
                source,
                codes::BITDEFENDER_YARA_SIZE,
                format!("the signature has {count} characters; GravityZone takes at most 30,000"),
                &path,
            ));
        }
    }
    out
}

/// `bitdefender_registry_full_hive` and `bitdefender_contains_no_wildcard`.
fn advisories(source: &str, list: &[Criterion], out: &mut Vec<Diagnostic>) {
    let hives = &criteria().registry_hives;
    for c in list {
        let at = c.index.to_string();
        let path = ["detection", "criteria", at.as_str(), c.relation];
        if c.field == "Registry.Key" {
            let full = c.values.iter().filter_map(|v| v.as_str()).find_map(|s| {
                hives.iter().find(|(name, _)| {
                    s.len() >= name.len()
                        && s[..name.len()].eq_ignore_ascii_case(name)
                        && matches!(s.as_bytes().get(name.len()), None | Some(b'\\'))
                })
            });
            if let Some((name, short)) = full {
                out.push(
                    warn(
                        source,
                        codes::BITDEFENDER_REGISTRY_FULL_HIVE,
                        format!(
                            "GravityZone never matches a key under `{name}`: write `{short}` (HKLM, HKCU, HKU, HKCR, HKCC, or HKLU)"
                        ),
                        &path,
                    )
                    .with_suggestion(short.clone()),
                );
            }
        }
        if c.relation == "contains" {
            if let Some(v) = c.values.first() {
                let text = text_of(v);
                if !text.contains(['*', '?']) {
                    out.push(warn(
                        source,
                        codes::BITDEFENDER_CONTAINS_NO_WILDCARD,
                        format!(
                            "`contains: {text}` has no `*` or `?`: GravityZone matches it as written; write `*{text}*` for a substring"
                        ),
                        &path,
                    ));
                }
            }
        }
    }
}

// --------------------------------------------------------------------------
// Completion and hover

/// The cursor's path inside the block (`detection.criteria.field`), or `None`
/// outside it.
fn block_path(cursor: &YamlCursor) -> Option<Vec<&str>> {
    let path: Vec<&str> = cursor.path.iter().map(String::as_str).collect();
    (path.len() >= 2 && path[..2] == BLOCK).then(|| path[2..].to_vec())
}

fn container(cursor: &YamlCursor) -> Option<Vec<String>> {
    let parent = cursor.container_path();
    let parts: Vec<String> = parent.split('.').map(str::to_string).collect();
    (parts.len() >= 2 && parts[0] == BLOCK[0] && parts[1] == BLOCK[1]).then(|| parts[2..].to_vec())
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The text after `key:` on a line (after an optional `- `).
fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let body = line.trim_start();
    let body = body.strip_prefix("- ").unwrap_or(body).trim_start();
    let rest = body.strip_prefix(key)?.strip_prefix(':')?;
    let rest = rest.split(" #").next().unwrap_or(rest).trim();
    Some(rest.trim_matches(['"', '\'']))
}

/// The block's `detection.target`, read from the lines, so it works while the
/// YAML around the cursor does not parse.
fn current_target(source: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with("bitdefender:") && indent(l) > 0)?;
    let base = indent(lines[start]);
    lines[start + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || indent(l) > base)
        .find_map(|l| key_value(l, "target").filter(|v| !v.is_empty()))
        .map(str::to_string)
}

/// The `field` of the list item at `offset`.
fn item_field(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    let lines: Vec<(usize, &str)> = source
        .split_inclusive('\n')
        .scan(0usize, |at, l| {
            let start = *at;
            *at += l.len();
            Some((start, l.trim_end_matches(['\n', '\r'])))
        })
        .collect();
    let here = lines
        .iter()
        .rposition(|(start, _)| *start <= offset)
        .unwrap_or(0);
    // Up to the item's dash.
    let mut first = here;
    while first > 0 && !lines[first].1.trim_start().starts_with("- ") {
        first -= 1;
    }
    let dash = indent(lines[first].1);
    let mut last = first + 1;
    while last < lines.len() {
        let l = lines[last].1;
        if !l.trim().is_empty() && (indent(l) <= dash) {
            break;
        }
        last += 1;
    }
    lines[first..last]
        .iter()
        .filter(|(_, l)| indent(l) <= dash + 2)
        .find_map(|(_, l)| key_value(l, "field").filter(|v| !v.is_empty()))
        .map(str::to_string)
}

/// The word being typed in a value: after `[`, `,` or the start.
fn value_prefix(cursor: &YamlCursor) -> String {
    let raw = cursor.value.as_deref().unwrap_or("").trim();
    let word = raw
        .rsplit(['[', ','])
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\'']);
    word.to_string()
}

fn starts(prefix: &str, candidate: &str) -> bool {
    candidate
        .to_ascii_lowercase()
        .starts_with(&prefix.to_ascii_lowercase())
}

fn target_markdown(target: &TargetRow) -> String {
    let catalogue = criteria();
    let fields: Vec<&FieldRow> = catalogue.detection_fields(&target.name).collect();
    let edr = fields.iter().any(|f| f.availability != "xdr");
    let xdr = fields.iter().any(|f| f.availability != "edr");
    let sensors = match (edr, xdr) {
        (true, true) => "EDR and XDR",
        (true, false) => "EDR",
        _ => "XDR",
    };
    format!(
        "**{}** · GravityZone detection target\n\n{} fields · {sensors}\n\nSource: [{}]({}) ({})",
        target.name,
        fields.len(),
        "Detection and exclusion criteria for Basic rules",
        catalogue.source,
        catalogue.fetched
    )
}

/// Completion inside `configurations.bitdefender`, or `None` elsewhere.
pub(crate) fn completions(
    source: &str,
    offset: usize,
    cursor: &YamlCursor,
) -> Option<Vec<CompletionItem>> {
    let catalogue = criteria();
    let on_key = cursor.on_key || cursor.value.is_none();
    if on_key || (cursor.in_list && cursor.current_key.is_none()) {
        let parent = container(cursor)?;
        let parent: Vec<&str> = parent.iter().map(String::as_str).collect();
        let prefix = if cursor.on_key {
            cursor.current_key.clone().unwrap_or_default()
        } else {
            String::new()
        };
        let existing = |name: &str| cursor.siblings.iter().any(|s| s == name && s != &prefix);
        let items: Vec<CompletionItem> = match parent.as_slice() {
            ["detection", "criteria"] => {
                let field = item_field(source, offset);
                let row = field.as_deref().and_then(|f| catalogue.field(f));
                let has_relation = RELATIONS.iter().any(|r| existing(r));
                let mut items = Vec::new();
                if !existing("field") {
                    items.push(
                        CompletionItem::new("field", "property")
                            .with_detail("string · required")
                            .with_docs("The GravityZone field API name (`Process.CommandLine`), from the criteria catalogue for the `target`."),
                    );
                }
                if !has_relation {
                    for (relation, doc) in RELATION_DOCS {
                        if row.is_some_and(|r| !r.relations.iter().any(|x| x == relation)) {
                            continue;
                        }
                        if row.is_some_and(|r| r.kind == "hash") && relation == "contains" {
                            continue;
                        }
                        items.push(
                            CompletionItem::new(relation, "property")
                                .with_detail("relation")
                                .with_docs(doc),
                        );
                    }
                }
                items
            }
            ["actions"] => ACTIONS
                .iter()
                .filter(|(a, _)| !existing(a))
                .map(|(a, doc)| {
                    CompletionItem::new(*a, "property")
                        .with_detail("automatic action")
                        .with_docs(*doc)
                })
                .collect(),
            ["actions", "kill_process" | "quarantine"] => STEP_KEYS
                .iter()
                .filter(|k| !existing(k))
                .map(|k| CompletionItem::new(*k, "property").with_detail("boolean · default false"))
                .collect(),
            _ => return None,
        };
        return Some(
            items
                .into_iter()
                .filter(|i| starts(&prefix, &i.label))
                .collect(),
        );
    }
    let path = block_path(cursor)?;
    let prefix = value_prefix(cursor);
    let items: Vec<CompletionItem> = match path.as_slice() {
        ["detection", "target"] => catalogue
            .targets
            .iter()
            .filter(|t| t.detection)
            .map(|t| {
                CompletionItem::new(t.name.clone(), "enum")
                    .with_detail("GravityZone detection target")
                    .with_docs(target_markdown(t))
            })
            .collect(),
        ["detection", "criteria", "field"] => {
            let target = current_target(source);
            catalogue
                .fields
                .iter()
                .filter(|f| f.detection)
                .filter(|f| {
                    target
                        .as_deref()
                        .is_none_or(|t| catalogue.target(t).is_none() || f.target == t)
                })
                .map(|f| {
                    CompletionItem::new(f.name.clone(), "field")
                        .with_detail(format!("{} · {}", f.label, sensors(&f.availability)))
                        .with_docs(f.markdown())
                })
                .collect()
        }
        ["detection", "criteria", "is" | "any"] => {
            let Some(row) = item_field(source, offset).and_then(|f| catalogue.field(&f)) else {
                return Some(Vec::new());
            };
            row.values
                .iter()
                .map(|v| {
                    CompletionItem::new(v.name.clone(), "enum")
                        .with_detail(format!("{} · {}", row.name, sensors(&v.availability)))
                        .with_docs(value_markdown(row, v))
                })
                .collect()
        }
        ["severity"] => SEVERITIES
            .iter()
            .map(|s| CompletionItem::new(*s, "enum").with_detail("GravityZone severity"))
            .collect(),
        ["actions", "antimalware_scan"] => SCAN_TYPES
            .iter()
            .map(|s| CompletionItem::new(*s, "enum").with_detail("scan type"))
            .collect(),
        ["actions", _] => vec![CompletionItem::new("true", "enum").with_detail("boolean")],
        _ => return None,
    };
    Some(
        items
            .into_iter()
            .filter(|i| starts(&prefix, &i.label))
            .collect(),
    )
}

fn value_markdown(row: &FieldRow, value: &ValueRow) -> String {
    let mut md = format!(
        "**{}** · `{}`\n\n{}",
        value.name,
        row.name,
        sensors(&value.availability)
    );
    if !value.incompatible.is_empty() {
        md.push_str(&format!(
            "\n\nNot with {} in the same rule.",
            ticked(&value.incompatible)
        ));
    }
    md
}

/// Hover inside `configurations.bitdefender`, or `None` when the catalogue
/// has nothing to say there.
pub(crate) fn hover(source: &str, offset: usize, cursor: &YamlCursor) -> Option<String> {
    let catalogue = criteria();
    let path = block_path(cursor)?;
    if cursor.on_key {
        return match path.as_slice() {
            [
                "detection",
                "criteria",
                relation @ ("is" | "contains" | "any"),
            ] => RELATION_DOCS
                .iter()
                .find(|(r, _)| r == relation)
                .map(|(r, doc)| format!("**{r}** · criterion relation\n\n{doc}")),
            ["actions", action] => ACTIONS
                .iter()
                .find(|(a, _)| a == action)
                .map(|(a, doc)| format!("**{a}** · automatic action\n\n{doc}")),
            _ => None,
        };
    }
    let value = cursor
        .value
        .as_deref()
        .map(|v| v.trim().trim_matches(['"', '\'']))
        .filter(|v| !v.is_empty())?;
    match path.as_slice() {
        ["detection", "target"] => catalogue.target(value).map(target_markdown),
        ["detection", "criteria", "field"] => catalogue.field(value).map(FieldRow::markdown),
        ["detection", "criteria", "is" | "any"] => {
            let row = item_field(source, offset).and_then(|f| catalogue.field(&f))?;
            let word = word_at(source, offset)?;
            row.value(&word).map(|v| value_markdown(row, v))
        }
        _ => None,
    }
}

/// The value word under the cursor (letters, digits, `_`, `/`).
fn word_at(source: &str, offset: usize) -> Option<String> {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '/');
    let offset = offset.min(source.len());
    let start = source[..offset]
        .char_indices()
        .rev()
        .take_while(|(_, c)| ok(*c))
        .last()
        .map_or(offset, |(i, _)| i);
    let end = source[offset..]
        .char_indices()
        .find(|(_, c)| !ok(*c))
        .map_or(source.len(), |(i, _)| offset + i);
    (end > start).then(|| source[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(block: &str) -> Vec<(String, String, bool)> {
        found_in(&format!("configurations:\n  bitdefender:\n{block}"))
    }

    fn found_in(source: &str) -> Vec<(String, String, bool)> {
        let object: Value = serde_yaml::from_str(source).unwrap();
        let block = &object["configurations"]["bitdefender"];
        constraint_diagnostics(source, &object, block)
            .into_iter()
            .map(|d| {
                (
                    d.code,
                    d.field_path.unwrap_or_default().join("."),
                    d.severity == opentide_core::Severity::Error,
                )
            })
            .collect()
    }

    fn codes_of(block: &str) -> Vec<String> {
        found(block).into_iter().map(|(c, _, _)| c).collect()
    }

    fn detection(criteria: &str) -> String {
        format!(
            "    status: STAGING\n    detection:\n      target: process\n      criteria:\n{criteria}"
        )
    }

    #[test]
    fn the_catalogue_loads() {
        let c = criteria();
        assert!(c.target("process").is_some_and(|t| t.closed && t.detection));
        assert!(
            c.target("flow")
                .is_some_and(|t| !t.detection && t.exclusion)
        );
        assert_eq!(
            c.field("Process.MD5").map(|f| f.kind.as_str()),
            Some("hash")
        );
        assert_eq!(
            c.registry_hives
                .get("HKEY_LOCAL_MACHINE")
                .map(String::as_str),
            Some("HKLM")
        );
    }

    #[test]
    fn the_spec_example_is_clean() {
        let block = "    status: STAGING
    tags: [office]
    targets:
      endpoint_tags: [tier0-servers]
    actions:
      kill_process: {include_children: true}
      collect_investigation_package: true
    detection:
      target: process
      criteria:
        - field: Process.Parent.Name
          any: [winword.exe, excel.exe, powerpnt.exe]
        - field: Process.Name
          is: powershell.exe
        - field: Process.CommandLine
          contains: \"*-enc*\"
";
        assert!(found(block).is_empty(), "{:?}", found(block));
    }

    #[test]
    fn no_status_reports_nothing_here() {
        assert!(codes_of("    detection:\n      target: nope\n").is_empty());
    }

    #[test]
    fn rule_kind_severity_and_targets() {
        assert_eq!(
            codes_of("    status: STAGING\n    exclusion:\n      target: process\n"),
            ["bitdefender_rule_kind"]
        );
        let both = "    status: STAGING
    severity: Critical
    targets:
      endpoint_tags: [a]
      companies: [b]
    detection:
      target: process
      criteria:
      - field: Process.Name
        is: a
    yara:
      signature: 'rule A { condition: true }'
";
        assert_eq!(
            found(both),
            [
                (
                    "bitdefender_rule_kind".into(),
                    "configurations.bitdefender".into(),
                    true
                ),
                (
                    "bitdefender_severity".into(),
                    "configurations.bitdefender.severity".into(),
                    true
                ),
                (
                    "bitdefender_targets_shape".into(),
                    "configurations.bitdefender.targets".into(),
                    true
                ),
            ]
        );
        assert_eq!(
            codes_of(
                "    status: STAGING\n    targets:\n      endpoint_tags: []\n    yara:\n      signature: x\n"
            ),
            ["bitdefender_targets_shape"]
        );
    }

    #[test]
    fn targets_and_shapes() {
        assert_eq!(
            found(
                "    status: STAGING\n    detection:\n      target: flow\n      criteria:\n      - field: Flow.Name\n        is: a\n"
            ),
            [(
                "bitdefender_target".into(),
                "configurations.bitdefender.detection.target".into(),
                true
            )]
        );
        assert_eq!(
            codes_of(&detection(
                "      - field: Process.Name\n        is: a\n        any: [b]\n"
            )),
            ["bitdefender_criterion_shape"]
        );
        assert_eq!(
            codes_of(&detection("      - field: Process.Name\n        any: []\n")),
            ["bitdefender_criterion_shape"]
        );
        assert_eq!(
            codes_of(&detection("      - field: Process.Name\n        is: [a]\n")),
            ["bitdefender_criterion_shape"]
        );
        assert_eq!(
            codes_of(
                "    status: STAGING\n    detection:\n      target: process\n      criteria: []\n"
            ),
            ["bitdefender_criterion_shape"]
        );
    }

    #[test]
    fn fields_are_errors_on_closed_targets_and_warnings_elsewhere() {
        assert_eq!(
            found(&detection(
                "      - field: Process.Hash\n        is: 44d88612fea8a8f36de82e1278abb02f\n"
            )),
            [(
                "bitdefender_criterion_field".into(),
                "configurations.bitdefender.detection.criteria.0.field".into(),
                true
            )]
        );
        let open = "    status: STAGING
    detection:
      target: role
      alert: Suspicious role assignment
      criteria:
      - field: Role.Colour
        is: red
";
        assert_eq!(
            found(open),
            [(
                "bitdefender_criterion_field".into(),
                "configurations.bitdefender.detection.criteria.0.field".into(),
                false
            )]
        );
        // An exclusion-only field of a closed target.
        assert_eq!(
            codes_of(
                "    status: STAGING\n    detection:\n      target: connection\n      criteria:\n      - field: Connection.Flow.Name\n        is: a\n"
            ),
            ["bitdefender_criterion_field"]
        );
    }

    #[test]
    fn relations_and_values() {
        assert_eq!(
            codes_of(&detection(
                "      - field: Process.MD5\n        contains: \"*abc*\"\n"
            )),
            ["bitdefender_criterion_relation"]
        );
        let registry = |c: &str| {
            format!(
                "    status: STAGING\n    detection:\n      target: registry\n      criteria:\n{c}"
            )
        };
        assert_eq!(
            codes_of(&registry(
                "      - field: Registry.Operation\n        contains: \"*key*\"\n"
            )),
            // As the reference checker: the relation and the value are both wrong.
            [
                "bitdefender_criterion_relation",
                "bitdefender_criterion_value"
            ]
        );
        // Registry.DataType takes `is` only; and needs no partner.
        assert_eq!(
            codes_of(&registry(
                "      - field: Registry.DataType\n        any: [dword]\n"
            )),
            ["bitdefender_criterion_relation"]
        );
        assert_eq!(
            codes_of(&registry(
                "      - field: Registry.Operation\n        any: [key_created, key_moved]\n"
            )),
            ["bitdefender_criterion_value"]
        );
        let connection = |c: &str| {
            format!(
                "    status: STAGING\n    detection:\n      target: connection\n      criteria:\n{c}"
            )
        };
        assert_eq!(
            codes_of(&connection(
                "      - field: Connection.DestinationPort\n        any: [443, 70000]\n"
            )),
            ["bitdefender_criterion_value"]
        );
        assert!(
            codes_of(&connection(
                "      - field: Connection.DestinationPort\n        is: 4444\n"
            ))
            .is_empty()
        );
    }

    #[test]
    fn pairing_rules() {
        let file = |c: &str| {
            format!("    status: STAGING\n    detection:\n      target: file\n      criteria:\n{c}")
        };
        // File.Certificate* needs File.Name or File.FullPathName.
        assert_eq!(
            found(&file(
                "      - field: File.CertificateSigner\n        is: Contoso\n"
            )),
            [(
                "bitdefender_criteria_combination".into(),
                "configurations.bitdefender.detection.criteria.0.field".into(),
                true
            )]
        );
        assert!(codes_of(&file("      - field: File.Name\n        is: a.exe\n      - field: File.CertificateSigner\n        is: Contoso\n")).is_empty());
        // is_unsigned is not used with a signer.
        assert_eq!(
            codes_of(&file(
                "      - field: File.Name\n        is: a.exe\n      - field: File.CertificateSigner\n        is: Contoso\n      - field: File.CertificateSignedStatus\n        is: is_unsigned\n"
            )),
            ["bitdefender_criteria_combination"]
        );
        // EDR-only (File.CreatedBy.Name) and XDR-only (File.MD5) do not mix.
        assert_eq!(
            codes_of(&file(
                "      - field: File.CreatedBy.Name\n        is: a.exe\n      - field: File.MD5\n        is: 44d88612fea8a8f36de82e1278abb02f\n"
            )),
            [
                "bitdefender_criteria_combination",
                "bitdefender_criteria_combination"
            ]
        );
        // A value narrows the sensor: `rename` is EDR-only, `uploaded` XDR-only.
        assert_eq!(
            codes_of(&file(
                "      - field: File.Operation\n        any: [rename, uploaded]\n"
            )),
            ["bitdefender_criteria_combination"]
        );
        let connection = |c: &str| {
            format!(
                "    status: STAGING\n    detection:\n      target: connection\n      criteria:\n{c}"
            )
        };
        // Connection.Protocol needs Connection.Domain (and Domain needs Protocol).
        assert_eq!(
            codes_of(&connection(
                "      - field: Connection.Protocol\n        is: smb\n"
            )),
            ["bitdefender_criteria_combination"]
        );
        assert!(codes_of(&connection("      - field: Connection.Domain\n        is: example.com\n      - field: Connection.Protocol\n        is: smb\n")).is_empty());
        // smb is not used with an HTTP field.
        assert_eq!(
            codes_of(&connection(
                "      - field: Connection.Domain\n        is: example.com\n      - field: Connection.Protocol\n        is: smb\n      - field: Connection.HTTPUser\n        is: bob\n"
            )),
            ["bitdefender_criteria_combination"]
        );
        // Incompatible Connection.* pair.
        assert_eq!(
            found(&connection(
                "      - field: Connection.URL\n        is: http://a\n      - field: Connection.SSHUser\n        is: root\n"
            )),
            [(
                "bitdefender_criteria_combination".into(),
                "configurations.bitdefender.detection.criteria.1.field".into(),
                true
            )]
        );
        // One XDR resource per connection rule; an XDR detection uses alert or an operation, not both.
        let xdr = "    status: STAGING
    detection:
      target: connection
      alert: Data exfiltration
      criteria:
      - field: Connection.File.Name
        is: secrets.zip
      - field: Connection.File.Operation
        is: uploaded
      - field: Connection.Email.Subject
        contains: '*invoice*'
";
        assert_eq!(
            found(xdr)
                .into_iter()
                .map(|(c, p, _)| (c, p))
                .collect::<Vec<_>>(),
            [
                (
                    "bitdefender_criteria_combination".to_string(),
                    "configurations.bitdefender.detection.criteria".to_string()
                ),
                (
                    "bitdefender_criteria_combination".to_string(),
                    "configurations.bitdefender.detection.alert".to_string()
                ),
            ]
        );
        // An XDR-only target needs alert or its operation.
        let role = "    status: STAGING
    detection:
      target: role
      criteria:
      - field: Role.Name
        is: Owner
";
        assert_eq!(codes_of(role), ["bitdefender_criteria_combination"]);
        assert!(
            codes_of(&role.replace(
                "      criteria:",
                "      alert: Role granted\n      criteria:"
            ))
            .is_empty()
        );
    }

    #[test]
    fn action_scope() {
        let yara = "    status: STAGING
    actions:
      kill_process: true
      quarantine: true
      antimalware_scan: deep
      reboot: true
    yara:
      signature: 'rule A { condition: true }'
";
        assert_eq!(
            found(yara)
                .into_iter()
                .map(|(_, p, _)| p)
                .collect::<Vec<_>>(),
            [
                "configurations.bitdefender.actions.kill_process",
                "configurations.bitdefender.actions.antimalware_scan",
                "configurations.bitdefender.actions.reboot",
            ]
        );
        let registry = "    status: STAGING
    actions:
      sandbox: true
      isolate: true
    detection:
      target: registry
      criteria:
      - field: Registry.Key
        is: HKLM\\Software\\Run
";
        assert_eq!(codes_of(registry), ["bitdefender_action_scope"]);
        // A *.CreatedBy.* criterion makes a registry rule process-like.
        assert!(
            codes_of(&format!(
                "{registry}      - field: Registry.CreatedBy.Name\n        is: reg.exe\n"
            ))
            .is_empty()
        );
    }

    #[test]
    fn yara_ascii_and_size() {
        assert_eq!(
            codes_of(
                "    status: STAGING\n    yara:\n      signature: 'rule Ä { condition: true }'\n"
            ),
            ["bitdefender_yara_ascii"]
        );
        let long = format!(
            "    status: STAGING\n    yara:\n      signature: '{}'\n",
            "a".repeat(30_001)
        );
        assert_eq!(codes_of(&long), ["bitdefender_yara_size"]);
    }

    #[test]
    fn advisories_are_warnings() {
        let source = "response:
  alert_severity: Critical
configurations:
  bitdefender:
    status: STAGING
    detection:
      target: registry
      criteria:
      - field: Registry.Key
        is: HKEY_LOCAL_MACHINE\\Software\\Run
      - field: Registry.Value
        contains: Updater
";
        assert_eq!(
            found_in(source),
            [
                (
                    "bitdefender_severity_collapsed".into(),
                    "configurations.bitdefender".into(),
                    false
                ),
                (
                    "bitdefender_registry_full_hive".into(),
                    "configurations.bitdefender.detection.criteria.0.is".into(),
                    false
                ),
                (
                    "bitdefender_contains_no_wildcard".into(),
                    "configurations.bitdefender.detection.criteria.1.contains".into(),
                    false
                ),
            ]
        );
        assert!(
            found_in(&source.replace(
                "    status: STAGING",
                "    status: STAGING\n    severity: High"
            ))
            .iter()
            .all(|(c, _, _)| c != "bitdefender_severity_collapsed")
        );
    }

    fn complete(source: &str, at: &str) -> Vec<String> {
        let offset = source.find(at).unwrap() + at.len();
        let cursor = crate::yaml_path::yaml_cursor(source, offset);
        completions(source, offset, &cursor)
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.label)
            .collect()
    }

    #[test]
    fn completion_follows_the_target_and_the_field() {
        let source = "configurations:
  bitdefender:
    status: STAGING
    actions:
      kill_process: true
      iso
    detection:
      target: reg
      criteria:
      - field: Registry.Op
        an
      - field: Registry.Operation
        any: [key_cr
";
        assert_eq!(complete(source, "target: reg"), ["registry"]);
        let fields = complete(source, "field: Registry.Op");
        assert_eq!(fields, ["Registry.Operation"]);
        assert_eq!(complete(source, "any: [key_cr"), ["key_created"]);
        assert_eq!(complete(source, "\n        an"), ["any"]);
        assert_eq!(complete(source, "      iso"), ["isolate"]);
    }

    #[test]
    fn hover_names_fields_and_values() {
        let source = "configurations:
  bitdefender:
    status: STAGING
    detection:
      target: registry
      criteria:
      - field: Registry.DataType
        is: dword
";
        let at = |needle: &str| {
            let offset = source.find(needle).unwrap() + 1;
            let cursor = crate::yaml_path::yaml_cursor(source, offset);
            hover(source, offset, &cursor).unwrap_or_default()
        };
        assert!(
            at("Registry.DataType").contains("Registry type"),
            "{}",
            at("Registry.DataType")
        );
        assert!(at("dword").contains("**dword**"), "{}", at("dword"));
        assert!(at("registry\n").contains("GravityZone detection target"));
        assert!(at("is: dword").contains("Exact match"));
    }
}
