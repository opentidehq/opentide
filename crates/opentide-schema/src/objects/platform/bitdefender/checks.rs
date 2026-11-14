//! The named check `bitdefender_rule_shape`: every bitdefender-1.0
//! constraint finding of a block, as authored, at the `field_path` the spec
//! fixes for it, relative to the block (0.28.0's
//! `platforms/bitdefender/catalog.py`, `block_findings`).
//!
//! The catalogue ([`super::criteria`]) covers the EDR targets; a field of
//! another target is not checked here, because the spec makes an unknown
//! field there a warning ([`unknown_field_paths`], reported by
//! [`super::advisories`]).

use std::collections::{BTreeSet, HashMap};

use crate::error::{ErrorKind, PathSegment};
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::platform::python_strip;

use super::criteria::{Criteria, FieldRow, criteria};
use super::{ACTION_TYPES, NOT_ON_YARA, PROCESS_ACTIONS};

/// `bitdefender_rule_kind`.
pub const RULE_KIND: &str = "bitdefender_rule_kind";
/// `bitdefender_target`.
pub const TARGET: &str = "bitdefender_target";
/// `bitdefender_criterion_shape`.
pub const CRITERION_SHAPE: &str = "bitdefender_criterion_shape";
/// `bitdefender_criterion_field`.
pub const CRITERION_FIELD: &str = "bitdefender_criterion_field";
/// `bitdefender_criterion_relation`.
pub const CRITERION_RELATION: &str = "bitdefender_criterion_relation";
/// `bitdefender_criterion_value`.
pub const CRITERION_VALUE: &str = "bitdefender_criterion_value";
/// `bitdefender_criteria_combination`.
pub const CRITERIA_COMBINATION: &str = "bitdefender_criteria_combination";
/// `bitdefender_action_scope`.
pub const ACTION_SCOPE: &str = "bitdefender_action_scope";
/// `bitdefender_targets_shape`.
pub const TARGETS_SHAPE: &str = "bitdefender_targets_shape";
/// `bitdefender_severity`.
pub const SEVERITY: &str = "bitdefender_severity";
/// `yara_empty_signature`, on a signature with no text: the YARA engine
/// reports it on one it can read (a blank scalar is no injection).
pub const EMPTY_SIGNATURE: &str = opentide_core::codes::YARA_EMPTY_SIGNATURE;
/// `yara_signature_alias` ([`signature_aliases`]).
pub const SIGNATURE_ALIAS: &str = opentide_core::codes::YARA_SIGNATURE_ALIAS;

/// What each constraint code says, for the finding's message
/// (bitdefender-1.0, Constraints; `CODE_MESSAGES`).
pub const CODE_MESSAGES: [(&str, &str); 11] = [
    (
        RULE_KIND,
        "a Bitdefender block sets exactly one of detection and yara",
    ),
    (TARGET, "target is not a GravityZone detection target"),
    (
        CRITERION_SHAPE,
        "a criterion has field and exactly one of is (a string or an integer), contains (a \
         string) and any (a non-empty list of strings or integers)",
    ),
    (
        CRITERION_FIELD,
        "the field is not one of the target's in the criteria catalogue",
    ),
    (CRITERION_RELATION, "the field does not take this relation"),
    (CRITERION_VALUE, "the value is not one the field accepts"),
    (
        CRITERIA_COMBINATION,
        "the criteria break a pairing rule of the catalogue",
    ),
    (
        ACTION_SCOPE,
        "the action is not allowed for the rule's kind and target",
    ),
    (
        TARGETS_SHAPE,
        "targets sets one of endpoint_tags and companies, non-empty",
    ),
    (SEVERITY, "severity is Low, Medium or High"),
    (
        EMPTY_SIGNATURE,
        "the YARA signature has no rule that is neither private nor global",
    ),
];

/// The alert criterion's API field: the block writes it as `alert`.
pub const ALERT_FIELD: &str = "detection";

/// The message of a criterion on the alert field.
pub const ALERT_MESSAGE: &str = "the alert filter is not a criterion: write it as the block's \
                                 detection.alert, which deploy sends as filters";

/// The relations a criterion uses, in their order.
pub const RELATIONS: [&str; 3] = ["is", "contains", "any"];

/// The block's severities.
pub const SEVERITIES: [&str; 3] = ["Low", "Medium", "High"];

/// A finding: its code, the path it is reported at relative to
/// `configurations.bitdefender`, and a message when the code's own does not
/// say enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code.
    pub code: &'static str,
    /// The path, relative to the block.
    pub path: Vec<PathSegment>,
    /// The message, when not the code's.
    pub message: Option<&'static str>,
}

impl Finding {
    fn new(code: &'static str, path: Vec<PathSegment>) -> Self {
        Self {
            code,
            path,
            message: None,
        }
    }

    /// The finding's message: its own, else its code's.
    pub fn text(&self) -> &'static str {
        self.message.unwrap_or_else(|| message(self.code))
    }

    /// The path as the CLI's `field_path` parts.
    pub fn field_path(&self) -> Vec<String> {
        self.path.iter().map(ToString::to_string).collect()
    }

    /// Reports the finding on the block `block` (the context is at the
    /// block): one error of the code's own type, at its path.
    pub(crate) fn report(&self, block: &Node, cx: &mut Context) {
        fn at(cx: &mut Context, path: &[PathSegment], f: &mut dyn FnMut(&mut Context)) {
            match path.split_first() {
                None => f(cx),
                Some((segment, rest)) => cx.at(segment.clone(), |cx| at(cx, rest, f)),
            }
        }
        let text = self.text();
        at(cx, &self.path, &mut |cx| {
            cx.error(ErrorKind::Constraint(self.code), text, block);
        });
    }
}

/// The message of a constraint code.
pub fn message(code: &str) -> &'static str {
    CODE_MESSAGES
        .iter()
        .find(|(known, _)| *known == code)
        .map_or("", |(_, text)| *text)
}

fn key(name: &str) -> PathSegment {
    PathSegment::Key(name.to_owned())
}

fn criteria_path() -> Vec<PathSegment> {
    vec![key("detection"), key("criteria")]
}

fn criterion_path(index: usize) -> Vec<PathSegment> {
    vec![key("detection"), key("criteria"), PathSegment::Index(index)]
}

fn get<'n>(node: &'n Node, name: &str) -> Option<&'n Node> {
    node.get(name).map(AsRef::as_ref)
}

/// `raw.get(key)` with a `null` read as absent.
fn set<'n>(node: &'n Node, name: &str) -> Option<&'n Node> {
    get(node, name).filter(|value| !matches!(value.value, Value::Null))
}

/// A string or an integer: a boolean is neither (`_scalar`).
fn scalar(node: &Node) -> bool {
    matches!(node.value, Value::Str(_) | Value::Int(_))
}

/// A scalar's text, as Python's `str()` writes it.
fn scalar_text(node: &Node) -> Option<String> {
    match &node.value {
        Value::Str(text) => Some(text.clone()),
        Value::Int(integer) => Some(integer.to_string()),
        _ => None,
    }
}

/// The keys of a mapping, in order; a key that is not a string is `None`.
fn keys(node: &Node) -> Vec<Option<&str>> {
    match &node.value {
        Value::Map(entries) => entries
            .iter()
            .map(|entry| entry.key.value.as_str())
            .collect(),
        _ => Vec::new(),
    }
}

fn has(node: &Node, name: &str) -> bool {
    keys(node).contains(&Some(name))
}

/// The relation a well-shaped criterion uses (`_relation`).
fn relation(criterion: &Node) -> &'static str {
    RELATIONS
        .iter()
        .copied()
        .find(|name| has(criterion, name))
        .unwrap_or("is")
}

/// The values of a well-shaped criterion (`_values`): its list for `any`,
/// else its one value.
fn values(criterion: &Node) -> Vec<&Node> {
    let relation = relation(criterion);
    match get(criterion, relation) {
        Some(Node {
            value: Value::Seq(items),
            ..
        }) if relation == "any" => items.iter().map(AsRef::as_ref).collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    }
}

/// A criterion's `field`, which a well-shaped criterion has.
fn field_name(criterion: &Node) -> &str {
    get(criterion, "field")
        .and_then(|field| field.value.as_str())
        .unwrap_or_default()
}

/// `field` and one relation: `is` a string or integer, `contains` a string,
/// `any` a non-empty list of strings or integers (`_criterion_shape_ok`).
pub fn criterion_shape_ok(criterion: &Node) -> bool {
    if !matches!(criterion.value, Value::Map(_))
        || get(criterion, "field")
            .and_then(|field| field.value.as_str())
            .is_none()
    {
        return false;
    }
    let names = keys(criterion);
    let used: Vec<&str> = RELATIONS
        .iter()
        .copied()
        .filter(|name| names.contains(&Some(name)))
        .collect();
    let [used] = used.as_slice() else {
        return false;
    };
    if names
        .iter()
        .any(|name| !matches!(name, Some("field" | "is" | "contains" | "any")))
    {
        return false;
    }
    let Some(value) = get(criterion, used) else {
        return false;
    };
    match *used {
        "any" => match &value.value {
            Value::Seq(items) => !items.is_empty() && items.iter().all(|item| scalar(item)),
            _ => false,
        },
        "contains" => matches!(value.value, Value::Str(_)),
        _ => scalar(value),
    }
}

fn value_ok(row: &FieldRow, value: &Node) -> bool {
    match row.kind.as_str() {
        "enum" => value
            .value
            .as_str()
            .is_some_and(|text| row.value(text).is_some()),
        "port" => {
            let low = row.minimum.unwrap_or(0);
            let high = row.maximum.unwrap_or(65_535);
            matches!(value.value, Value::Int(port) if (low..=high).contains(&port))
        }
        _ => true,
    }
}

/// Whether the criterion's field is not one of `target`'s in the catalogue
/// (`unknown_field`).
pub fn unknown_field(catalogue: &Criteria, target: &str, criterion: &Node) -> bool {
    catalogue
        .field(field_name(criterion))
        .is_none_or(|row| row.target != target)
}

/// `bitdefender_criterion_field`, `_relation` and `_value` for one
/// criterion (`_criterion_codes`). An unknown field is an error on a target
/// whose field list the spec states, and a warning elsewhere.
fn criterion_code(catalogue: &Criteria, target: &str, criterion: &Node) -> Option<&'static str> {
    if unknown_field(catalogue, target, criterion) {
        return catalogue
            .is_closed_target(target)
            .then_some(CRITERION_FIELD);
    }
    let row = catalogue.field(field_name(criterion))?;
    let relation = relation(criterion);
    if !row.relations.iter().any(|known| known == relation)
        || (relation == "contains" && row.kind == "hash")
    {
        return Some(CRITERION_RELATION);
    }
    if !values(criterion).iter().all(|value| value_ok(row, value)) {
        return Some(CRITERION_VALUE);
    }
    None
}

/// The sensors the criteria need: a field's, or each enum value's
/// (`_sensors`), without `both`.
fn sensors<'c>(catalogue: &'c Criteria, criteria: &[&Node]) -> BTreeSet<&'c str> {
    let mut sensors = BTreeSet::new();
    for criterion in criteria {
        let Some(row) = catalogue.field(field_name(criterion)) else {
            continue;
        };
        if row.kind == "enum" {
            for value in values(criterion) {
                let text = scalar_text(value).unwrap_or_default();
                sensors.insert(row.value_availability(&text));
            }
        } else {
            sensors.insert(row.availability.as_str());
        }
    }
    sensors.remove("both");
    sensors
}

fn meets(names: &[String], present: &BTreeSet<&str>) -> bool {
    names.is_empty() || names.iter().any(|name| present.contains(name.as_str()))
}

fn clashes(names: &[String], fields: &BTreeSet<&str>) -> bool {
    names.iter().any(|name| fields.contains(name.as_str()))
}

/// The catalogue's pairing rules (`bitdefender_criteria_combination`,
/// `_combination_ok`).
fn combination_ok(catalogue: &Criteria, target: &str, criteria: &[&Node], alert: bool) -> bool {
    let fields: BTreeSet<&str> = criteria
        .iter()
        .map(|criterion| field_name(criterion))
        .collect();
    let mut present = fields.clone();
    if alert {
        present.insert(ALERT_FIELD);
    }
    let sensors = sensors(catalogue, criteria);
    if sensors.contains("edr") && sensors.contains("xdr") {
        return false;
    }
    for criterion in criteria {
        let Some(row) = catalogue.field(field_name(criterion)) else {
            continue;
        };
        if !meets(&row.requires_any, &present)
            || !meets(&row.detection_requires_any, &present)
            || clashes(&row.incompatible, &fields)
        {
            return false;
        }
        for value in values(criterion) {
            let text = scalar_text(value).unwrap_or_default();
            if row
                .value(&text)
                .is_some_and(|value| clashes(&value.incompatible, &fields))
            {
                return false;
            }
        }
    }
    if catalogue.one_resource_targets().contains(target) {
        let resources: BTreeSet<&str> = fields
            .iter()
            .filter_map(|name| catalogue.field(name))
            .filter_map(|row| row.resource.as_deref())
            .collect();
        if resources.len() > 1 {
            return false;
        }
    }
    // Every target but the four EDR ones is an XDR sensor's.
    let xdr = sensors.contains("xdr") || !catalogue.is_closed_target(target);
    let operation = fields.iter().any(|name| name.ends_with("Operation"));
    for rule in catalogue.alert_or_operation() {
        if rule.target.as_deref().is_some_and(|only| only != target) {
            continue;
        }
        if rule.scope.as_deref() == Some("xdr") && !xdr {
            continue;
        }
        let has_operation = rule
            .field
            .as_deref()
            .map_or(operation, |name| fields.contains(name));
        if alert && has_operation {
            return false;
        }
        if rule.require == Some(true) && !(alert || has_operation) {
            return false;
        }
    }
    true
}

/// The findings of a `detection` table, its target, and its criteria's
/// fields (`detection_findings`).
fn detection_findings<'n>(
    catalogue: &Criteria,
    detection: &'n Node,
) -> (Vec<Finding>, Option<&'n str>, Vec<&'n str>) {
    if !matches!(detection.value, Value::Map(_)) {
        return (Vec::new(), None, Vec::new());
    }
    let mut found = Vec::new();
    let target = get(detection, "target")
        .and_then(|target| target.value.as_str())
        .filter(|target| catalogue.is_detection_target(target));
    if target.is_none() {
        found.push(Finding::new(TARGET, vec![key("detection"), key("target")]));
    }
    let criteria = match get(detection, "criteria").map(|criteria| &criteria.value) {
        Some(Value::Seq(items)) if !items.is_empty() => items,
        _ => {
            found.push(Finding::new(CRITERION_SHAPE, criteria_path()));
            return (found, target, Vec::new());
        }
    };
    let mut shaped: Vec<&Node> = Vec::new();
    let mut criterion_found = false;
    for (index, criterion) in criteria.iter().enumerate() {
        let criterion: &Node = criterion;
        if !criterion_shape_ok(criterion) {
            found.push(Finding::new(CRITERION_SHAPE, criterion_path(index)));
            criterion_found = true;
            continue;
        }
        shaped.push(criterion);
        if field_name(criterion) == ALERT_FIELD {
            // On every target, open ones included (bitdefender-1.0, as the language server).
            found.push(Finding {
                code: CRITERION_FIELD,
                path: criterion_path(index),
                message: Some(ALERT_MESSAGE),
            });
            criterion_found = true;
        } else if let Some(target) = target
            && let Some(code) = criterion_code(catalogue, target, criterion)
        {
            found.push(Finding::new(code, criterion_path(index)));
            criterion_found = true;
        }
    }
    let fields: Vec<&str> = shaped
        .iter()
        .map(|criterion| field_name(criterion))
        .collect();
    if let Some(target) = target
        && !shaped.is_empty()
        && shaped.len() == criteria.len()
        && !criterion_found
        && !combination_ok(
            catalogue,
            target,
            &shaped,
            crate::objects::platform::truthy(get(detection, "alert")),
        )
    {
        found.push(Finding::new(CRITERIA_COMBINATION, criteria_path()));
    }
    (found, target, fields)
}

/// Criteria whose field a target outside the spec's table does not list:
/// warnings (`unknown_field_paths`), each the criterion's index.
pub fn unknown_field_paths(detection: &Node) -> Vec<usize> {
    let catalogue = criteria();
    let Some(target) = get(detection, "target").and_then(|target| target.value.as_str()) else {
        return Vec::new();
    };
    if !catalogue.is_detection_target(target) || catalogue.is_closed_target(target) {
        return Vec::new();
    }
    let Some(Value::Seq(criteria)) = get(detection, "criteria").map(|criteria| &criteria.value)
    else {
        return Vec::new();
    };
    criteria
        .iter()
        .enumerate()
        .filter(|(_, criterion)| {
            criterion_shape_ok(criterion)
                && field_name(criterion) != ALERT_FIELD
                && unknown_field(catalogue, target, criterion)
        })
        .map(|(index, _)| index)
        .collect()
}

/// `bitdefender_action_scope` at `actions.<key>` for each action the rule
/// cannot take (`action_scope_findings`).
fn action_scope_findings(
    actions: &Node,
    yara: bool,
    target: Option<&str>,
    fields: &[&str],
) -> Vec<Finding> {
    keys(actions)
        .into_iter()
        .flatten()
        .filter(|name| ACTION_TYPES.iter().any(|(known, _)| known == name))
        .filter(|name| !action_allowed(name, yara, target, fields))
        .map(|name| Finding::new(ACTION_SCOPE, vec![key("actions"), key(name)]))
        .collect()
}

/// Whether a block may take the automatic action `action`
/// (`bitdefender_action_scope`): a YARA rule (`yara`) takes every action but
/// `kill_process`; a Basic rule takes the process actions (`sandbox`,
/// `kill_process`, `quarantine`) only with a `process` or `file` `target`
/// or a `*.CreatedBy.*` field among its criteria (`fields`). The editor's
/// action completion asks the same.
pub fn action_allowed(action: &str, yara: bool, target: Option<&str>, fields: &[&str]) -> bool {
    if yara {
        !NOT_ON_YARA.contains(&action)
    } else {
        !PROCESS_ACTIONS.contains(&action)
            || matches!(target, Some("process" | "file"))
            || fields.iter().any(|field| field.contains(".CreatedBy."))
    }
}

/// `bitdefender_targets_shape`: exactly one list, non-empty, of non-blank
/// aliases (`targets_codes`). A value that is not a table is left to the
/// field's type.
pub fn targets_shape_ok(targets: &Node) -> bool {
    if !matches!(targets.value, Value::Map(_)) {
        return true;
    }
    let present: Vec<&str> = ["endpoint_tags", "companies"]
        .into_iter()
        .filter(|name| has(targets, name))
        .collect();
    // Neither list means the whole company: leave targets out to say that.
    let [name] = present.as_slice() else {
        return false;
    };
    match get(targets, name).map(|value| &value.value) {
        Some(Value::Seq(aliases)) => {
            !aliases.is_empty()
                && aliases.iter().all(|alias| {
                    alias
                        .value
                        .as_str()
                        .is_some_and(|alias| !python_strip(alias).is_empty())
                })
        }
        _ => false,
    }
}

/// [`targets_shape_ok`] on a JSON value: a tenant's default `targets`, or a
/// block's, as deploy resolves them (`resolve_targets`).
pub fn targets_shape_ok_json(targets: &serde_json::Value) -> bool {
    targets_shape_ok(&crate::objects::platform::json_node(targets))
}

/// Every bitdefender-1.0 constraint finding of a block, as authored, at its
/// path (`block_findings`). A key present with a `null` value inside
/// `targets` or a criterion is a key the author wrote, and checked as such.
/// At the block's root a `null` is the key left out.
///
/// The YARA signature's codes (yara-1.0 and the Bitdefender profile:
/// `bitdefender_yara_ascii`, `_yara_size`, `yara_include`,
/// `yara_empty_signature`, `yara_duplicate_rule`) are the YARA engine's,
/// which reads the signature under the Bitdefender profile; a signature with
/// no text, which it never reads, is `yara_empty_signature` here.
pub fn block_findings(block: &Node) -> Vec<Finding> {
    if !matches!(block.value, Value::Map(_)) {
        return Vec::new();
    }
    let catalogue = criteria();
    let mut found = Vec::new();
    let detection = set(block, "detection");
    let yara = set(block, "yara");
    if detection.is_some() == yara.is_some() {
        found.push(Finding::new(RULE_KIND, Vec::new()));
    }
    if let Some(severity) = set(block, "severity")
        && !severity
            .value
            .as_str()
            .is_some_and(|severity| SEVERITIES.contains(&severity))
    {
        found.push(Finding::new(SEVERITY, vec![key("severity")]));
    }
    if let Some(targets) = set(block, "targets")
        && !targets_shape_ok(targets)
    {
        found.push(Finding::new(TARGETS_SHAPE, vec![key("targets")]));
    }
    let mut target = None;
    let mut fields = Vec::new();
    if let Some(detection) = detection {
        let (detection_found, detection_target, detection_fields) =
            detection_findings(catalogue, detection);
        found.extend(detection_found);
        target = detection_target;
        fields = detection_fields;
    }
    // A signature the YARA engine reads is its: the Bitdefender profile and
    // yara-1.0 codes come from the injection (`opentide_tide::injection`).
    if let Some(signature) = yara.and_then(|yara| set(yara, "signature"))
        && signature
            .value
            .as_str()
            .is_some_and(|text| python_strip(text).is_empty())
    {
        found.push(Finding::new(
            EMPTY_SIGNATURE,
            vec![key("yara"), key("signature")],
        ));
    }
    if detection.is_some() != yara.is_some() {
        let is_yara = yara.is_some();
        if (is_yara || target.is_some())
            && let Some(actions) = set(block, "actions")
        {
            found.extend(action_scope_findings(actions, is_yara, target, &fields));
        }
    }
    found
}

/// Every bitdefender-1.0 constraint code a block, as authored, breaks
/// (`block_codes`): the named check's result.
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    block_findings(block)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

/// Each platform whose `yara.signature` is a YAML alias in `rule`, with the
/// node it names: its anchor's, which starts where the oracle places the
/// finding (`yara_signature_alias`, 0.28.0's `validation/yara_signature.py`).
/// A platform block's `YaraSignature` must be written out in the block. An
/// alias shares its anchor's node, so the signature is an alias when its
/// node first appears, in document order, at another path: also when the
/// whole `yara` block is the alias (`yara: *y`). HarfangLab's block has its
/// own check ([`crate::objects::platform::harfanglab::yara::aliased_signature`]),
/// so it is not one of them; [`crate::objects::platform::aliased_yara_signature`]
/// answers for either.
pub fn signature_aliases(rule: &Node) -> Vec<(&str, &Node)> {
    let Some(configurations) = get(rule, "configurations") else {
        return Vec::new();
    };
    let Value::Map(blocks) = &configurations.value else {
        return Vec::new();
    };
    let platforms: Vec<&str> = blocks
        .iter()
        .filter_map(|entry| {
            let platform = entry.key.value.as_str()?;
            let yara = get(&entry.value, "yara")?;
            (platform != "harfanglab" && yara.get("signature").is_some()).then_some(platform)
        })
        .collect();
    if platforms.is_empty() {
        return Vec::new();
    }
    let mut first = HashMap::new();
    first_paths(rule, &mut Vec::new(), &mut first);
    platforms
        .into_iter()
        .filter_map(|platform| {
            let path = ["configurations", platform, "yara", "signature"];
            let node = path.iter().try_fold(rule, |node, name| get(node, name))?;
            let seen = first.get(&std::ptr::from_ref(node))?;
            seen.iter()
                .map(String::as_str)
                .ne(path)
                .then_some((platform, node))
        })
        .collect()
}

/// The path at which each node first appears, in document order, each node
/// walked once (`_first_paths`).
fn first_paths(node: &Node, path: &mut Vec<String>, first: &mut HashMap<*const Node, Vec<String>>) {
    let at = std::ptr::from_ref(node);
    if first.contains_key(&at) {
        return;
    }
    first.insert(at, path.clone());
    match &node.value {
        Value::Map(entries) => {
            for entry in entries {
                let key = match &entry.key.value {
                    Value::Str(key) => key.clone(),
                    _ => crate::configuration::repr::node(&entry.key),
                };
                path.push(key);
                first_paths(&entry.value, path, first);
                path.pop();
            }
        }
        Value::Seq(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                first_paths(item, path, first);
                path.pop();
            }
        }
        _ => {}
    }
}
