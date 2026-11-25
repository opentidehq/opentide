//! The constraints of `configurations.microsoft_defender`
//! (microsoft-defender-1.0, Constraints): each code at the path the
//! specification fixes for it, relative to the block. A key the block does
//! not define is the model's (`extra_forbidden`), not a finding here, except
//! inside `entities`, `actions`, `scope` and `incident`, whose keys the
//! specification checks under its own codes.

use std::collections::BTreeSet;

use crate::configuration::repr;
use crate::error::PathSegment;
use crate::node::{Node, Value};

use super::{
    ACTIONS, DEVICE_GROUPS, Duration, ENTITY_KINDS, GROUPINGS, ISOLATION_TYPE, ISOLATION_TYPES,
    Kind, SCHEMA, SEVERITIES,
};

/// `schema`, when set, is `platform::microsoft_defender::1.0`.
pub const SCHEMA_CODE: &str = opentide_core::codes::MICROSOFT_DEFENDER_SCHEMA;
/// `schedule.frequency` is `NRT`, `<n>H`, or `<n>D`.
pub const FREQUENCY: &str = opentide_core::codes::MICROSOFT_DEFENDER_FREQUENCY;
/// `schedule.lookback` is `<n>H` or `<n>D`, not with `NRT`, not shorter than
/// `frequency`.
pub const LOOKBACK: &str = opentide_core::codes::MICROSOFT_DEFENDER_LOOKBACK;
/// `alert.severity` is one of the five severities.
pub const SEVERITY: &str = opentide_core::codes::MICROSOFT_DEFENDER_SEVERITY;
/// `alert.grouping` is `alert_per_event` or `single_alert`.
pub const GROUPING: &str = opentide_core::codes::MICROSOFT_DEFENDER_GROUPING;
/// `alert.custom_details` is a map of non-blank names to strings.
pub const CUSTOM_DETAILS: &str = opentide_core::codes::MICROSOFT_DEFENDER_CUSTOM_DETAILS;
/// Every key of `entities` is an entity kind.
pub const ENTITY_KIND: &str = opentide_core::codes::MICROSOFT_DEFENDER_ENTITY_KIND;
/// Every kind holds a list of mappings, each with at least one field and
/// only its kind's fields.
pub const ENTITY_MAPPING: &str = opentide_core::codes::MICROSOFT_DEFENDER_ENTITY_MAPPING;
/// Every key of `actions` is an automated action.
pub const ACTION_KIND: &str = opentide_core::codes::MICROSOFT_DEFENDER_ACTION_KIND;
/// Every action holds a non-empty list of targets, each with at least one
/// field and only its action's fields.
pub const ACTION_TARGET: &str = opentide_core::codes::MICROSOFT_DEFENDER_ACTION_TARGET;
/// `isolation_type` is `full` or `selective`.
pub const ISOLATION: &str = opentide_core::codes::MICROSOFT_DEFENDER_ISOLATION_TYPE;
/// Every column name is a non-blank string.
pub const COLUMN: &str = opentide_core::codes::MICROSOFT_DEFENDER_COLUMN;
/// `scope` is `{device_groups: [...]}`, a non-empty list of non-blank names.
pub const SCOPE: &str = opentide_core::codes::MICROSOFT_DEFENDER_SCOPE;
/// `incident` is `{exclude_from_correlation: <boolean>}`.
pub const INCIDENT: &str = opentide_core::codes::MICROSOFT_DEFENDER_INCIDENT;

/// Every code [`block_findings`] reports, in the specification's order.
pub const CONSTRAINT_CODES: [&str; 14] = [
    SCHEMA_CODE,
    FREQUENCY,
    LOOKBACK,
    SEVERITY,
    GROUPING,
    CUSTOM_DETAILS,
    ENTITY_KIND,
    ENTITY_MAPPING,
    ACTION_KIND,
    ACTION_TARGET,
    ISOLATION,
    COLUMN,
    SCOPE,
    INCIDENT,
];

/// One broken constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The constraint code (`microsoft_defender_lookback`).
    pub code: &'static str,
    /// Where, relative to the block.
    pub path: Vec<PathSegment>,
    /// What is wrong.
    pub message: String,
}

fn key(name: &str) -> PathSegment {
    PathSegment::Key(name.to_owned())
}

fn at(path: &[PathSegment], next: PathSegment) -> Vec<PathSegment> {
    let mut out = path.to_vec();
    out.push(next);
    out
}

/// The codes of [`block_findings`], each once.
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    block_findings(block)
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

/// A value's text in a message: `'x'` for a string, its YAML for anything
/// else.
fn shown(node: &Node) -> String {
    repr::node(node)
}

/// The text of a non-blank string.
fn non_blank(node: &Node) -> Option<&str> {
    node.value.as_str().filter(|text| !text.trim().is_empty())
}

fn entries(node: &Node) -> Option<&[crate::node::Entry]> {
    match &node.value {
        Value::Map(entries) => Some(entries),
        _ => None,
    }
}

/// The key of an entry as text (a non-string key is shown as YAML).
fn key_text(entry: &crate::node::Entry) -> String {
    match &entry.key.value {
        Value::Str(text) => text.to_string(),
        _ => shown(&entry.key),
    }
}

/// Every broken constraint of the block `block`, in the order of its keys.
pub fn block_findings(block: &Node) -> Vec<Finding> {
    let mut found = Vec::new();
    let Some(fields) = entries(block) else {
        return found;
    };
    for entry in fields {
        let value = entry.value.as_ref();
        match entry.key.value.as_str() {
            Some("schema") => schema(value, &mut found),
            Some("schedule") => schedule(value, &mut found),
            Some("alert") => alert(value, &mut found),
            Some("entities") => entities(value, &mut found),
            Some("actions") => actions(value, &mut found),
            Some("scope") => scope(value, &mut found),
            Some("incident") => incident(value, &mut found),
            _ => {}
        }
    }
    found
}

fn schema(value: &Node, found: &mut Vec<Finding>) {
    if matches!(value.value, Value::Null) || value.value.as_str() == Some(SCHEMA) {
        return;
    }
    found.push(Finding {
        code: SCHEMA_CODE,
        path: vec![key("schema")],
        message: format!(
            "unknown platform schema {}: this block's schema is '{SCHEMA}'",
            shown(value)
        ),
    });
}

fn schedule(value: &Node, found: &mut Vec<Finding>) {
    // A schedule that is not a mapping, or has no frequency, is the
    // model's to report (a mapping with a required `frequency`).
    let Some(fields) = entries(value) else {
        return;
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|entry| entry.key.value.as_str() == Some(name))
            .map(|entry| entry.value.as_ref())
    };
    let frequency = field("frequency").filter(|node| !matches!(node.value, Value::Null));
    let parsed_frequency = frequency.and_then(|node| node.value.as_str().and_then(Duration::parse));
    if let (Some(node), None) = (frequency, parsed_frequency) {
        found.push(Finding {
            code: FREQUENCY,
            path: vec![key("schedule"), key("frequency")],
            message: format!(
                "schedule.frequency {} is not NRT, <n>H or <n>D (n a positive whole number \
                 without a leading zero: 1H, 24H, 1D)",
                shown(node)
            ),
        });
    }
    let Some(lookback) = field("lookback").filter(|node| !matches!(node.value, Value::Null)) else {
        return;
    };
    let path = vec![key("schedule"), key("lookback")];
    let parsed = lookback.value.as_str().and_then(Duration::parse);
    let message = match parsed {
        None | Some(Duration::NearRealTime) => Some(format!(
            "schedule.lookback {} is not <n>H or <n>D (n a positive whole number without a \
             leading zero: 4H, 1D)",
            shown(lookback)
        )),
        Some(_) if parsed_frequency == Some(Duration::NearRealTime) => Some(
            "schedule.lookback is not supported with frequency NRT: a near-real-time rule \
             reads each event as it arrives"
                .to_owned(),
        ),
        Some(window) => match (window.hours(), parsed_frequency.and_then(Duration::hours)) {
            (Some(window), Some(every)) if window < every => Some(format!(
                "schedule.lookback {} is shorter than frequency {}: Graph requires the lookback \
                 to be at least the frequency",
                shown(lookback),
                frequency.map(shown).unwrap_or_default()
            )),
            _ => None,
        },
    };
    if let Some(message) = message {
        found.push(Finding {
            code: LOOKBACK,
            path,
            message,
        });
    }
}

fn alert(value: &Node, found: &mut Vec<Finding>) {
    let Some(fields) = entries(value) else {
        return;
    };
    for entry in fields {
        let node = entry.value.as_ref();
        if matches!(node.value, Value::Null) {
            continue;
        }
        match entry.key.value.as_str() {
            Some("severity") if !node.value.as_str().is_some_and(|s| SEVERITIES.contains(&s)) => {
                let meant = node
                    .value
                    .as_str()
                    .and_then(|text| {
                        SEVERITIES
                            .iter()
                            .find(|severity| severity.eq_ignore_ascii_case(text))
                    })
                    .map(|severity| format!("; did you mean '{severity}'?"))
                    .unwrap_or_default();
                found.push(Finding {
                    code: SEVERITY,
                    path: vec![key("alert"), key("severity")],
                    message: format!(
                        "alert.severity {} is not Informational, Low, Medium, High or Critical \
                         (exact case){meant}",
                        shown(node)
                    ),
                });
            }
            Some("grouping")
                if !node
                    .value
                    .as_str()
                    .is_some_and(|text| GROUPINGS.iter().any(|(name, _)| *name == text)) =>
            {
                found.push(Finding {
                    code: GROUPING,
                    path: vec![key("alert"), key("grouping")],
                    message: format!(
                        "alert.grouping {} is not alert_per_event or single_alert",
                        shown(node)
                    ),
                });
            }
            Some("custom_details") => custom_details(node, found),
            _ => {}
        }
    }
}

fn custom_details(value: &Node, found: &mut Vec<Finding>) {
    let base = [key("alert"), key("custom_details")];
    let Some(details) = entries(value) else {
        found.push(Finding {
            code: CUSTOM_DETAILS,
            path: base.to_vec(),
            message: format!(
                "alert.custom_details is a mapping of detail name to result column, not {}",
                shown(value)
            ),
        });
        return;
    };
    for detail in details {
        let name = key_text(detail);
        let blank_name = detail
            .key
            .value
            .as_str()
            .is_none_or(|text| text.trim().is_empty());
        if blank_name {
            found.push(Finding {
                code: CUSTOM_DETAILS,
                path: base.to_vec(),
                message: format!("alert.custom_details has a blank or non-string name {name:?}"),
            });
            continue;
        }
        let path = at(&base, key(&name));
        match &detail.value.value {
            Value::Str(text) if text.trim().is_empty() => found.push(Finding {
                code: COLUMN,
                path,
                message: format!("custom detail {name:?} names no column: the value is blank"),
            }),
            Value::Str(_) => {}
            _ => found.push(Finding {
                code: CUSTOM_DETAILS,
                path,
                message: format!(
                    "custom detail {name:?} is a result column's name (a string), not {}",
                    shown(&detail.value)
                ),
            }),
        }
    }
}

/// A column name at `path`: a non-blank string.
fn column(value: &Node, path: Vec<PathSegment>, label: &str, found: &mut Vec<Finding>) {
    if non_blank(value).is_none() {
        found.push(Finding {
            code: COLUMN,
            path,
            message: format!(
                "{label} is a result column's name, a non-blank string, not {}",
                shown(value)
            ),
        });
    }
}

fn kind_names(kinds: &[Kind]) -> String {
    kinds
        .iter()
        .map(|kind| kind.key)
        .collect::<Vec<_>>()
        .join(", ")
}

fn field_names(kind: &Kind) -> String {
    kind.fields
        .iter()
        .map(|(field, _)| *field)
        .collect::<Vec<_>>()
        .join(", ")
}

fn entities(value: &Node, found: &mut Vec<Finding>) {
    if matches!(value.value, Value::Null) {
        return;
    }
    let base = [key("entities")];
    let Some(kinds) = entries(value) else {
        found.push(Finding {
            code: ENTITY_KIND,
            path: base.to_vec(),
            message: format!(
                "entities is a mapping of entity kind to mappings, not {}",
                shown(value)
            ),
        });
        return;
    };
    for entry in kinds {
        let name = key_text(entry);
        let path = at(&base, key(&name));
        let Some(kind) = ENTITY_KINDS.iter().find(|kind| kind.key == name) else {
            found.push(Finding {
                code: ENTITY_KIND,
                path,
                message: format!(
                    "{name:?} is not an entity kind; the kinds are {}",
                    kind_names(&ENTITY_KINDS)
                ),
            });
            continue;
        };
        let mappings = match &entry.value.value {
            Value::Null => continue,
            Value::Seq(items) => items,
            _ => {
                found.push(Finding {
                    code: ENTITY_MAPPING,
                    path,
                    message: format!(
                        "entities.{name} is a list of mappings, not {}",
                        shown(&entry.value)
                    ),
                });
                continue;
            }
        };
        for (index, mapping) in mappings.iter().enumerate() {
            let path = at(&path, PathSegment::Index(index));
            let label = format!("entities.{name}[{index}]");
            let fields = match entries(mapping) {
                Some(fields) if !fields.is_empty() => fields,
                _ => {
                    found.push(Finding {
                        code: ENTITY_MAPPING,
                        path,
                        message: format!(
                            "{label} maps no column: a mapping is a mapping with at least one of \
                             {}",
                            field_names(kind)
                        ),
                    });
                    continue;
                }
            };
            for field in fields {
                let field_name = key_text(field);
                if kind.graph_field(&field_name).is_none() {
                    found.push(Finding {
                        code: ENTITY_MAPPING,
                        path: path.clone(),
                        message: format!(
                            "{label}: {name} has no field {field_name:?}; its fields are {}",
                            field_names(kind)
                        ),
                    });
                    continue;
                }
                column(
                    &field.value,
                    at(&path, key(&field_name)),
                    &format!("{label}.{field_name}"),
                    found,
                );
            }
        }
    }
}

fn actions(value: &Node, found: &mut Vec<Finding>) {
    if matches!(value.value, Value::Null) {
        return;
    }
    let base = [key("actions")];
    let Some(actions) = entries(value) else {
        found.push(Finding {
            code: ACTION_KIND,
            path: base.to_vec(),
            message: format!(
                "actions is a mapping of automated action to targets, not {}",
                shown(value)
            ),
        });
        return;
    };
    for entry in actions {
        let name = key_text(entry);
        let path = at(&base, key(&name));
        let Some(action) = ACTIONS.iter().find(|action| action.key == name) else {
            found.push(Finding {
                code: ACTION_KIND,
                path,
                message: format!(
                    "{name:?} is not an automated action; the actions are {}",
                    kind_names(&ACTIONS)
                ),
            });
            continue;
        };
        let targets = match &entry.value.value {
            Value::Seq(items) if !items.is_empty() => items,
            _ => {
                found.push(Finding {
                    code: ACTION_TARGET,
                    path,
                    message: format!(
                        "actions.{name} is a non-empty list of targets, not {}",
                        shown(&entry.value)
                    ),
                });
                continue;
            }
        };
        for (index, target) in targets.iter().enumerate() {
            let path = at(&path, PathSegment::Index(index));
            let label = format!("actions.{name}[{index}]");
            let fields = match entries(target) {
                Some(fields) if !fields.is_empty() => fields,
                _ => {
                    found.push(Finding {
                        code: ACTION_TARGET,
                        path,
                        message: format!(
                            "{label} names no target: a target is a mapping with at least one of \
                             {}",
                            field_names(action)
                        ),
                    });
                    continue;
                }
            };
            for field in fields {
                action_field(action, &label, &path, field, found);
            }
        }
    }
}

/// One field of the automated action `action`'s target at `path`.
fn action_field(
    action: &Kind,
    label: &str,
    path: &[PathSegment],
    field: &crate::node::Entry,
    found: &mut Vec<Finding>,
) {
    let name = action.key;
    let field_name = key_text(field);
    let field_path = at(path, key(&field_name));
    if action.graph_field(&field_name).is_none() {
        found.push(Finding {
            code: ACTION_TARGET,
            path: path.to_vec(),
            message: format!(
                "{label}: {name} takes no field {field_name:?}; its fields are {}",
                field_names(action)
            ),
        });
        return;
    }
    match field_name.as_str() {
        ISOLATION_TYPE => {
            if !field
                .value
                .value
                .as_str()
                .is_some_and(|text| ISOLATION_TYPES.contains(&text))
            {
                found.push(Finding {
                    code: ISOLATION,
                    path: field_path,
                    message: format!(
                        "{label}.isolation_type {} is not full or selective",
                        shown(&field.value)
                    ),
                });
            }
        }
        DEVICE_GROUPS => {
            if !names(&field.value) {
                found.push(Finding {
                    code: ACTION_TARGET,
                    path: field_path,
                    message: format!(
                        "{label}.device_groups is a non-empty list of device group names, not {}",
                        shown(&field.value)
                    ),
                });
            }
        }
        _ => column(
            &field.value,
            field_path,
            &format!("{label}.{field_name}"),
            found,
        ),
    }
}

/// Whether `value` is a non-empty list of non-blank strings.
fn names(value: &Node) -> bool {
    match &value.value {
        Value::Seq(items) => {
            !items.is_empty() && items.iter().all(|item| non_blank(item).is_some())
        }
        _ => false,
    }
}

fn scope(value: &Node, found: &mut Vec<Finding>) {
    if matches!(value.value, Value::Null) {
        return;
    }
    let shaped = entries(value).is_some_and(|fields| {
        fields.len() == 1
            && fields[0].key.value.as_str() == Some(DEVICE_GROUPS)
            && names(&fields[0].value)
    });
    if !shaped {
        found.push(Finding {
            code: SCOPE,
            path: vec![key("scope")],
            message: format!(
                "scope is {{device_groups: [...]}}, a non-empty list of device group names, \
                 not {}",
                shown(value)
            ),
        });
    }
}

fn incident(value: &Node, found: &mut Vec<Finding>) {
    if matches!(value.value, Value::Null) {
        return;
    }
    let shaped = entries(value).is_some_and(|fields| {
        fields.len() == 1
            && fields[0].key.value.as_str() == Some("exclude_from_correlation")
            && matches!(fields[0].value.value, Value::Bool(_))
    });
    if !shaped {
        found.push(Finding {
            code: INCIDENT,
            path: vec![key("incident")],
            message: format!(
                "incident is {{exclude_from_correlation: true or false}}, not {}",
                shown(value)
            ),
        });
    }
}
