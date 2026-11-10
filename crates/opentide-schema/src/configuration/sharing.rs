//! `sharing.toml`, merged block by block (`sharing/config.py`
//! `merge_sharing_documents`).
//!
//! `deep_merge` replaces every list, so a later layer restating only a
//! block's `name` and `enabled` would drop its `url`: each integration array
//! is merged by block `name` instead, key by key, later layers winning. Each
//! merged block is then checked with [`MispIntegration`] and what the model
//! cannot say (a status `deployment.toml` does not declare, a literal API
//! key). Messages never hold a secret.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use regex::Regex;

use super::Severity;
use super::codes;
use super::models::{MispIntegration, is_table_array};
use super::repr;
use crate::from_node::{Context, FromNode};
use crate::node::{Node, Value};

/// The one sharing integration of sharing 1.0.
pub const INTEGRATION_MISP: &str = "misp";
/// What replaces a literal API key in messages.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// One sharing finding (`SharingIssue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingIssue {
    /// The code.
    pub code: &'static str,
    /// The message.
    pub message: String,
    /// `error` or `warning`.
    pub severity: Severity,
    /// The block's name, when it has one.
    pub block: Option<String>,
    /// The integration (`misp`), when the finding is about a block.
    pub integration: Option<String>,
    /// The key the finding is about.
    pub field_name: Option<String>,
    /// `(layer, index)`: the layer's position in the merge, and the block's
    /// in that layer's array (`None` for a top-level key). For a merged
    /// block, the layer that set `field_name`.
    pub location: Option<(usize, Option<usize>)>,
    /// Every `(layer, index)` the block appears at, in merge order.
    pub occurrences: Vec<(usize, usize)>,
}

impl SharingIssue {
    fn error(code: &'static str, message: String) -> Self {
        Self {
            code,
            message,
            severity: Severity::Error,
            block: None,
            integration: None,
            field_name: None,
            location: None,
            occurrences: Vec::new(),
        }
    }
}

/// A block and where it was written.
struct Located<'n> {
    layer: usize,
    index: usize,
    table: &'n Node,
}

impl Located<'_> {
    fn name(&self) -> Option<&str> {
        self.table.get("name").and_then(|name| name.value.as_str())
    }
}

/// A block merged across layers, with where each key was set.
struct Merged {
    raw: Vec<(String, Arc<Node>)>,
    provenance: BTreeMap<String, (usize, usize)>,
    occurrences: Vec<(usize, usize)>,
}

impl Merged {
    fn location(&self, field: &str) -> (usize, Option<usize>) {
        let (layer, index) = self
            .provenance
            .get(field)
            .copied()
            .or_else(|| self.occurrences.last().copied())
            .unwrap_or_default();
        (layer, Some(index))
    }

    fn get(&self, key: &str) -> Option<&Node> {
        self.raw
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_ref())
    }

    fn node(&self) -> Node {
        Node {
            value: Value::Map(
                self.raw
                    .iter()
                    .map(|(key, value)| crate::node::Entry {
                        key: Arc::new(Node {
                            value: Value::Str(key.clone()),
                            start: value.start,
                            end: value.start,
                        }),
                        value: Arc::clone(value),
                    })
                    .collect(),
            ),
            start: crate::node::Mark::default(),
            end: crate::node::Mark::default(),
        }
    }
}

/// Merges `layers` (parsed `sharing.toml` documents, in order) and checks
/// each merged block. `status_names` are the merged `deployment.toml`
/// statuses; `tlp_names` the `tlp` vocabulary's names.
pub fn merge_sharing_documents(
    layers: &[&Node],
    status_names: &[String],
    tlp_names: &[String],
) -> Vec<SharingIssue> {
    let mut issues = Vec::new();
    let mut known: Vec<Located<'_>> = Vec::new();
    for (layer_index, layer) in layers.iter().enumerate() {
        let Value::Map(entries) = &layer.value else {
            continue;
        };
        let mut arrays: Vec<(String, Vec<Located<'_>>)> = Vec::new();
        for entry in entries {
            let key = entry.key.value.to_string();
            if !is_table_array(&entry.value) {
                issues.push(SharingIssue {
                    field_name: Some(key.clone()),
                    location: Some((layer_index, None)),
                    ..SharingIssue::error(
                        codes::UNKNOWN_KEY,
                        format!(
                            "Unknown key {}. The only sharing integration is \
                             [[{INTEGRATION_MISP}]].",
                            repr::quote(&key)
                        ),
                    )
                });
                continue;
            }
            let Value::Seq(items) = &entry.value.value else {
                continue;
            };
            let located = items
                .iter()
                .enumerate()
                .map(|(index, table)| Located {
                    layer: layer_index,
                    index,
                    table: table.as_ref(),
                })
                .collect();
            if key != INTEGRATION_MISP {
                issues.push(SharingIssue {
                    severity: Severity::Warning,
                    integration: Some(key.clone()),
                    field_name: Some(key.clone()),
                    location: Some((layer_index, None)),
                    ..SharingIssue::error(
                        codes::UNKNOWN_CONNECTOR,
                        format!(
                            "Unknown sharing integration {} was skipped.",
                            repr::quote(&key)
                        ),
                    )
                });
            }
            match arrays.iter_mut().find(|(name, _)| *name == key) {
                Some((_, existing)) => *existing = located,
                None => arrays.push((key, located)),
            }
        }
        let duplicated = reject_duplicate_names(&arrays, &mut issues);
        for (integration, items) in arrays {
            if integration == INTEGRATION_MISP {
                known.extend(items.into_iter().filter(|item| {
                    item.name()
                        .is_none_or(|name| !duplicated.contains(&name.to_owned()))
                }));
            }
        }
    }
    for merged in merge_named(&known, INTEGRATION_MISP, &mut issues) {
        issues.extend(misp_block(&merged, status_names, tlp_names));
    }
    issues
}

fn reject_duplicate_names(
    arrays: &[(String, Vec<Located<'_>>)],
    issues: &mut Vec<SharingIssue>,
) -> Vec<String> {
    let mut owners: Vec<(String, Vec<(&str, &Located<'_>)>)> = Vec::new();
    for (integration, items) in arrays {
        for item in items {
            if let Some(name) = item.name() {
                match owners.iter_mut().find(|(owner, _)| owner == name) {
                    Some((_, users)) => users.push((integration, item)),
                    None => owners.push((name.to_owned(), vec![(integration, item)])),
                }
            }
        }
    }
    let mut duplicated = Vec::new();
    for (name, users) in owners {
        if users.len() < 2 {
            continue;
        }
        let place = users
            .iter()
            .map(|(integration, item)| format!("[[{integration}]] #{}", item.index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let occurrences: Vec<(usize, usize)> = users
            .iter()
            .map(|(_, item)| (item.layer, item.index))
            .collect();
        for (integration, item) in &users {
            issues.push(SharingIssue {
                block: Some(name.clone()),
                integration: Some((*integration).to_owned()),
                field_name: Some("name".to_owned()),
                location: Some((item.layer, Some(item.index))),
                occurrences: occurrences.clone(),
                ..SharingIssue::error(
                    codes::DUPLICATE_NAME,
                    format!(
                        "Name {} is used by more than one block in one layer: {place}.",
                        repr::quote(&name)
                    ),
                )
            });
        }
        duplicated.push(name);
    }
    duplicated
}

fn merge_named(
    items: &[Located<'_>],
    integration: &str,
    issues: &mut Vec<SharingIssue>,
) -> Vec<Merged> {
    let mut merged: Vec<(String, Merged)> = Vec::new();
    for item in items {
        let Some(name) = item.name() else {
            issues.push(SharingIssue {
                integration: Some(integration.to_owned()),
                field_name: Some("name".to_owned()),
                location: Some((item.layer, Some(item.index))),
                ..SharingIssue::error(
                    codes::MISSING_FIELD,
                    format!("A [[{integration}]] block is missing name."),
                )
            });
            continue;
        };
        let position = match merged.iter().position(|(seen, _)| seen == name) {
            Some(position) => position,
            None => {
                merged.push((
                    name.to_owned(),
                    Merged {
                        raw: Vec::new(),
                        provenance: BTreeMap::new(),
                        occurrences: Vec::new(),
                    },
                ));
                merged.len() - 1
            }
        };
        let current = &mut merged[position].1;
        current.occurrences.push((item.layer, item.index));
        if let Value::Map(entries) = &item.table.value {
            for entry in entries {
                let key = entry.key.value.to_string();
                match current.raw.iter_mut().find(|(seen, _)| *seen == key) {
                    Some((_, value)) => *value = Arc::clone(&entry.value),
                    None => current.raw.push((key.clone(), Arc::clone(&entry.value))),
                }
                current.provenance.insert(key, (item.layer, item.index));
            }
        }
    }
    merged.into_iter().map(|(_, merged)| merged).collect()
}

/// The code of an invalid value, by its key (the spec checker's codes).
fn spec_code(field: &str) -> &'static str {
    match field {
        "name" => codes::NAME_INVALID,
        "url" => codes::URL_INVALID,
        "max_tlp" => codes::MAX_TLP_UNKNOWN,
        "organisation_uuid" => codes::ORGANISATION_UUID_INVALID,
        "object_types" => codes::OBJECT_TYPE_UNKNOWN,
        "rule_statuses" => codes::RULE_STATUS_UNKNOWN,
        _ => codes::INVALID_VALUE,
    }
}

fn api_key_pattern() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    super::types::compiled(&REGEX, r"^\$\{([A-Z][A-Z0-9_]*)\}$")
}

/// One finding: `(code, key, list entry)`.
type Found = (&'static str, String, Option<String>);

fn misp_block(merged: &Merged, status_names: &[String], tlp_names: &[String]) -> Vec<SharingIssue> {
    let block = merged
        .get("name")
        .and_then(|name| name.value.as_str())
        .map(str::to_owned);
    let mut found: Vec<Found> = Vec::new();
    let node = merged.node();
    let mut cx = Context::new();
    let model = MispIntegration::from_node(&node, &mut cx);
    let errors = cx.into_errors();
    if errors.is_empty()
        && let Some(model) = &model
    {
        if !tlp_names.iter().any(|name| name == model.max_tlp.name()) {
            found.push((codes::MAX_TLP_UNKNOWN, "max_tlp".to_owned(), None));
        }
    } else {
        found.extend(model_findings(&errors, merged));
    }
    if let Some(Node {
        value: Value::Seq(statuses),
        ..
    }) = merged.get("rule_statuses")
    {
        for status in statuses {
            if let Value::Str(text) = &status.value
                && !text.is_empty()
                && !status_names.contains(text)
            {
                found.push((
                    codes::RULE_STATUS_UNKNOWN,
                    "rule_statuses".to_owned(),
                    Some(repr::quote(text)),
                ));
            }
        }
    }
    if let Some(Value::Str(key)) = merged.get("api_key").map(|node| &node.value)
        && !key.is_empty()
        && !api_key_pattern().is_match(key)
    {
        found.push((codes::API_KEY_LITERAL, "api_key".to_owned(), None));
    }
    found
        .into_iter()
        .map(|(code, field, entry)| issue(code, &field, block.as_deref(), merged, entry))
        .collect()
}

/// `(code, key, entry)` per `MispIntegration` error. Inputs are never echoed,
/// except list entries.
fn model_findings(errors: &[crate::SchemaError], merged: &Merged) -> Vec<Found> {
    let mut found = Vec::new();
    for error in errors {
        let Some(crate::PathSegment::Key(field)) = error.path.first() else {
            continue;
        };
        let kind = error.kind.pydantic_type().unwrap_or("");
        let empty = merged
            .get(field)
            .is_some_and(|value| value.value.as_str() == Some(""));
        let code = if kind == "extra_forbidden" {
            codes::UNKNOWN_KEY
        } else if kind == "missing" || (empty && field != "name") {
            codes::MISSING_FIELD
        } else {
            spec_code(field)
        };
        let mut entry = None;
        if (code == codes::OBJECT_TYPE_UNKNOWN || code == codes::RULE_STATUS_UNKNOWN)
            && let (Some(crate::PathSegment::Index(index)), Some(Value::Seq(items))) =
                (error.path.get(1), merged.get(field).map(|node| &node.value))
            && let Some(item) = items.get(*index)
        {
            entry = Some(repr::node(item));
        }
        found.push((code, field.clone(), entry));
    }
    found
}

fn issue(
    code: &'static str,
    field: &str,
    block: Option<&str>,
    merged: &Merged,
    entry: Option<String>,
) -> SharingIssue {
    let place = format!(
        "[[{INTEGRATION_MISP}]] block {}",
        block.map_or_else(|| "None".to_owned(), repr::quote)
    );
    let entry = entry.unwrap_or_else(|| "None".to_owned());
    let message = match code {
        codes::MISSING_FIELD => format!("{place} is missing {field}."),
        codes::UNKNOWN_KEY => format!("Unknown key '{field}' in {place}."),
        codes::NAME_INVALID => "Block name must be 1–64 characters of lowercase letters, \
                                digits, hyphen, and underscore."
            .to_owned(),
        codes::URL_INVALID => format!("{place} url must be an http(s) URL."),
        codes::MAX_TLP_UNKNOWN => format!("{place} max_tlp is not a tlp vocabulary name."),
        codes::ORGANISATION_UUID_INVALID => {
            format!("{place} organisation_uuid must be a 36-character hex UUID (8-4-4-4-12).")
        }
        codes::OBJECT_TYPE_UNKNOWN => format!("{place} object_types entry {entry} is unknown."),
        codes::RULE_STATUS_UNKNOWN => format!("{place} rule_statuses entry {entry} is unknown."),
        codes::API_KEY_LITERAL => format!(
            "{place} api_key is a literal. Use ${{ENV_VAR}}. The value was replaced with \
             {REDACTION_MARKER}."
        ),
        _ => format!("{place} {field} has an invalid value."),
    };
    let (layer, index) = merged.location(field);
    SharingIssue {
        code,
        message,
        severity: if code == codes::API_KEY_LITERAL {
            Severity::Warning
        } else {
            Severity::Error
        },
        block: block.map(str::to_owned),
        integration: Some(INTEGRATION_MISP.to_owned()),
        field_name: Some(field.to_owned()),
        location: Some((layer, index)),
        occurrences: merged.occurrences.clone(),
    }
}
