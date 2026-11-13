//! Completion and hover in the Bitdefender GravityZone block
//! (`configurations.bitdefender`, bitdefender-1.0), from the criteria
//! catalogue (`data/catalogs/bitdefender/criteria.toml`): the detection
//! targets, each target's criteria fields, the relations `is`, `contains` and
//! `any`, enumerated values, and the automatic actions the block's kind and
//! target allow.
//!
//! The block's checks are not here: the model reports its constraint codes
//! and advisories (`opentide_schema::objects::platform::bitdefender`), and the
//! YARA engine its signature's, which the language server reports as
//! `validate` does. Completion reads the catalogue and the action scope from
//! that same module, so the editor offers what `validate` accepts.
//!
//! The block is read from the text around the cursor, line by line, so
//! completion works while the YAML being typed does not parse.

use opentide_core::CompletionItem;
use opentide_core::node::{Node, Value};
use opentide_schema::objects::platform::bitdefender::checks::{
    RELATIONS, SEVERITIES, action_allowed,
};
use opentide_schema::objects::platform::bitdefender::criteria::{
    Criteria, FieldRow, TargetRow, ValueRow, criteria,
};

use crate::yaml_path::YamlCursor;

const BLOCK: [&str; 2] = ["configurations", "bitdefender"];
const STEP_KEYS: [&str; 2] = ["include_parent", "include_children"];
const SCAN_TYPES: [&str; 2] = ["quick", "full"];

/// The automatic actions, in GravityZone `type` order, with what each takes
/// and where it is allowed (bitdefender-1.0, `actions`).
const ACTIONS: [(&str, &str); 7] = [
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
        "Send the file to Sandbox Analyzer (type 3). `true`. Basic rules with a `process` or \
         `file` target or a `*.CreatedBy.*` criterion; YARA rules.",
    ),
    (
        "kill_process",
        "Kill the process (type 4). `true`, or `{include_parent, include_children}`. Basic \
         rules with a `process` or `file` target or a `*.CreatedBy.*` criterion.",
    ),
    (
        "antimalware_scan",
        "Run an antimalware scan (type 5). `quick` or `full`. Basic and YARA rules.",
    ),
    (
        "quarantine",
        "Quarantine the file (type 6). `true`, or `{include_parent, include_children}`. As \
         `sandbox`.",
    ),
    (
        "risk_scan",
        "Run a risk scan (type 7). `true`. Basic and YARA rules.",
    ),
];

/// The block's own keys (bitdefender-1.0, Block) and the shared platform keys.
const BLOCK_KEYS: [(&str, &str, &str); 13] = [
    (
        "enabled",
        "boolean",
        "Whether this platform block is active.",
    ),
    ("schema", "string", "`platform::bitdefender::1.0`."),
    (
        "status",
        "string · required",
        "Deployment status of this platform block.",
    ),
    (
        "name",
        "string",
        "The GravityZone rule name. Empty means the opentide rule `name`.",
    ),
    ("contributors", "array", "Platform contributors."),
    ("flags", "array", "Platform flags."),
    ("tenants", "array", "Target tenant identifiers."),
    (
        "severity",
        "string",
        "`Low`, `Medium`, or `High`. Without it, from `response.alert_severity`.",
    ),
    (
        "tags",
        "array",
        "Extra GravityZone tags. Deploy adds the derived tags.",
    ),
    (
        "targets",
        "object",
        "Endpoint tags, or companies on a partner tenant, the rule applies to: \
         `endpoint_tags` or `companies`.",
    ),
    ("actions", "object", "Automatic actions."),
    (
        "detection",
        "object",
        "A Basic detection rule: a `target` and its `criteria`. Not with `yara`.",
    ),
    (
        "yara",
        "object",
        "A YARA detection rule: a `signature`. Not with `detection`.",
    ),
];

const DETECTION_KEYS: [(&str, &str, &str); 3] = [
    (
        "target",
        "string · required",
        "A GravityZone detection target, as the API spells it (`process`, `user connection`).",
    ),
    (
        "criteria",
        "array · required",
        "At least one criterion: a `field` and one of `is`, `contains`, `any`. All must match.",
    ),
    (
        "alert",
        "string",
        "A GravityZone alert (detection) name, sent as the `detection` filter.",
    ),
];

const YARA_KEYS: [(&str, &str, &str); 2] = [
    (
        "signature",
        "string · required",
        "The YARA signature: imports, then one or more YARA rules. Sent verbatim.",
    ),
    (
        "on_access",
        "boolean · default true",
        "On-access scanning with this rule. With `false`, on-demand scans only.",
    ),
];

const TARGETS_KEYS: [(&str, &str, &str); 2] = [
    (
        "endpoint_tags",
        "array",
        "Aliases from the tenant's `endpoint_tags` table. Not with `companies`.",
    ),
    (
        "companies",
        "array",
        "Partner tenants: aliases from the tenant's `companies` table. Not with \
         `endpoint_tags`.",
    ),
];

const RELATION_DOCS: [(&str, &str); 3] = [
    (
        "is",
        "Exact match: one string or integer. Sent as `relation: \"is\"`.",
    ),
    (
        "contains",
        "Substring, with `*` and `?` wildcards: one string. Sent as `relation: \"contains\"`. \
         Not on enumerated fields or hashes.",
    ),
    (
        "any",
        "Any of the values: a non-empty list. Sent as `relation: \"any\"`.",
    ),
];

fn ticked(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
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

fn field_markdown(row: &FieldRow) -> String {
    let mut md = format!(
        "**{}** · {} · `{}`\n\n{} · {}",
        row.name,
        row.label,
        row.target,
        kind_text(row),
        sensors(&row.availability)
    );
    md.push_str(&format!("\n\nRelations: {}", ticked(&row.relations)));
    if !row.values.is_empty() {
        let values: Vec<String> = row
            .values
            .iter()
            .map(|value| {
                let availability = row.value_availability(&value.name);
                if availability == row.availability {
                    format!("`{}`", value.name)
                } else {
                    format!("`{}` ({})", value.name, sensors(availability))
                }
            })
            .collect();
        md.push_str(&format!("\n\nValues: {}", values.join(", ")));
    }
    if !row.requires_any.is_empty() {
        md.push_str(&format!(
            "\n\nNeeds one of {} in the same rule.",
            ticked(&row.requires_any)
        ));
    }
    if !row.detection_requires_any.is_empty() {
        md.push_str(&format!(
            "\n\nNeeds one of {} in the same rule (`detection` is `alert`).",
            ticked(&row.detection_requires_any)
        ));
    }
    if !row.incompatible.is_empty() {
        md.push_str(&format!("\n\nNot with {}.", ticked(&row.incompatible)));
    }
    if !row.detection {
        md.push_str("\n\nExclusion rules only.");
    }
    md
}

fn value_markdown(row: &FieldRow, value: &ValueRow) -> String {
    let mut md = format!(
        "**{}** · `{}`\n\n{}",
        value.name,
        row.name,
        sensors(row.value_availability(&value.name))
    );
    if !value.incompatible.is_empty() {
        md.push_str(&format!(
            "\n\nNot with {} in the same rule.",
            ticked(&value.incompatible)
        ));
    }
    md
}

fn target_markdown(catalogue: &Criteria, target: &TargetRow) -> String {
    let fields: Vec<&FieldRow> = catalogue.detection_fields(&target.name).collect();
    let edr = fields.iter().any(|field| field.availability != "xdr");
    let xdr = fields.iter().any(|field| field.availability != "edr");
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

/// The cursor's path inside the block (`detection.criteria.field`), or `None`
/// outside it.
fn block_path(cursor: &YamlCursor) -> Option<Vec<&str>> {
    let path: Vec<&str> = cursor.path.iter().map(String::as_str).collect();
    (path.len() >= 2 && path[..2] == BLOCK).then(|| path[2..].to_vec())
}

/// The path, inside the block, of the mapping whose keys the cursor
/// completes, or `None` outside the block.
fn container(cursor: &YamlCursor) -> Option<Vec<String>> {
    let parent = cursor.container_path();
    let parts: Vec<String> = parent.split('.').map(str::to_owned).collect();
    (parts.len() >= 2 && parts[0] == BLOCK[0] && parts[1] == BLOCK[1]).then(|| parts[2..].to_vec())
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The text after `key:` on a line (after an optional `- `), without a
/// trailing comment or the quotes around it.
fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let body = line.trim_start();
    let body = body.strip_prefix("- ").unwrap_or(body).trim_start();
    let rest = body.strip_prefix(key)?.strip_prefix(':')?;
    let rest = rest.split(" #").next().unwrap_or(rest).trim();
    Some(rest.trim_matches(['"', '\'']))
}

/// The lines under the block's `bitdefender:` key, and that key's indent.
fn block_lines(source: &str) -> Option<(usize, Vec<&str>)> {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("bitdefender:") && indent(line) > 0)?;
    let base = indent(lines[start]);
    let body = lines[start + 1..]
        .iter()
        .take_while(|line| line.trim().is_empty() || indent(line) > base)
        .copied()
        .collect();
    Some((base, body))
}

/// The block's `detection.target`.
fn current_target(source: &str) -> Option<String> {
    let (_, body) = block_lines(source)?;
    body.iter()
        .find_map(|line| key_value(line, "target").filter(|value| !value.is_empty()))
        .map(str::to_owned)
}

/// The keys written directly under the block.
fn block_keys(source: &str) -> Vec<String> {
    let Some((base, body)) = block_lines(source) else {
        return Vec::new();
    };
    let child = body
        .iter()
        .find(|line| !line.trim().is_empty())
        .map_or(base + 2, |line| indent(line));
    body.iter()
        .filter(|line| indent(line) == child)
        .filter_map(|line| {
            line.trim()
                .split_once(':')
                .map(|(key, _)| key.trim().to_owned())
        })
        .collect()
}

/// The `field` of each criterion of the block: from the loaded object, or,
/// while the YAML does not load, from the `field:` keys written under
/// `criteria:`. Never from comments or other text.
fn criteria_fields(source: &str) -> Vec<String> {
    if let Ok(document) = opentide_core::node::load(source) {
        let get = |node: &Node, key: &str| node.get(key).cloned();
        return document
            .root()
            .and_then(|root| get(root, "configurations"))
            .and_then(|configurations| get(&configurations, "bitdefender"))
            .and_then(|block| get(&block, "detection"))
            .and_then(|detection| get(&detection, "criteria"))
            .map(|criteria| match &criteria.value {
                Value::Seq(items) => items
                    .iter()
                    .filter_map(|item| item.get("field")?.value.as_str().map(str::to_owned))
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
    }
    crate::yaml_scalar::mapping_keys(source)
        .iter()
        .filter(|key| {
            key.path.len() == 6
                && key.path[..4] == ["configurations", "bitdefender", "detection", "criteria"]
                && key.path[5] == "field"
        })
        .filter_map(|key| {
            let line = &source[key.key_start..];
            let line = &line[..line.find('\n').unwrap_or(line.len())];
            key_value(line, "field").map(str::to_owned)
        })
        .collect()
}

/// Whether the block, as written, may take `action` (the model's
/// `bitdefender_action_scope`).
fn action_allowed_here(action: &str, source: &str) -> bool {
    let keys = block_keys(source);
    let yara = keys.iter().any(|key| key == "yara") && !keys.iter().any(|key| key == "detection");
    let target = current_target(source);
    let fields = criteria_fields(source);
    let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
    action_allowed(action, yara, target.as_deref(), &fields)
}

fn key_items(keys: &[(&str, &str, &str)], existing: &dyn Fn(&str) -> bool) -> Vec<CompletionItem> {
    keys.iter()
        .filter(|(key, _, _)| !existing(key))
        .map(|(key, detail, doc)| {
            CompletionItem::new(*key, "property")
                .with_detail(*detail)
                .with_docs(*doc)
        })
        .collect()
}

/// The `field` of the list item at `offset`.
fn item_field(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    let lines: Vec<(usize, &str)> = source
        .split_inclusive('\n')
        .scan(0usize, |at, line| {
            let start = *at;
            *at += line.len();
            Some((start, line.trim_end_matches(['\n', '\r'])))
        })
        .collect();
    let here = lines
        .iter()
        .rposition(|(start, _)| *start <= offset)
        .unwrap_or(0);
    // Up to the item's dash.
    let mut first = here;
    while first > 0 && !lines.get(first)?.1.trim_start().starts_with("- ") {
        first -= 1;
    }
    let dash = indent(lines.get(first)?.1);
    let mut last = first + 1;
    while let Some((_, line)) = lines.get(last) {
        if !line.trim().is_empty() && indent(line) <= dash {
            break;
        }
        last += 1;
    }
    lines[first..last]
        .iter()
        .filter(|(_, line)| indent(line) <= dash + 2)
        .find_map(|(_, line)| key_value(line, "field").filter(|value| !value.is_empty()))
        .map(str::to_owned)
}

/// The word being typed in a value: after `[`, `,` or the start.
fn value_prefix(cursor: &YamlCursor) -> String {
    let raw = cursor.value.as_deref().unwrap_or("").trim();
    raw.rsplit(['[', ','])
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\''])
        .to_owned()
}

fn starts(prefix: &str, candidate: &str) -> bool {
    candidate
        .to_ascii_lowercase()
        .starts_with(&prefix.to_ascii_lowercase())
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
        let existing = |name: &str| {
            cursor
                .siblings
                .iter()
                .any(|sibling| sibling == name && sibling != &prefix)
        };
        let items: Vec<CompletionItem> = match parent.as_slice() {
            ["detection", "criteria"] => criterion_keys(catalogue, source, offset, &existing),
            [] => {
                let kind = |name: &str| cursor.siblings.iter().any(|sibling| sibling == name);
                let mut keys = BLOCK_KEYS.to_vec();
                // A block sets one kind.
                if kind("detection") {
                    keys.retain(|(key, _, _)| *key != "yara");
                }
                if kind("yara") {
                    keys.retain(|(key, _, _)| *key != "detection");
                }
                key_items(&keys, &existing)
            }
            ["detection"] => key_items(&DETECTION_KEYS, &existing),
            ["yara"] => key_items(&YARA_KEYS, &existing),
            // One of the two.
            ["targets"] if TARGETS_KEYS.iter().any(|(key, _, _)| existing(key)) => Vec::new(),
            ["targets"] => key_items(&TARGETS_KEYS, &existing),
            ["actions"] => ACTIONS
                .iter()
                .filter(|(action, _)| !existing(action) && action_allowed_here(action, source))
                .map(|(action, doc)| {
                    CompletionItem::new(*action, "property")
                        .with_detail("automatic action")
                        .with_docs(*doc)
                })
                .collect(),
            ["actions", "kill_process" | "quarantine"] => STEP_KEYS
                .iter()
                .filter(|key| !existing(key))
                .map(|key| {
                    CompletionItem::new(*key, "property").with_detail("boolean · default false")
                })
                .collect(),
            _ => return None,
        };
        return Some(
            items
                .into_iter()
                .filter(|item| starts(&prefix, &item.label))
                .collect(),
        );
    }
    let path = block_path(cursor)?;
    let prefix = value_prefix(cursor);
    let items: Vec<CompletionItem> = match path.as_slice() {
        ["detection", "target"] => catalogue
            .targets
            .iter()
            .filter(|target| target.detection)
            .map(|target| {
                CompletionItem::new(target.name.clone(), "enum")
                    .with_detail("GravityZone detection target")
                    .with_docs(target_markdown(catalogue, target))
            })
            .collect(),
        ["detection", "criteria", "field"] => {
            let target = current_target(source);
            catalogue
                .fields
                .iter()
                .filter(|field| field.detection)
                .filter(|field| {
                    target.as_deref().is_none_or(|target| {
                        catalogue.target(target).is_none() || field.target == target
                    })
                })
                .map(|field| {
                    CompletionItem::new(field.name.clone(), "field")
                        .with_detail(format!(
                            "{} · {}",
                            field.label,
                            sensors(&field.availability)
                        ))
                        .with_docs(field_markdown(field))
                })
                .collect()
        }
        ["detection", "criteria", "is" | "any"] => {
            let Some(row) = item_field(source, offset).and_then(|field| catalogue.field(&field))
            else {
                return Some(Vec::new());
            };
            row.values
                .iter()
                .map(|value| {
                    CompletionItem::new(value.name.clone(), "enum")
                        .with_detail(format!(
                            "{} · {}",
                            row.name,
                            sensors(row.value_availability(&value.name))
                        ))
                        .with_docs(value_markdown(row, value))
                })
                .collect()
        }
        ["severity"] => SEVERITIES
            .iter()
            .map(|severity| {
                CompletionItem::new(*severity, "enum").with_detail("GravityZone severity")
            })
            .collect(),
        ["actions", "antimalware_scan"] => SCAN_TYPES
            .iter()
            .map(|scan| CompletionItem::new(*scan, "enum").with_detail("scan type"))
            .collect(),
        ["actions", _] => vec![CompletionItem::new("true", "enum").with_detail("boolean")],
        _ => return None,
    };
    Some(
        items
            .into_iter()
            .filter(|item| starts(&prefix, &item.label))
            .collect(),
    )
}

/// A criterion's keys: `field`, then the relations its field takes (no
/// `contains` on a hash), until one is written.
fn criterion_keys(
    catalogue: &Criteria,
    source: &str,
    offset: usize,
    existing: &dyn Fn(&str) -> bool,
) -> Vec<CompletionItem> {
    let field = item_field(source, offset);
    let row = field.as_deref().and_then(|field| catalogue.field(field));
    let mut items = Vec::new();
    if !existing("field") {
        items.push(
            CompletionItem::new("field", "property")
                .with_detail("string · required")
                .with_docs(
                    "The GravityZone field API name (`Process.CommandLine`), from the criteria \
                     catalogue for the `target`.",
                ),
        );
    }
    if RELATIONS.iter().any(|relation| existing(relation)) {
        return items;
    }
    for (relation, doc) in RELATION_DOCS {
        if row.is_some_and(|row| {
            !row.relations.iter().any(|known| known == relation)
                || (row.kind == "hash" && relation == "contains")
        }) {
            continue;
        }
        items.push(
            CompletionItem::new(relation, "property")
                .with_detail("relation")
                .with_docs(doc),
        );
    }
    items
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
                .find(|(known, _)| known == relation)
                .map(|(known, doc)| format!("**{known}** · criterion relation\n\n{doc}")),
            ["actions", action] => ACTIONS
                .iter()
                .find(|(known, _)| known == action)
                .map(|(known, doc)| format!("**{known}** · automatic action\n\n{doc}")),
            _ => None,
        };
    }
    let value = cursor
        .value
        .as_deref()
        .map(|value| value.trim().trim_matches(['"', '\'']))
        .filter(|value| !value.is_empty())?;
    match path.as_slice() {
        ["detection", "target"] => catalogue
            .target(value)
            .map(|target| target_markdown(catalogue, target)),
        ["detection", "criteria", "field"] => catalogue.field(value).map(field_markdown),
        ["detection", "criteria", "is" | "any"] => {
            let row = item_field(source, offset).and_then(|field| catalogue.field(&field))?;
            let word = word_at(source, offset)?;
            row.value(&word).map(|value| value_markdown(row, value))
        }
        _ => None,
    }
}

/// The value word under the cursor (letters, digits, `_`, `/`).
fn word_at(source: &str, offset: usize) -> Option<String> {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '/');
    let mut offset = offset.min(source.len());
    // A host converts positions to char boundaries; stay safe if one did not.
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
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
    (end > start).then(|| source[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(source: &str, at: &str) -> Vec<String> {
        let offset = source.find(at).unwrap() + at.len();
        let cursor = crate::yaml_path::yaml_cursor(source, offset);
        completions(source, offset, &cursor)
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.label)
            .collect()
    }

    #[test]
    fn only_criteria_fields_unlock_process_actions() {
        let source = "configurations:
  bitdefender:
    status: STAGING
    # field: Registry.CreatedBy.Name
    detection:
      target: registry
      alert: File.CreatedBy.Name
      criteria:
      - field: Registry.Key
        is: HKLM\\Run.CreatedBy.x
    actions:\n      \n";
        let actions = complete(source, "actions:\n      ");
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a.as_str(), "kill_process" | "sandbox" | "quarantine")),
            "{actions:?}"
        );
        let unlocked = source.replace(
            "      criteria:\n",
            "      criteria:\n      - field: Registry.CreatedBy.Name\n        is: reg.exe\n",
        );
        let actions = complete(&unlocked, "actions:\n      ");
        assert!(actions.contains(&"kill_process".to_owned()), "{actions:?}");
        assert_eq!(criteria_fields(source), ["Registry.Key"]);
    }

    #[test]
    fn completion_offers_keys_and_filters_actions() {
        let labels = |source: &str, at: &str| complete(source, at);
        let yara = "configurations:
  bitdefender:
    status: STAGING
    yara:
      signature: x
    actions:
      ki
";
        assert!(labels(yara, "      ki").is_empty());
        let yara_any = yara.replace("      ki\n", "      \n");
        let actions = labels(&yara_any, "actions:\n      ");
        assert!(!actions.contains(&"kill_process".to_owned()), "{actions:?}");
        assert!(actions.contains(&"quarantine".to_owned()), "{actions:?}");
        let registry = "configurations:
  bitdefender:
    status: STAGING
    detection:
      target: registry
      criteria:
      - field: Registry.Key
        is: HKLM\\Run
    actions:\n      \n";
        let actions = labels(registry, "actions:\n      ");
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a.as_str(), "kill_process" | "sandbox" | "quarantine")),
            "{actions:?}"
        );
        assert!(actions.contains(&"isolate".to_owned()));
        let root = "configurations:
  bitdefender:
    status: STAGING
    detection:
      target: process
    se
";
        assert_eq!(labels(root, "    se"), ["severity"]);
        let root_all = root.replace("    se\n", "    \n");
        let keys = labels(&root_all, "      target: process\n    ");
        assert!(keys.contains(&"targets".to_owned()), "{keys:?}");
        assert!(!keys.contains(&"yara".to_owned()), "{keys:?}");
        assert!(!keys.contains(&"status".to_owned()), "{keys:?}");
        let detection = "configurations:
  bitdefender:
    status: STAGING
    detection:
      target: process
      al
";
        assert_eq!(labels(detection, "      al"), ["alert"]);
        let targets = "configurations:
  bitdefender:
    status: STAGING
    targets:
      end
";
        assert_eq!(labels(targets, "      end"), ["endpoint_tags"]);
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
        assert_eq!(
            complete(source, "field: Registry.Op"),
            ["Registry.Operation"]
        );
        assert_eq!(complete(source, "any: [key_cr"), ["key_created"]);
        assert_eq!(complete(source, "\n        an"), ["any"]);
        assert_eq!(complete(source, "      iso"), ["isolate"]);
    }

    #[test]
    fn a_hash_takes_no_contains() {
        let source = "configurations:
  bitdefender:
    status: STAGING
    detection:
      target: process
      criteria:
      - field: Process.MD5\n        \n";
        let relations = complete(source, "Process.MD5\n        ");
        assert!(relations.contains(&"is".to_owned()), "{relations:?}");
        assert!(!relations.contains(&"contains".to_owned()), "{relations:?}");
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
    actions:
      isolate: true
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
        assert!(at("isolate").contains("automatic action"));
    }

    #[test]
    fn outside_the_block_the_catalogue_says_nothing() {
        let source = "configurations:\n  sentinel:\n    query: x\n";
        let offset = source.find("query").unwrap() + 1;
        let cursor = crate::yaml_path::yaml_cursor(source, offset);
        assert!(hover(source, offset, &cursor).is_none());
        assert!(completions(source, offset, &cursor).is_none());
    }
}
