//! Path-aware Tide hover, completions, inlay hints, and completion resolve.
//!
//! Field identity is `(schema family, YAML path)` from the generated OpenTide
//! catalog. Enum completions come from that node's schema enum. Empty-enum
//! sentinels are already dropped. Cross-object UUID fields use `ref`.

use crate::IndexedObject;
use crate::yaml_path::{YamlCursor, object_schema_kind, yaml_cursor};
use opentide_core::{CompletionItem, Position, offset_to_position};
use opentide_highlight::{TideField, load_tide_fields, tide_children, tide_field_at};

#[derive(Debug, Clone)]
pub struct TideInlay {
    pub position: Position,
    pub label: String,
}

pub fn field_markdown(field: &TideField) -> String {
    let title = if field.title.is_empty() {
        field.name.as_str()
    } else {
        field.title.as_str()
    };
    let ty = if field.type_name.is_empty() {
        "any"
    } else {
        field.type_name.as_str()
    };
    let req = if field.required {
        "required"
    } else {
        "optional"
    };
    let mut md = format!("**{title}** `{ty}` — {req}\n\n");
    if !field.description.is_empty() {
        md.push_str(&field.description);
        md.push_str("\n\n");
    }
    if field.markdown {
        md.push_str("Markdown text.\n\n");
    }
    if field.array && field.min_items.unwrap_or(0) >= 1 {
        md.push_str("Non-empty list.\n\n");
    }
    if let Some(r) = &field.ref_kind {
        md.push_str(&format!("References `{r}::1.0` objects by UUID.\n\n"));
    }
    if let Some(c) = &field.const_value {
        md.push_str(&format!("Const: `{c}`\n\n"));
    }
    if let Some(d) = &field.default_value {
        md.push_str(&format!("Default: `{d}`\n\n"));
    }
    md
}

fn field_for(source: &str, cursor: &YamlCursor) -> Option<&'static TideField> {
    let path = cursor.field_path();
    if path.is_empty() {
        return None;
    }
    let schema = object_schema_kind(source);
    if !schema.is_empty() {
        return tide_field_at(&schema, &path);
    }
    let matches: Vec<_> = ["rule", "objective", "threat"]
        .into_iter()
        .filter_map(|family| tide_field_at(family, &path))
        .collect();
    match matches.as_slice() {
        [field] => Some(*field),
        _ => None,
    }
}

fn is_block_scalar_marker(value: &str) -> bool {
    matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+")
        || value.starts_with('|')
        || value.starts_with('>')
}

fn hover_markdown(field: &TideField, cursor: &YamlCursor) -> String {
    let mut md = field_markdown(field);
    if !cursor.path.is_empty() {
        md.push_str(&format!("\n\nPath: `{}`", cursor.path.join(".")));
    }
    md
}

fn enum_hover(field: &TideField, value: &str) -> Option<String> {
    let index = field.enum_values.iter().position(|item| item == value)?;
    let doc = field.enum_docs.get(index).map(String::as_str).unwrap_or("");
    let mut md = format!("**{value}**\n\n`{}`", field.path);
    if !doc.is_empty() {
        md.push_str("\n\n");
        md.push_str(doc);
    }
    Some(md)
}

pub fn hover_tide(source: &str, offset: usize, workspace: &[IndexedObject]) -> Option<String> {
    let cursor = yaml_cursor(source, offset);
    if cursor.on_key {
        return field_for(source, &cursor).map(|field| hover_markdown(field, &cursor));
    }
    if let Some(value) = cursor
        .value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && !is_block_scalar_marker(v))
    {
        if let Some(uuid) = extract_uuid(value) {
            if let Some(o) = workspace.iter().find(|o| o.uuid == uuid) {
                return Some(format!(
                    "**{}** (`{}::1.0`)\n\n`{}`\n\n{}",
                    o.name, o.object_type, o.uuid, o.path
                ));
            }
        }
        if let Some(field) = field_for(source, &cursor) {
            if let Some(md) = enum_hover(field, value) {
                return Some(md);
            }
            if field.default_value.as_deref() == Some(value) {
                return Some(format!("**{value}**\n\nDefault for `{}`.", field.path));
            }
            if field.const_value.as_deref() == Some(value) {
                return Some(format!("**{value}**\n\nConst for `{}`.", field.path));
            }
        }
    }
    field_for(source, &cursor).map(|field| hover_markdown(field, &cursor))
}

pub fn completions_tide(
    source: &str,
    offset: usize,
    workspace: &[IndexedObject],
) -> Vec<CompletionItem> {
    let cursor = yaml_cursor(source, offset);
    let schema = object_schema_kind(source);
    if cursor.on_key || cursor.value.is_none() {
        return complete_keys(&cursor, &schema);
    }
    // An empty `- ` under an array of objects completes that object's keys.
    // An empty `- ` under an array of enums completes the enum.
    if cursor.in_list && cursor.current_key.is_none() {
        let path = cursor.field_path();
        if tide_children(&schema, &path)
            .iter()
            .any(|field| !field.hidden)
        {
            return complete_keys(&cursor, &schema);
        }
    }
    complete_values(source, &cursor, workspace)
}

fn complete_keys(cursor: &YamlCursor, schema: &str) -> Vec<CompletionItem> {
    let raw_prefix = cursor
        .current_key
        .as_deref()
        .filter(|_| cursor.on_key)
        .unwrap_or("");
    let parent = cursor.container_path();
    let known_complete = tide_field_at(schema, &join_path(&parent, raw_prefix)).is_some()
        && cursor.siblings.iter().any(|sibling| sibling == raw_prefix);
    let prefix = if known_complete { "" } else { raw_prefix };
    let existing: std::collections::BTreeSet<&str> =
        cursor.siblings.iter().map(String::as_str).collect();
    let mut fields = tide_children(schema, &parent);
    if fields.is_empty() && schema.is_empty() {
        fields = tide_children("rule", &parent);
    }
    fields
        .into_iter()
        .filter(|field| !field.hidden)
        .filter(|field| {
            (prefix.is_empty() || field.name.starts_with(prefix))
                && (prefix == field.name || !existing.contains(field.name.as_str()))
        })
        .map(|field| {
            let req = if field.required {
                "required"
            } else {
                "optional"
            };
            let ty = if field.type_name.is_empty() {
                "field"
            } else {
                field.type_name.as_str()
            };
            CompletionItem::new(field.name.clone(), "property")
                .with_detail(format!("{ty} · {req}"))
                .with_docs(field_markdown(field))
        })
        .collect()
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}.{name}")
    }
}

fn value_prefix(cursor: &YamlCursor, field: Option<&TideField>) -> String {
    let raw = cursor
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let known = field.is_some_and(|field| field.enum_values.iter().any(|value| value == &raw));
    if known { String::new() } else { raw }
}

fn prefix_match(prefix: &str, candidate: &str) -> bool {
    prefix.is_empty()
        || candidate
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
}

fn complete_values(
    source: &str,
    cursor: &YamlCursor,
    workspace: &[IndexedObject],
) -> Vec<CompletionItem> {
    let Some(field) = field_for(source, cursor) else {
        return Vec::new();
    };
    if field.hidden {
        return Vec::new();
    }
    let prefix = value_prefix(cursor, Some(field));
    let mut items = Vec::new();
    for (index, value) in field.enum_values.iter().enumerate() {
        if !prefix_match(&prefix, value) {
            continue;
        }
        let mut item = CompletionItem::new(value.clone(), "enum")
            .with_detail(format!("{} {}", field.schema, field.path));
        if let Some(doc) = field.enum_docs.get(index).filter(|doc| !doc.is_empty()) {
            item = item.with_docs(doc.clone());
        }
        items.push(item);
    }
    if let Some(kind) = &field.ref_kind {
        for object in workspace
            .iter()
            .filter(|object| object.object_type == *kind)
        {
            if prefix.is_empty()
                || object.uuid.starts_with(&prefix)
                || object.name.contains(&prefix)
            {
                items.push(
                    CompletionItem::new(object.uuid.clone(), "reference")
                        .with_detail(format!("{} ({kind})", object.name))
                        .with_docs(format!(
                            "**{}** `{kind}::1.0`\n\n`{}`",
                            object.name, object.uuid
                        )),
                );
            }
        }
    }
    if field.type_name == "boolean" {
        for value in ["true", "false"] {
            if prefix_match(&prefix, value) {
                items.push(CompletionItem::new(value, "enum").with_detail("boolean"));
            }
        }
    }
    items
}

pub fn resolve_completion(mut item: CompletionItem) -> CompletionItem {
    if item.documentation.is_some() {
        return item;
    }
    if let Some(field) = field_from_detail(item.detail.as_deref()) {
        if let Some(index) = field
            .enum_values
            .iter()
            .position(|value| value == &item.label)
        {
            if let Some(doc) = field.enum_docs.get(index).filter(|doc| !doc.is_empty()) {
                let label = item.label.clone();
                return item.with_docs(format!("**{label}**\n\n{doc}"));
            }
        }
    }
    for field in load_tide_fields() {
        if let Some(index) = field
            .enum_values
            .iter()
            .position(|value| value == &item.label)
        {
            if let Some(doc) = field.enum_docs.get(index).filter(|doc| !doc.is_empty()) {
                let label = item.label.clone();
                return item.with_docs(format!("**{label}**\n\n{doc}"));
            }
        }
    }
    if let Some(field) = resolve_field_by_name(&item.label) {
        item = item.with_docs(field_markdown(field));
        if item.detail.is_none() {
            let ty = if field.type_name.is_empty() {
                "field".to_string()
            } else {
                field.type_name.clone()
            };
            item = item.with_detail(ty);
        }
    }
    item
}

fn field_from_detail(detail: Option<&str>) -> Option<&'static TideField> {
    let detail = detail?;
    let (schema, path) = detail.split_once(' ')?;
    tide_field_at(schema, path)
}

/// Name-only resolve prefers the document-root field (`path == name`).
fn resolve_field_by_name(label: &str) -> Option<&'static TideField> {
    let named: Vec<_> = load_tide_fields()
        .into_iter()
        .filter(|field| field.name == label)
        .collect();
    named
        .iter()
        .copied()
        .find(|field| field.path == label)
        .or_else(|| (named.len() == 1).then(|| named[0]))
}

fn document_uuid(source: &str) -> Option<String> {
    let idx = source.find("uuid:")?;
    let rest = source[idx + 5..].trim_start();
    let token = rest
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .next()
        .unwrap_or("");
    (token.len() == 36).then(|| token.to_string())
}

pub fn inlay_hints(source: &str, workspace: &[IndexedObject]) -> Vec<TideInlay> {
    let self_uuid = document_uuid(source);
    let re = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .expect("uuid");
    let mut out = Vec::new();
    for m in re.find_iter(source) {
        if self_uuid.as_deref() == Some(m.as_str()) {
            continue;
        }
        if let Some(obj) = workspace.iter().find(|o| o.uuid == m.as_str()) {
            out.push(TideInlay {
                position: offset_to_position(source, m.end()),
                label: format!("{} {}", obj.object_type, obj.name),
            });
        }
    }
    out
}

pub fn extract_uuid(text: &str) -> Option<String> {
    let re = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .ok()?;
    re.find(text).map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  tlp: clear
description: |
  hello
detection_model: 00000000-0000-4000-8002-000000000001
"#;

    #[test]
    fn hover_on_description_key() {
        let off = RULE.find("description:").unwrap();
        let md = hover_tide(RULE, off, &[]).expect("hover");
        assert!(md.contains("Description"), "{md}");
        assert!(md.to_lowercase().contains("markdown"), "{md}");
        assert!(md.contains("required"), "{md}");
    }

    #[test]
    fn hover_on_tlp_value() {
        let off = RULE.find("clear").unwrap();
        let md = hover_tide(RULE, off, &[]).expect("tlp");
        assert!(md.to_lowercase().contains("clear"), "{md}");
        assert!(md.contains("tlp"), "{md}");
    }

    #[test]
    fn metadata_completions_are_path_scoped() {
        let off = RULE.find("  tlp:").unwrap();
        let items = completions_tide(RULE, off, &[]);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(
            items.iter().any(|i| i.label == "author"),
            "missing author in {labels:?}"
        );
        assert!(
            items.iter().any(|i| i
                .documentation
                .as_ref()
                .is_some_and(|d| d.contains("Author"))),
            "field docs"
        );
        assert!(
            !items
                .iter()
                .any(|i| i.label == "clear" || i.label == "High"),
            "must not dump vocabs at key position: {labels:?}"
        );
        assert!(
            !items.iter().any(|i| i.label == "query"),
            "query is not a metadata key: {labels:?}"
        );
    }

    #[test]
    fn tlp_value_completions_only_tlp() {
        let off = RULE.find("clear").unwrap() + 1;
        let items = completions_tide(RULE, off, &[]);
        assert!(items.iter().any(|i| i.label == "amber"), "{items:?}");
        assert!(items.iter().all(|i| i.kind == "enum"), "{items:?}");
        assert!(!items.iter().any(|i| i.label == "High"));
    }

    #[test]
    fn hover_on_key_includes_yaml_path() {
        let off = RULE.find("description:").unwrap();
        let md = hover_tide(RULE, off, &[]).expect("hover");
        assert!(md.contains("Path: `description`"), "{md}");
    }

    #[test]
    fn hover_inside_markdown_block_falls_back_to_field_docs() {
        let off = RULE.find("  hello").unwrap();
        let md = hover_tide(RULE, off, &[]).expect("block hover");
        assert!(md.contains("Description"), "{md}");
        assert!(md.contains("Path: `description`"), "{md}");
    }

    #[test]
    fn detection_model_is_an_optional_objective_reference() {
        let off = RULE.find("detection_model:").unwrap();
        let md = hover_tide(RULE, off, &[]).expect("hover");
        assert!(md.contains("optional"), "{md}");
        assert!(md.contains("objective"), "{md}");
        assert!(!md.to_lowercase().contains("required"), "{md}");
    }

    #[test]
    fn status_value_does_not_invent_lifecycle_enums() {
        let src = "name: R\nmetadata:\n  schema: rule::1.0\nstatus: ST\n";
        let off = src.find("ST").unwrap() + 2;
        let items = completions_tide(src, off, &[]);
        let labels: Vec<&str> = items.iter().map(|item| item.label.as_str()).collect();
        assert!(
            !labels.iter().any(|label| {
                matches!(
                    *label,
                    "STAGING" | "PRODUCTION" | "DEVELOPMENT" | "DEPRECATED"
                )
            }),
            "{labels:?}"
        );
    }

    #[test]
    fn impact_list_completions_come_from_schema_enum() {
        let src = "name: T\nmetadata:\n  schema: threat::1.0\nthreat:\n  impact:\n  - \n";
        let off = src.find("- ").unwrap() + 2;
        let items = completions_tide(src, off, &[]);
        assert!(
            items.iter().any(|item| item.label == "Nuisance"),
            "{:?}",
            items.iter().map(|item| &item.label).collect::<Vec<_>>()
        );
        assert!(items.iter().all(|item| item.kind == "enum"), "{items:?}");
    }

    #[test]
    fn next_search_item_completes_purpose_again() {
        let src = "name: R\nmetadata:\n  schema: rule::1.0\nresponse:\n  procedure:\n    searches:\n    - purpose: first\n      system: defender_for_endpoint\n    - \n";
        let off = src.rfind("- ").unwrap() + 2;
        let items = completions_tide(src, off, &[]);
        assert!(
            items.iter().any(|item| item.label == "purpose"),
            "{:?}",
            items.iter().map(|item| &item.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn metadata_schema_const_is_not_every_family() {
        let off = RULE.find("rule::1.0").unwrap() + 2;
        let items = completions_tide(RULE, off, &[]);
        let labels: Vec<&str> = items.iter().map(|item| item.label.as_str()).collect();
        assert!(labels.contains(&"rule::1.0"), "{labels:?}");
        assert!(!labels.contains(&"threat::1.0"), "{labels:?}");
        assert!(!labels.contains(&"objective::1.0"), "{labels:?}");
    }
}
