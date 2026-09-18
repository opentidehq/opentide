//! Path-aware Tide hover, completions, inlay hints, and completion resolve.

use crate::vocabs::{bundled_vocabs, vocab_for_field};
use crate::yaml_path::{object_schema_kind, yaml_cursor, YamlCursor};
use crate::IndexedObject;
use opentide_core::{offset_to_position, CompletionItem, Position};
use opentide_highlight::{load_tide_fields, tide_field, TideField};

pub const STATUS_VALUES: &[&str] = &["STAGING", "DEVELOPMENT", "PRODUCTION", "DEPRECATED"];
pub const SCHEMA_VALUES: &[&str] = &["rule::1.0", "objective::1.0", "threat::1.0"];

#[derive(Debug, Clone)]
pub struct TideInlay {
    pub position: Position,
    pub label: String,
}

pub fn field_markdown(field: &TideField) -> String {
    let title = field.title.as_deref().unwrap_or(&field.name);
    let ty = field.type_name.as_deref().unwrap_or("any");
    let req = if field.required {
        "required"
    } else {
        "optional"
    };
    let mut md = format!("**{title}** `{ty}` — {req}\n\n");
    if let Some(d) = &field.description {
        md.push_str(d);
    }
    if let Some(v) = &field.vocab {
        md.push_str(&format!("\n\nVocabulary: `{v}`"));
    }
    if let Some(r) = &field.ref_kind {
        md.push_str(&format!("\n\nReferences: `{r}::1.0` UUID"));
    }
    if !field.parents.is_empty() {
        let parents: Vec<&str> = field
            .parents
            .iter()
            .map(|p| if p.is_empty() { "(root)" } else { p.as_str() })
            .collect();
        md.push_str(&format!("\n\nParent: {}", parents.join(", ")));
    }
    md
}

fn schema_allows(field: &TideField, schema: &str) -> bool {
    field.schemas.is_empty() || schema.is_empty() || field.schemas.iter().any(|s| s == schema)
}

fn field_at_parent(field: &TideField, parent: &str) -> bool {
    if field.parents.is_empty() {
        return parent.is_empty();
    }
    field.parents.iter().any(|p| p == parent)
}

fn fields_for_parent(parent: &str, schema: &str) -> Vec<TideField> {
    load_tide_fields()
        .into_iter()
        .filter(|f| field_at_parent(f, parent) && schema_allows(f, schema))
        .collect()
}

pub fn hover_tide(source: &str, offset: usize, workspace: &[IndexedObject]) -> Option<String> {
    let cursor = yaml_cursor(source, offset);
    if cursor.on_key {
        if let Some(name) = &cursor.current_key {
            if let Some(field) = tide_field(name) {
                return Some(field_markdown(field));
            }
        }
        return None;
    }
    if let Some(value) = cursor
        .value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if let Some(uuid) = extract_uuid(value) {
            if let Some(o) = workspace.iter().find(|o| o.uuid == uuid) {
                return Some(format!(
                    "**{}** (`{}::1.0`)\n\n`{}`\n\n{}",
                    o.name, o.object_type, o.uuid, o.path
                ));
            }
        }
        if let Some(name) = &cursor.current_key {
            if let Some(field) = tide_field(name) {
                if let Some(vocab_name) = &field.vocab {
                    if let Some(vocab) = vocab_for_field(vocab_name) {
                        if let Some(md) = vocab.hover(value) {
                            return Some(md);
                        }
                    }
                }
                if name == "status" && STATUS_VALUES.contains(&value) {
                    return Some(format!("**{value}** (object lifecycle)"));
                }
                if name == "schema" && SCHEMA_VALUES.contains(&value) {
                    return Some(format!("**{value}** (Tide object schema)"));
                }
            }
        }
    }
    None
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
    complete_values(&cursor, workspace)
}

fn complete_keys(cursor: &YamlCursor, schema: &str) -> Vec<CompletionItem> {
    let raw_prefix = cursor
        .current_key
        .as_deref()
        .filter(|_| cursor.on_key)
        .unwrap_or("");
    let known_complete = opentide_highlight::tide_field(raw_prefix).is_some()
        && cursor.siblings.iter().any(|s| s == raw_prefix);
    let prefix = if known_complete { "" } else { raw_prefix };
    let existing: std::collections::BTreeSet<&str> =
        cursor.siblings.iter().map(String::as_str).collect();
    fields_for_parent(&cursor.parent, schema)
        .into_iter()
        .filter(|f| {
            (prefix.is_empty() || f.name.starts_with(prefix))
                && (prefix == f.name || !existing.contains(f.name.as_str()))
        })
        .map(|f| {
            let req = if f.required { "required" } else { "optional" };
            let ty = f.type_name.clone().unwrap_or_else(|| "field".into());
            CompletionItem::new(f.name.clone(), "property")
                .with_detail(format!("{ty} · {req}"))
                .with_docs(field_markdown(&f))
        })
        .collect()
}

fn complete_values(cursor: &YamlCursor, workspace: &[IndexedObject]) -> Vec<CompletionItem> {
    let Some(name) = cursor.current_key.as_deref() else {
        return Vec::new();
    };
    let raw_prefix = cursor
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let field = tide_field(name);
    let known_vocab = field
        .and_then(|f| f.vocab.as_deref())
        .and_then(vocab_for_field)
        .is_some_and(|v| v.contains(&raw_prefix));
    let prefix = if known_vocab {
        String::new()
    } else {
        raw_prefix
    };
    let mut items = Vec::new();
    if let Some(field) = field {
        if let Some(vocab_name) = &field.vocab {
            if let Some(vocab) = vocab_for_field(vocab_name) {
                for key in &vocab.keys {
                    if prefix.is_empty()
                        || key
                            .name
                            .to_ascii_lowercase()
                            .starts_with(&prefix.to_ascii_lowercase())
                        || key.title.as_deref().is_some_and(|t| {
                            t.to_ascii_lowercase()
                                .contains(&prefix.to_ascii_lowercase())
                        })
                    {
                        let mut item =
                            CompletionItem::new(key.name.clone(), "enum").with_detail(format!(
                                "{} vocabulary",
                                vocab.title.as_deref().unwrap_or(&vocab.field)
                            ));
                        if let Some(d) = &key.description {
                            item = item.with_docs(d.clone());
                        } else if let Some(t) = &key.title {
                            item = item.with_docs(t.clone());
                        }
                        items.push(item);
                    }
                }
            }
        }
        if let Some(kind) = &field.ref_kind {
            for o in workspace.iter().filter(|o| o.object_type == *kind) {
                if prefix.is_empty() || o.uuid.starts_with(&prefix) || o.name.contains(&prefix) {
                    items.push(
                        CompletionItem::new(o.uuid.clone(), "reference")
                            .with_detail(format!("{} ({kind})", o.name))
                            .with_docs(format!("**{}** `{kind}::1.0`\n\n`{}`", o.name, o.uuid)),
                    );
                }
            }
        }
        if field.type_name.as_deref() == Some("boolean") {
            for b in ["true", "false"] {
                if prefix.is_empty() || b.starts_with(&prefix) {
                    items.push(CompletionItem::new(b, "enum").with_detail("boolean"));
                }
            }
        }
    }
    if name == "status" {
        for s in STATUS_VALUES {
            if prefix.is_empty() || s.starts_with(&prefix) {
                items.push(CompletionItem::new(*s, "enum").with_detail("lifecycle"));
            }
        }
    }
    if name == "schema" {
        for s in SCHEMA_VALUES {
            if prefix.is_empty() || s.starts_with(&prefix) {
                items.push(CompletionItem::new(*s, "enum").with_detail("Tide schema"));
            }
        }
    }
    items
}

pub fn resolve_completion(mut item: CompletionItem) -> CompletionItem {
    if item.documentation.is_some() {
        return item;
    }
    if let Some(field) = tide_field(&item.label) {
        item = item.with_docs(field_markdown(field));
        if item.detail.is_none() {
            item = item.with_detail(field.type_name.clone().unwrap_or_else(|| "field".into()));
        }
        return item;
    }
    for vocab in bundled_vocabs().values() {
        if let Some(md) = vocab.hover(&item.label) {
            return item.with_docs(md);
        }
    }
    item
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
}
