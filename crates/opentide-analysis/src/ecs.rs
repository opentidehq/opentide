//! ECS field intelligence shared by the Elastic engines: field completion,
//! value completion for fields with allowed values, and hover. The engines
//! know the query's own fields; ECS adds the standard ones. The list is never
//! closed (elastic-1.0), so nothing here produces a diagnostic.

use opentide_core::{CompletionItem, LanguageId};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Characters of a dotted field name.
fn is_field_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-')
}

/// The dotted field name being typed at `offset`.
fn prefix_at(text: &str, offset: usize) -> &str {
    let before = &text[..offset.min(text.len())];
    let start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_field_char(*c))
        .last()
        .map_or(before.len(), |(i, _)| i);
    &before[start..]
}

/// The dotted field name under `offset`.
fn word_at(text: &str, offset: usize) -> &str {
    let offset = offset.min(text.len());
    let start = text[..offset]
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_field_char(*c))
        .last()
        .map_or(offset, |(i, _)| i);
    let end = text[offset..]
        .char_indices()
        .find(|(_, c)| !is_field_char(*c))
        .map_or(text.len(), |(i, _)| offset + i);
    text[start..end].trim_end_matches('.')
}

pub(crate) fn hover(text: &str, offset: usize) -> Option<String> {
    opentide_ecs::field(word_at(text, offset)).map(|f| f.markdown())
}

fn field_item(field: &opentide_ecs::EcsField) -> CompletionItem {
    CompletionItem::new(field.name.clone(), "property")
        .with_detail(format!("{} · ECS", field.type_name))
        .with_docs(field.markdown())
}

/// `field:` (kuery, Lucene) or `field ==` / `field :` / `field in (` /
/// `field like` (EQL, ES|QL) right before the cursor: the field and whether
/// the value's opening quote is already typed.
fn value_context(language: LanguageId, before: &str) -> Option<(String, bool)> {
    static KIBANA: OnceLock<Regex> = OnceLock::new();
    static EXPR: OnceLock<Regex> = OnceLock::new();
    let re = match language {
        LanguageId::Kuery | LanguageId::Lucene => KIBANA.get_or_init(|| {
            Regex::new(r#"([\w.@]+)\s*:\s*(?:\((?:[^()]*\s)?)?("?)[\w\-]*$"#).unwrap()
        }),
        _ => EXPR.get_or_init(|| {
            Regex::new(
                r#"(?i)([\w.@]+)\s*(?:==|!=|:|\bin~?\s*\((?:[^()]*,\s*)?|\blike~?)\s*("?)[\w\-]*$"#,
            )
            .unwrap()
        }),
    };
    let caps = re.captures(before)?;
    Some((caps[1].to_string(), !caps[2].is_empty()))
}

pub(crate) fn complete(
    language: LanguageId,
    text: &str,
    offset: usize,
    items: &mut Vec<CompletionItem>,
) {
    let before = &text[..offset.min(text.len())];

    // EQL event categories are `event.category` values: add their docs.
    if let Some(category) = opentide_ecs::field("event.category") {
        for item in items.iter_mut().filter(|i| i.kind == "type") {
            if let Some(v) = category.allowed.iter().find(|v| v.name == item.label) {
                if item.documentation.is_none() {
                    item.documentation =
                        Some(format!("**{}** event category\n\n{}", v.name, v.short));
                }
            }
        }
    }

    if let Some((name, quoted)) = value_context(language, before) {
        if let Some(field) = opentide_ecs::field(&name).filter(|f| !f.allowed.is_empty()) {
            let quote = matches!(language, LanguageId::Eql | LanguageId::Esql) && !quoted;
            items.retain(|i| i.kind != "property");
            for v in &field.allowed {
                let label = if quote {
                    format!("\"{}\"", v.name)
                } else {
                    v.name.clone()
                };
                items.push(
                    CompletionItem::new(label, "enum")
                        .with_detail(format!("{} value · ECS", field.name))
                        .with_docs(v.short.clone()),
                );
            }
            return;
        }
    }

    // Field positions are where the engine already offers the query's fields.
    if !items.iter().any(|i| i.kind == "property") {
        return;
    }
    let prefix = prefix_at(text, offset);
    let known: BTreeSet<String> = items.iter().map(|i| i.label.clone()).collect();
    if prefix.contains('.') {
        let parent = &prefix[..prefix.rfind('.').unwrap_or(0) + 1];
        for field in opentide_ecs::with_prefix(parent) {
            if !known.contains(&field.name) {
                items.push(field_item(field));
            }
        }
        return;
    }
    // Before a dot, offer field-set roots; typing `.` asks again with the
    // full list under that root.
    for root in opentide_ecs::roots() {
        if known.contains(root) || !root.starts_with(prefix) {
            continue;
        }
        match opentide_ecs::field(root) {
            Some(field) => items.push(field_item(field)),
            None => items.push(CompletionItem::new(root, "module").with_detail(format!(
                "ECS field set · {} fields",
                opentide_ecs::with_prefix(&format!("{root}.")).len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(language: LanguageId, text: &str) -> Vec<String> {
        let mut items = match language {
            LanguageId::Kuery => opentide_kuery::completions(text, text.len()),
            LanguageId::Eql => opentide_eql::completions(text, text.len()),
            LanguageId::Esql => opentide_esql::completions(text, text.len()),
            _ => opentide_lucene::completions(text, text.len()),
        };
        complete(language, text, text.len(), &mut items);
        items.into_iter().map(|i| i.label).collect()
    }

    #[test]
    fn dotted_prefix_lists_the_field_set() {
        let found = labels(LanguageId::Kuery, "host.name:x and process.pa");
        assert!(
            found.iter().any(|l| l == "process.parent.name"),
            "{found:?}"
        );
        assert!(!found.iter().any(|l| l == "source.ip"));
    }

    #[test]
    fn roots_before_a_dot() {
        let found = labels(LanguageId::Lucene, "host.name:x AND pro");
        assert!(found.iter().any(|l| l == "process"), "{found:?}");
        assert!(!found.iter().any(|l| l == "@timestamp"));
        let found = labels(LanguageId::Lucene, "host.name:x AND ");
        assert!(found.iter().any(|l| l == "@timestamp"), "{found:?}");
    }

    #[test]
    fn allowed_values_after_a_field() {
        let found = labels(LanguageId::Kuery, "event.category:");
        assert!(found.iter().any(|l| l == "process"), "{found:?}");
        let found = labels(LanguageId::Kuery, "event.category:(process or ");
        assert!(found.iter().any(|l| l == "network"), "{found:?}");
        let found = labels(LanguageId::Eql, "any where event.type == ");
        assert!(found.iter().any(|l| l == "\"start\""), "{found:?}");
        let found = labels(LanguageId::Esql, "FROM logs-* | WHERE event.outcome == \"");
        assert!(found.iter().any(|l| l == "failure"), "{found:?}");
    }

    #[test]
    fn hover_names_type_and_values() {
        let text = "event.category:process";
        let md = hover(text, 3).expect("hover");
        assert!(
            md.contains("`keyword`") && md.contains("Allowed values"),
            "{md}"
        );
        assert!(hover("my.custom.field:1", 3).is_none());
    }
}
