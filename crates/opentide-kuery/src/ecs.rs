//! ECS checks for a query that reads ECS indices (the caller decides, with
//! `opentide_ecs::indices_are_ecs`). Kibana turns `field:value` into a
//! `match` query, a wildcard value into `query_string`, and `field < v` into
//! a `range` query; Elasticsearch fails each one when the value cannot be a
//! term of the field's type (`failed to create query`), and a wildcard on a
//! number, date, ip, or boolean field ("Can only use wildcard queries on
//! keyword and text fields").

use crate::parser;
use crate::syntax::{SyntaxElement, SyntaxKind as K, SyntaxNode};
use crate::{field_value, node_span, range, text};
use opentide_core::Diagnostic;
use opentide_core::LineIndex;
use opentide_ecs::ValueType;

/// A literal as Kibana reads it: its text, and whether it holds an
/// unescaped `*` (a wildcard; quoted strings never do).
fn literal(element: &SyntaxElement, source: &str) -> (String, bool) {
    let raw = text(element.text_range(), source);
    if element.kind() == K::QuotedString {
        let inner = raw.get(1..raw.len().saturating_sub(1)).unwrap_or("");
        return (unescape(inner).0, false);
    }
    unescape(raw)
}

/// Kibana's escapes: `\t`, `\r`, `\n`, `\uXXXX`, and a backslash before any
/// other character keeps that character (`\*`, `\:`, `\and`).
fn unescape(raw: &str) -> (String, bool) {
    let mut out = String::with_capacity(raw.len());
    let mut wildcard = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(ch) => out.push(ch),
                        None => out.push_str(&hex),
                    }
                }
                Some(other) => out.push(other),
                None => {}
            },
            '*' => {
                wildcard = true;
                out.push('*');
            }
            _ => out.push(c),
        }
    }
    (out, wildcard)
}

/// The field a `field` node names, unless it is a pattern (`file.hash.*`).
fn field_name(node: &SyntaxNode, source: &str) -> Option<String> {
    let inner = node
        .children_with_tokens()
        .find(|e| e.kind() != K::Whitespace)?;
    let (name, wildcard) = literal(&inner, source);
    let name = name.trim().to_string();
    (!wildcard && !name.is_empty() && !name.contains('*')).then_some(name)
}

/// Literal values under a `field:` value, through `( ... )` lists.
fn literals(element: SyntaxElement, out: &mut Vec<SyntaxElement>) {
    match element.kind() {
        K::QuotedString | K::UnquotedLiteral => out.push(element),
        _ => {
            if let Some(node) = element.as_node() {
                for child in node.children_with_tokens() {
                    literals(child, out);
                }
            }
        }
    }
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query whose indices hold
/// ECS documents. Fields inside a nested query (`a:{ b:c }`) are relative to
/// their parent and are not checked. A query that does not parse gets none.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    let parsed = parser::parse_memo(source);
    let (root, parse) = &*parsed;
    if !parse.errors.is_empty() {
        return Vec::new();
    }
    let lines = LineIndex::new(source);
    let mut out = Vec::new();
    for node in root.descendants() {
        let kind = node.kind();
        if !matches!(kind, K::FieldValueExpression | K::RangeExpression)
            || node.ancestors().any(|a| a.kind() == K::NestedQuery)
        {
            continue;
        }
        let Some(field) = node.children().find(|c| c.kind() == K::Field) else {
            continue;
        };
        let Some(name) = field_name(&field, source) else {
            continue;
        };
        if let Some(d) = opentide_ecs::unknown_field_diagnostic(&name, || {
            range(&lines, node_span(field.text_range()))
        }) {
            out.push(d);
            continue;
        }
        let Some((value_type, type_name)) = opentide_ecs::field_type(&name) else {
            continue;
        };
        let value = if kind == K::FieldValueExpression {
            field_value(&node)
        } else {
            node.children_with_tokens()
                .skip_while(|e| !matches!(e.kind(), K::Lt | K::Lte | K::Gt | K::Gte))
                .skip(1)
                .find(|e| e.kind() != K::Whitespace)
        };
        let Some(value) = value else {
            continue;
        };
        let mut values = Vec::new();
        literals(value, &mut values);
        for v in values {
            let (value_text, wildcard) = literal(&v, source);
            let at = || range(&lines, node_span(v.text_range()));
            if kind == K::FieldValueExpression && wildcard {
                // `field:*` asks whether the field exists.
                if value_text.trim() == "*" || value_type == ValueType::String {
                    continue;
                }
                out.push(opentide_ecs::type_mismatch(
                    &name,
                    type_name,
                    "a wildcard",
                    at(),
                ));
                continue;
            }
            // A range compares dates in any format Kibana sends; only
            // numbers and addresses are checked there.
            if kind == K::RangeExpression
                && !matches!(value_type, ValueType::Numeric | ValueType::Ip)
            {
                continue;
            }
            if let Some(problem) = opentide_ecs::value_problem(value_type, &value_text) {
                out.push(opentide_ecs::type_mismatch(
                    &name,
                    type_name,
                    &format!("the value `{}`, which {problem},", value_text.trim()),
                    at(),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::{Severity, codes};

    fn found(query: &str) -> Vec<(String, Severity)> {
        ecs_diagnostics(query)
            .into_iter()
            .map(|d| (d.code, d.severity))
            .collect()
    }

    fn mismatch(query: &str) -> bool {
        found(query)
            .iter()
            .any(|(c, s)| c == codes::ECS_TYPE_MISMATCH && *s == Severity::Error)
    }

    #[test]
    fn wildcards_and_values_the_type_cannot_take() {
        assert!(mismatch("source.ip: 10.*"));
        assert!(mismatch("process.pid: 12*"));
        assert!(mismatch("@timestamp: 2024*"));
        assert!(mismatch("source.ip: abc"));
        assert!(mismatch("source.port: \"http\""));
        assert!(mismatch("process.interactive: maybe"));
        assert!(mismatch("source.port >= abc"));
        assert!(mismatch(
            "host.name: x and destination.ip:(10.0.0.1 or 192.168.*)"
        ));
    }

    #[test]
    fn what_elasticsearch_accepts() {
        for query in [
            "source.ip: *",
            "source.ip:(* and not (127.0.0.1 or \"::1\"))",
            "destination.ip:(10.0.0.0/8 or 172.16.0.0/12 or \"FE80::/10\")",
            "source.ip >= 10.0.0.0",
            "process.pid: 4624",
            "process.pid: \"4624\"",
            "process.name: cmd*",
            "process.command_line.text: *powershell*",
            "@timestamp >= now-1d",
            "@timestamp: 2024-01-01",
            "process.interactive: true",
            "file.hash.*: *",
            "user:{ name: x* }",
            "winlog.event_id: 4*",
            "process.name: \\*",
        ] {
            assert!(found(query).is_empty(), "{query}: {:?}", found(query));
        }
    }

    #[test]
    fn near_misses_warn() {
        let d = ecs_diagnostics("process.nmae: cmd.exe");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, codes::ECS_UNKNOWN_FIELD);
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(d[0].suggestion.as_deref(), Some("process.name"));
        assert!(ecs_diagnostics("process.my_field: x and labels.team: y").is_empty());
    }
}
