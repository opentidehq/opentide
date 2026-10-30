//! ECS checks for an Elastic `query_string` that reads ECS indices (the
//! caller decides, with `opentide_ecs::indices_are_ecs`). Elastic Security
//! runs `query_string` with `lenient: false`, so a term the field's type
//! cannot parse, and a wildcard, regexp, or fuzzy term on a number, date, ip,
//! or boolean field, fail the search
//! (`testdata/oracles/elasticsearch/lucene`).

use crate::{range, text};
use opentide_core::{Diagnostic, LanguageId};
use opentide_ecs::ValueType;
use opentide_syntax::{node_span, parse as ts_parse};
use tree_sitter::Node;

/// A term with Lucene's backslash escapes removed.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn phrase_text(node: Node, source: &str) -> String {
    let raw = text(node, source);
    unescape(raw.get(1..raw.len().saturating_sub(1)).unwrap_or(""))
}

/// The term-level queries a field applies to: the body itself, or every
/// clause of a `( ... )` group that does not name its own field.
fn term_queries<'t>(node: Node<'t>, out: &mut Vec<Node<'t>>) {
    match node.kind() {
        "term_query" | "phrase_query" | "range_query" | "regexp_query" => out.push(node),
        "field_query" => {}
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                term_queries(child, out);
            }
        }
    }
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query (Elastic dialect)
/// whose indices hold ECS documents. A query that does not parse gets none.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    let Some(tree) = ts_parse(LanguageId::Lucene, source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    let mut out = Vec::new();
    crate::walk(root, &mut |node| {
        if node.kind() == "field_query" {
            check_field_query(node, source, &mut out);
        }
    });
    out
}

fn check_field_query(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let Some(field) = node.child_by_field_name("field") else {
        return;
    };
    // `book.\*:` and `*:` name patterns, not fields.
    let Some(term) = field.named_child(0).filter(|t| t.kind() == "term") else {
        return;
    };
    let name = unescape(text(term, source));
    if name == "_exists_" {
        return;
    }
    if let Some(d) =
        opentide_ecs::unknown_field_diagnostic(&name, || range(source, node_span(field)))
    {
        out.push(d);
        return;
    }
    let Some((value_type, type_name)) = opentide_ecs::field_type(&name) else {
        return;
    };
    if value_type == ValueType::String {
        return;
    }
    let Some(body) = node.child_by_field_name("query") else {
        return;
    };
    let mut queries = Vec::new();
    term_queries(body, &mut queries);
    let mut mismatch = |what: String, at: Node| {
        out.push(opentide_ecs::type_mismatch(
            &name,
            type_name,
            &what,
            range(source, node_span(at)),
        ));
    };
    let value = |value: &str, at: Node, mismatch: &mut dyn FnMut(String, Node)| {
        if let Some(problem) = opentide_ecs::value_problem(value_type, value) {
            mismatch(
                format!("the value `{}`, which {problem},", value.trim()),
                at,
            );
        }
    };
    for query in queries {
        match query.kind() {
            "term_query" => {
                let Some(term) = query.child_by_field_name("term") else {
                    continue;
                };
                let mut cursor = query.walk();
                let fuzzy = query
                    .named_children(&mut cursor)
                    .any(|c| c.kind() == "fuzzy");
                match term.kind() {
                    "wildcard_term" => mismatch("a wildcard".into(), term),
                    "term" if fuzzy => mismatch("a fuzzy query".into(), query),
                    "term" => value(&unescape(text(term, source)), term, &mut mismatch),
                    // `field:*` asks whether the field exists.
                    _ => {}
                }
            }
            "phrase_query" => {
                if let Some(phrase) = query.child_by_field_name("phrase") {
                    value(&phrase_text(phrase, source), phrase, &mut mismatch);
                }
            }
            "regexp_query" => mismatch("a regexp".into(), query),
            "range_query" if matches!(value_type, ValueType::Numeric | ValueType::Ip) => {
                for bound in ["lower", "upper"] {
                    let Some(b) = query.child_by_field_name(bound) else {
                        continue;
                    };
                    let v = if b.kind() == "phrase" {
                        phrase_text(b, source)
                    } else {
                        unescape(text(b, source))
                    };
                    if v != "*" {
                        value(&v, b, &mut mismatch);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::{Severity, codes};

    fn mismatch(query: &str) -> bool {
        ecs_diagnostics(query)
            .iter()
            .any(|d| d.code == codes::ECS_TYPE_MISMATCH && d.severity == Severity::Error)
    }

    #[test]
    fn rejected_by_elasticsearch() {
        // testdata/oracles/elasticsearch/lucene: ERR with `lenient: false`.
        for query in [
            "process.pid:12*",
            "process.pid:/12.*/",
            "process.pid:[a TO b]",
            "process.interactive:abc",
            "@timestamp:abc",
            "source.ip:abc",
            "process.pid:abc",
            "source.ip:10.*",
            "host.name:x AND source.port:(80 OR http)",
            "process.pid:12~",
        ] {
            assert!(mismatch(query), "{query}: {:?}", ecs_diagnostics(query));
        }
    }

    #[test]
    fn accepted_by_elasticsearch() {
        for query in [
            "process.pid:4624",
            "source.ip:10.0.0.0\\/8",
            "source.ip:\"10.0.0.0/8\"",
            "source.ip:[10.0.0.0 TO 10.255.255.255]",
            "source.port:[1024 TO *]",
            "source.ip:*",
            "@timestamp:[now-1d TO now]",
            "process.name:cmd* AND process.command_line:/.*-enc.*/",
            "process.interactive:true",
            "winlog.event_id:46*",
            "file.hash.\\*:x",
            "_exists_:process.pid",
        ] {
            assert!(
                ecs_diagnostics(query).is_empty(),
                "{query}: {:?}",
                ecs_diagnostics(query)
            );
        }
    }

    #[test]
    fn near_misses_warn() {
        let d = ecs_diagnostics("process.nmae:cmd.exe");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].code, codes::ECS_UNKNOWN_FIELD);
        assert_eq!(d[0].suggestion.as_deref(), Some("process.name"));
    }
}
