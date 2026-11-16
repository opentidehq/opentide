//! ECS checks for an Elastic `query_string` that reads ECS indices (the
//! caller decides, with `opentide_ecs::indices_are_ecs`). Elastic Security
//! runs `query_string` with `lenient: false`, so a term the field's type
//! cannot parse, and a wildcard, regexp, or fuzzy term on a number, date, ip,
//! or boolean field, fail the search
//! (`crates/testdata/oracles/elasticsearch/lucene`).

use crate::Cx;
use crate::syntax::SyntaxKind as K;
use crate::tree::{Node, Tree, walk_with_ancestors};
use opentide_core::{Diagnostic, LineIndex};
use opentide_ecs::ValueType;

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

fn phrase_text(node: &Node, source: &str) -> String {
    let raw = node.text(source);
    unescape(raw.get(1..raw.len().saturating_sub(1)).unwrap_or(""))
}

/// The term-level queries a field applies to: the body itself, or every
/// clause of a `( ... )` group that does not name its own field.
/// Iterative: a group nests a thousand levels deep.
fn term_queries(node: &Node, out: &mut Vec<Node>) {
    let mut stack = vec![node.clone()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            K::TermQuery | K::PhraseQuery | K::RangeQuery | K::RegexpQuery => out.push(node),
            K::FieldQuery => {}
            _ => stack.extend(node.children().into_iter().rev()),
        }
    }
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query (Elastic dialect)
/// whose indices hold ECS documents. A query that does not parse gets none.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    let tree = Tree::parse(source);
    if tree.has_error() {
        return Vec::new();
    }
    let lines = LineIndex::new(source);
    let cx = Cx {
        source,
        lines: &lines,
    };
    let mut out = Vec::new();
    walk_with_ancestors(&tree.root(), |node, _| {
        if node.kind() == K::FieldQuery {
            check_field_query(node, cx, &mut out);
        }
    });
    out
}

fn check_field_query(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let Some(field) = node.field() else {
        return;
    };
    // `book.\*:` and `*:` name patterns, not fields.
    let Some(term) = field.first_child().filter(|t| t.kind() == K::Term) else {
        return;
    };
    let name = unescape(term.text(source));
    if name == "_exists_" {
        return;
    }
    if let Some(d) = opentide_ecs::unknown_field_diagnostic(&name, || cx.range(field.span())) {
        out.push(d);
        return;
    }
    let Some((value_type, type_name)) = opentide_ecs::field_type(&name) else {
        return;
    };
    if value_type == ValueType::String {
        return;
    }
    let Some(body) = node.query() else {
        return;
    };
    let mut queries = Vec::new();
    term_queries(&body, &mut queries);
    let mut mismatch = |what: String, at: &Node| {
        out.push(opentide_ecs::type_mismatch(
            &name,
            type_name,
            &what,
            cx.range(at.span()),
        ));
    };
    let value = |value: &str, at: &Node, mismatch: &mut dyn FnMut(String, &Node)| {
        if let Some(problem) = opentide_ecs::value_problem(value_type, value) {
            mismatch(
                format!("the value `{}`, which {problem},", value.trim()),
                at,
            );
        }
    };
    for query in queries {
        match query.kind() {
            K::TermQuery => {
                let Some(term) = query.term() else {
                    continue;
                };
                let fuzzy = query.children().iter().any(|c| c.kind() == K::Fuzzy);
                match term.kind() {
                    K::WildcardTerm => mismatch("a wildcard".into(), &term),
                    K::Term if fuzzy => mismatch("a fuzzy query".into(), &query),
                    K::Term => value(&unescape(term.text(source)), &term, &mut mismatch),
                    // `field:*` asks whether the field exists.
                    _ => {}
                }
            }
            K::PhraseQuery => {
                if let Some(phrase) = query.phrase() {
                    value(&phrase_text(&phrase, source), &phrase, &mut mismatch);
                }
            }
            K::RegexpQuery => mismatch("a regexp".into(), &query),
            K::RangeQuery if matches!(value_type, ValueType::Numeric | ValueType::Ip) => {
                for upper in [false, true] {
                    let Some(b) = query.bound(upper) else {
                        continue;
                    };
                    let v = if b.kind() == K::Phrase {
                        phrase_text(&b, source)
                    } else {
                        unescape(b.text(source))
                    };
                    if v != "*" {
                        value(&v, &b, &mut mismatch);
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
        // crates/testdata/oracles/elasticsearch/lucene: ERR with `lenient: false`.
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
