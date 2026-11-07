//! ECS checks for an EQL query that reads ECS indices (the caller decides,
//! with `opentide_ecs::indices_are_ecs`). The Verifier types each field from
//! the index mapping; on ECS indices that mapping is ECS, so the rules the
//! engine can only hint about without one become errors here. Each rule is a
//! verdict recorded against an ECS-mapped index on every release
//! (`testdata/oracles/elasticsearch/eql-*`): `:`, `like`, and `regex` on a
//! non-string field, an `in` list of numbers on a string field, a function
//! argument or arithmetic operand of the wrong type, and an object used as a
//! value. `==` and `!=` convert their constant, so they are never reported.

use crate::semantics::{Want, function_name, named_children, parameters, strip_parens};
use crate::{parse_prepared, range, text};
use opentide_core::{Diagnostic, codes};
use opentide_ecs::ValueType;
use opentide_syntax::node_span;
use tree_sitter::Node;

/// The dotted name a `field` node reads, and whether it is optional (`?x`).
/// `None` for an array element (`process.args[0]`).
fn field_name(node: Node, source: &str) -> Option<(String, bool)> {
    let mut parts = Vec::new();
    let mut optional = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "optional_marker" => optional = true,
            "identifier" => parts.push(text(child, source).to_string()),
            "quoted_identifier" => {
                let t = text(child, source);
                parts.push(t[1..t.len().saturating_sub(1)].replace("``", "`"));
            }
            "comment" => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| (parts.join("."), optional))
}

/// The field an expression is, when it is one (through parentheses).
fn as_field(node: Node, source: &str) -> Option<String> {
    let node = strip_parens(node);
    (node.kind() == "field")
        .then(|| field_name(node, source))
        .flatten()
        .map(|(name, _)| name)
}

fn is_number(node: Node) -> bool {
    let node = strip_parens(node);
    match node.kind() {
        "number" => true,
        "unary_expression" => node.child_by_field_name("operand").is_some_and(is_number),
        _ => false,
    }
}

/// A field whose ECS type `want` rejects, with that type.
fn mismatch(want: Want, name: &str) -> Option<&'static str> {
    let (value_type, type_name) = opentide_ecs::field_type(name)?;
    let accepted = match want {
        Want::Str => value_type == ValueType::String,
        Want::Int | Want::Numeric => value_type == ValueType::Numeric,
        Want::Bool => value_type == ValueType::Boolean,
        Want::Ip => value_type == ValueType::Ip,
        // A field is never a constant; the engine reports that already.
        Want::StrConst => true,
    };
    (!accepted).then_some(type_name)
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query whose indices hold
/// ECS documents. A query that does not parse gets none.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    let Some((tree, _prepared)) = parse_prepared(source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    let mut out = Vec::new();
    crate::walk(root, &mut |node| check(node, source, &mut out));
    out
}

fn check(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let at = |n: Node| range(source, node_span(n));
    match node.kind() {
        "field" => {
            let Some((name, optional)) = field_name(node, source) else {
                return;
            };
            // `?x` is written for a field that may be missing: not a typo.
            if optional {
                return;
            }
            if let Some(d) = opentide_ecs::unknown_field_diagnostic(&name, || at(node)) {
                out.push(d);
            } else if opentide_ecs::is_object(&name) {
                out.push(Diagnostic::error(
                    codes::ECS_TYPE_MISMATCH,
                    format!(
                        "`{name}` is an object in ECS {}: Elasticsearch EQL reads only its subfields",
                        opentide_ecs::version()
                    ),
                    at(node),
                ));
            }
        }
        "predicate_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            let Some(subject) = node.child_by_field_name("subject") else {
                return;
            };
            let Some(name) = as_field(subject, source) else {
                return;
            };
            match operator {
                ":" | "like" | "like~" | "regex" | "regex~" => {
                    if let Some(type_name) = mismatch(Want::Str, &name) {
                        out.push(opentide_ecs::type_mismatch(
                            &name,
                            type_name,
                            &format!("`{operator}`, which compares strings,"),
                            at(subject),
                        ));
                    }
                }
                "in" => {
                    let values = named_children(node, "values");
                    let is_string = opentide_ecs::field_type(&name)
                        .is_some_and(|(t, _)| t == ValueType::String);
                    if is_string && !values.is_empty() && values.iter().all(|v| is_number(*v)) {
                        let type_name = opentide_ecs::field_type(&name).map_or("", |(_, t)| t);
                        out.push(opentide_ecs::type_mismatch(
                            &name,
                            type_name,
                            "an `in` list of numbers (quote them)",
                            at(node),
                        ));
                    }
                }
                _ => {}
            }
        }
        "function_call" => {
            let name = function_name(node, source);
            let Some((params, variadic)) = parameters(&name) else {
                return;
            };
            let display = node
                .child_by_field_name("name")
                .map(|n| text(n, source))
                .unwrap_or("");
            for (i, arg) in named_children(node, "arguments").into_iter().enumerate() {
                let want = match params.get(i) {
                    Some(w) => *w,
                    None if variadic => params[params.len() - 1],
                    None => break,
                };
                let Some(field) = as_field(arg, source) else {
                    continue;
                };
                if let Some(type_name) = mismatch(want, &field) {
                    out.push(opentide_ecs::type_mismatch(
                        &field,
                        type_name,
                        &format!(
                            "it as an argument of `{display}`, which takes {}",
                            want_name(want)
                        ),
                        at(arg),
                    ));
                }
            }
        }
        "binary_expression" | "unary_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            for side in ["left", "right", "operand"] {
                let Some(operand) = node.child_by_field_name(side) else {
                    continue;
                };
                let Some(field) = as_field(operand, source) else {
                    continue;
                };
                if let Some(type_name) = mismatch(Want::Numeric, &field) {
                    out.push(opentide_ecs::type_mismatch(
                        &field,
                        type_name,
                        &format!("arithmetic (`{operator}`)"),
                        at(operand),
                    ));
                }
            }
        }
        _ => {}
    }
}

fn want_name(want: Want) -> &'static str {
    match want {
        Want::Str | Want::StrConst => "a string",
        Want::Int => "an integer",
        Want::Numeric => "a number",
        Want::Bool => "a boolean",
        Want::Ip => "an ip field",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::Severity;

    fn mismatch_in(query: &str) -> bool {
        ecs_diagnostics(query)
            .iter()
            .any(|d| d.code == codes::ECS_TYPE_MISMATCH && d.severity == Severity::Error)
    }

    #[test]
    fn rejected_on_an_ecs_mapping() {
        // testdata/oracles/elasticsearch/eql-*: ERR on every release.
        for query in [
            "process where process.name + 1 == 1",
            "network where cidrMatch(source.address, \"10.0.0.0/8\")",
            "process where process.pid : \"4624\"",
            "process where event.code in (4624, 4625)",
            "process where length(process.pid) > 0",
            "process where process.pid like \"4*\"",
            "process where number(process.pid) == 1",
            "process where startsWith(process.pid, \"1\")",
            "any where host : \"x\"",
            "network where source.ip : \"10.*\"",
            "network where source.ip regex~ \"10\\\\..*\"",
        ] {
            assert!(mismatch_in(query), "{query}: {:?}", ecs_diagnostics(query));
        }
    }

    #[test]
    fn accepted_on_an_ecs_mapping() {
        for query in [
            // `==` converts the constant (eq_string_long_field: OK).
            "process where process.pid == \"4624\"",
            "process where event.code == 4624",
            "process where process.name : \"cmd.exe\" and process.pid > 4",
            "network where cidrmatch(destination.ip, \"10.0.0.0/8\")",
            "process where process.args[0] : \"x\"",
            "process where ?process.Ext.api.name : \"x\" and process.parent.name like~ \"a*\"",
            "sequence by host.id, source.ip [authentication where true] [process where true]",
            "process where winlog.event_id : \"4688\" and process.command_line.text : \"x\"",
            "process where length(process.name) > 3 and process.pid + 1 > 2",
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
        let d = ecs_diagnostics("process where process.nmae == \"x\"");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].code, codes::ECS_UNKNOWN_FIELD);
        assert_eq!(d[0].suggestion.as_deref(), Some("process.name"));
        // An optional field may be missing on purpose.
        assert!(ecs_diagnostics("process where ?process.nmae == \"x\"").is_empty());
    }
}
