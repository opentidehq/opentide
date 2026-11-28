//! ECS checks for an EQL query that reads ECS indices (the caller decides,
//! with `opentide_ecs::indices_are_ecs`). The Verifier types each field from
//! the index mapping; on ECS indices that mapping is ECS, so the rules the
//! engine can only hint about without one become errors here. Each rule is a
//! verdict recorded against an ECS-mapped index on every release
//! (`crates/testdata/oracles/elasticsearch/eql-*`): `:`, `like`, and `regex` on a
//! non-string field, an `in` list of numbers on a string field, a function
//! argument or arithmetic operand of the wrong type, and an object used as a
//! value. `==` and `!=` convert their constant, so they are never reported.

use crate::ast;
use crate::nav::{span, text};
use crate::semantics::{Run, Want, function_name, parameters, strip_parens};
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use crate::{parsed, range};
use opentide_core::{Diagnostic, codes};
use opentide_ecs::ValueType;
use opentide_parse::ast::AstNode;

/// The dotted name a field reads, and whether it is optional (`?x`). `None` for an array
/// element (`process.args[0]`).
fn field_name(field: &ast::Field, source: &str) -> Option<(String, bool)> {
    if field.indexes().next().is_some() {
        return None;
    }
    let parts: Vec<String> = field
        .name_parts()
        .map(|part| match part {
            ast::NamePart::Identifier(id) => text(id.syntax(), source).to_string(),
            ast::NamePart::QuotedIdentifier(q) => {
                // The lexer closes a quoted name: a backtick at both ends.
                let t = text(q.syntax(), source);
                let t = t.strip_prefix('`').unwrap_or(t);
                t.strip_suffix('`').unwrap_or(t).replace("``", "`")
            }
        })
        .collect();
    (!parts.is_empty()).then(|| (parts.join("."), field.optional_marker().is_some()))
}

/// The field an expression is, when it is one (through parentheses).
fn as_field(node: &SyntaxNode, source: &str) -> Option<String> {
    ast::Field::cast(strip_parens(node.clone()))
        .and_then(|f| field_name(&f, source))
        .map(|(name, _)| name)
}

/// A number, signed or not, through parentheses.
fn is_number(node: &SyntaxNode) -> bool {
    let mut node = strip_parens(node.clone());
    loop {
        match node.kind() {
            K::NUMBER => return true,
            K::UNARY_EXPRESSION => match node.first_child() {
                Some(operand) => node = strip_parens(operand),
                None => return false,
            },
            _ => return false,
        }
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
/// ECS documents. A query that does not parse gets none. The findings'
/// ranges come from one line table ([`opentide_core::with_line_index`]).
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    opentide_core::with_line_index(source, || ecs_diagnostics_lines(source))
}

fn ecs_diagnostics_lines(source: &str) -> Vec<Diagnostic> {
    let parsed = parsed::parse(source);
    if parsed.broken(span(&parsed.syntax)) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for event in parsed.syntax.preorder() {
        if let rowan::WalkEvent::Enter(node) = event {
            check(&node, source, &mut out);
        }
    }
    out
}

fn check(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let at = |n: &SyntaxNode| range(source, span(n));
    match node.kind() {
        K::FIELD => {
            let Some((name, optional)) =
                ast::Field::cast(node.clone()).and_then(|f| field_name(&f, source))
            else {
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
        K::PREDICATE_EXPRESSION => {
            let Some(predicate) = ast::PredicateExpression::cast(node.clone()) else {
                return;
            };
            let operator = predicate
                .operator()
                .map(|o| o.text().to_owned())
                .unwrap_or_default();
            let mut exprs = predicate.exprs();
            let Some(subject) = exprs.next() else {
                return;
            };
            let Some(name) = as_field(subject.syntax(), source) else {
                return;
            };
            match operator.as_str() {
                ":" | "like" | "like~" | "regex" | "regex~" => {
                    if let Some(type_name) = mismatch(Want::Str, &name) {
                        out.push(opentide_ecs::type_mismatch(
                            &name,
                            type_name,
                            &format!("`{operator}`, which compares strings,"),
                            at(subject.syntax()),
                        ));
                    }
                }
                "in" => {
                    let values: Vec<ast::Expr> = exprs.collect();
                    let is_string = opentide_ecs::field_type(&name)
                        .is_some_and(|(t, _)| t == ValueType::String);
                    if is_string
                        && !values.is_empty()
                        && values.iter().all(|v| is_number(v.syntax()))
                    {
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
        K::FUNCTION_CALL => {
            let Some(call) = ast::FunctionCall::cast(node.clone()) else {
                return;
            };
            let name = function_name(&call, source);
            let Some((params, variadic)) = parameters(&name) else {
                return;
            };
            let display = call.name().map_or("", |n| text(n.syntax(), source));
            for (i, arg) in call.exprs().enumerate() {
                let want = match params.get(i) {
                    Some(w) => *w,
                    None if variadic => params[params.len() - 1],
                    None => break,
                };
                let Some(field) = as_field(arg.syntax(), source) else {
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
                        at(arg.syntax()),
                    ));
                }
            }
        }
        // Each level of a run of arithmetic, the outermost first, as Elasticsearch's builder
        // nests it.
        K::BINARY_EXPRESSION => {
            let run = Run::of(node);
            for level in (0..run.len()).rev() {
                let operator = run.operator(level).map_or("", |o| o.text());
                for operand in run.operands(level).into_iter().flatten() {
                    arithmetic_operand(operand, operator, source, out);
                }
            }
        }
        K::UNARY_EXPRESSION => {
            let Some(unary) = ast::UnaryExpression::cast(node.clone()) else {
                return;
            };
            let operator = unary.operator().map(|o| o.text().to_owned());
            if let Some(operand) = unary.operand() {
                arithmetic_operand(
                    operand.syntax(),
                    operator.as_deref().unwrap_or(""),
                    source,
                    out,
                );
            }
        }
        _ => {}
    }
}

/// An arithmetic operand that is a field ECS does not map as a number.
fn arithmetic_operand(
    operand: &SyntaxNode,
    operator: &str,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let Some(field) = as_field(operand, source) else {
        return;
    };
    if let Some(type_name) = mismatch(Want::Numeric, &field) {
        out.push(opentide_ecs::type_mismatch(
            &field,
            type_name,
            &format!("arithmetic (`{operator}`)"),
            range(source, span(operand)),
        ));
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
        // crates/testdata/oracles/elasticsearch/eql-*: ERR on every release.
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
