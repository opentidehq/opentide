//! Checks on a parsed CQL query that the grammar cannot make: functions and
//! their arguments against the catalog, regex flags, string escapes, where free
//! text and `<=>` may appear, Falcon event names, and the Next-Gen SIEM
//! correlation-rule rules. Every check reads the tree only; none guesses at a
//! tenant's fields, saved searches, lookup files or repositories.

use crate::catalog::{Catalog, Function, Parameter};
use crate::{Context, range, text};
use opentide_core::{Diagnostic, codes};
use opentide_syntax::walk_with_ancestors;
use tree_sitter::Node;

/// Regex flags CQL accepts (`d` dot-all, `g`, `i`, `m`, `F` regex engine v2).
pub const REGEX_FLAGS: &str = "dgimF";

/// String escapes LogScale translates. Any other `\x` is kept verbatim.
const STRING_ESCAPES: &[char] = &['"', '\\', 'n', 't'];

pub(crate) fn diagnostics(root: Node, source: &str, ctx: &Context) -> Vec<Diagnostic> {
    let catalog = Catalog::cached();
    let mut out = Vec::new();
    // Checks that look upward read `ancestors`: `Node::parent` re-descends
    // from the root, which makes a deeply nested query quadratic.
    walk_with_ancestors(root, |node, ancestors| {
        if node.is_error() || node.is_missing() {
            return;
        }
        match node.kind() {
            "function_call" => function_call(node, ancestors, source, catalog, &mut out),
            "regex" => regex(node, source, &mut out),
            "string" => string(node, ancestors, source, &mut out),
            "pipeline" => pipeline(node, source, catalog, &mut out),
            "link_constraint" => link_constraint(node, ancestors, source, &mut out),
            "field_filter" => event_name(node, source, catalog, &mut out),
            _ => {}
        }
    });
    if ctx.correlation_rule {
        correlation_rule(root, source, catalog, &mut out);
    }
    out
}

/// The name a call is written with (`groupBy`, `array:filter`).
pub(crate) fn call_name<'s>(call: Node, source: &'s str) -> &'s str {
    call.child_by_field_name("name")
        .map(|n| text(n, source))
        .unwrap_or("")
}

/// The arguments of a call: `(name node, value node)`, the name absent when
/// the argument has none.
pub(crate) fn call_arguments<'t>(call: Node<'t>) -> Vec<(Option<Node<'t>>, Option<Node<'t>>)> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter_map(|arg| match arg.kind() {
            "named_argument" => Some((
                arg.child_by_field_name("name"),
                arg.child_by_field_name("value"),
            )),
            "argument" => Some((None, arg.child_by_field_name("value"))),
            _ => None,
        })
        .collect()
}

/// An argument or parameter name, without the quotes of `"name"=...`.
pub(crate) fn name_text<'s>(node: Node, source: &'s str) -> &'s str {
    unquote(text(node, source))
}

pub(crate) fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

fn function_call(
    call: Node,
    ancestors: &[Node],
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let Some(name_node) = call.child_by_field_name("name") else {
        return;
    };
    let name = text(name_node, source);
    // Computed only for a finding: a range counts lines from the start.
    let name_range = || range(source, name_node);
    let Some(function) = catalog.function(name) else {
        let mut d = Diagnostic::error(
            codes::CQL_UNKNOWN_FUNCTION,
            format!("unknown CQL function `{name}`"),
            name_range(),
        );
        if let Some(s) = catalog.suggest_function(name) {
            d = d.with_suggestion(s);
        }
        out.push(d);
        return;
    };
    if function.removed {
        let mut message = format!("`{}` was removed from CQL", function.name);
        if let Some(v) = &function.removed_in {
            message.push_str(&format!(" in {v}"));
        }
        let mut d = Diagnostic::error(codes::CQL_REMOVED_FUNCTION, message, name_range());
        if let Some(r) = &function.replacement {
            d = d.with_suggestion(r.clone());
        }
        out.push(d);
        return;
    }
    if function.deprecated {
        let mut message = format!("`{}` is deprecated", function.name);
        if let Some(note) = function
            .deprecated_note
            .as_deref()
            .filter(|n| !n.is_empty())
        {
            message.push_str(&format!(": {note}"));
        }
        out.push(Diagnostic::warning(
            codes::CQL_DEPRECATED_FUNCTION,
            message,
            name_range(),
        ));
    }
    let implied = implied_parameters(call, ancestors);
    arguments(call, function, implied, source, catalog, out);
}

/// What the call's position supplies without an argument: `x =~ f()` gives
/// `field`, `x := f()` gives `as`, and a `match` guard gives `field`.
fn implied_parameters(call: Node, ancestors: &[Node]) -> (bool, bool) {
    let mut up = ancestors.iter().rev();
    let mut parent = up.next();
    if parent.is_some_and(|p| p.kind() == "negated_function_call") {
        parent = up.next();
    }
    let Some(parent) = parent else {
        return (false, false);
    };
    let field = matches!(parent.kind(), "field_shorthand" | "match_branch");
    let assigned = parent.kind() == "assignment"
        && parent.child_by_field_name("value").map(|v| v.id()) == Some(call.id());
    (field, assigned)
}

fn arguments(
    call: Node,
    function: &Function,
    (implied_field, assigned): (bool, bool),
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    // `eval(a = b)` and the like take field assignments, not parameters.
    if function.parameters.is_empty() {
        return;
    }
    let mut given: Vec<&str> = Vec::new();
    if implied_field {
        given.push("field");
    }
    let mut unnamed_seen = false;
    for (name_node, value) in call_arguments(call) {
        let parameter: Option<&Parameter> = match name_node {
            Some(n) => {
                let name = name_text(n, source);
                match function.parameter(name) {
                    Some(p) => {
                        if assigned && p.name == "as" {
                            out.push(Diagnostic::error(
                                codes::CQL_ASSIGNMENT_AS,
                                format!(
                                    "`as` names the output of `{}` a second time: the assignment already names it",
                                    function.name
                                ),
                                range(source, n),
                            ));
                        }
                        Some(p)
                    }
                    None => {
                        let mut d = Diagnostic::error(
                            codes::CQL_UNKNOWN_PARAMETER,
                            format!("`{}` has no parameter `{name}`", function.name),
                            range(source, n),
                        );
                        if let Some(s) = catalog.suggest_parameter(function, name) {
                            d = d.with_suggestion(s);
                        }
                        out.push(d);
                        None
                    }
                }
            }
            None => {
                // `correlate(A: {...}, B: {...})`: every named subquery binds `query`.
                let named_subquery = value.is_some_and(is_named_subquery);
                if named_subquery && unnamed_seen {
                    continue;
                }
                let at = || {
                    value
                        .map(|v| range(source, v))
                        .unwrap_or_else(|| range(source, call))
                };
                match function.unnamed_parameter() {
                    None => {
                        out.push(Diagnostic::error(
                            codes::CQL_UNNAMED_ARGUMENT,
                            format!(
                                "`{}` takes no argument without a name: write `parameter=value`",
                                function.name
                            ),
                            at(),
                        ));
                        None
                    }
                    Some(_) if unnamed_seen => {
                        out.push(Diagnostic::error(
                            codes::CQL_UNNAMED_ARGUMENT,
                            format!(
                                "`{}` takes at most one argument without a name",
                                function.name
                            ),
                            at(),
                        ));
                        unnamed_seen = true;
                        continue;
                    }
                    Some(p) => {
                        unnamed_seen = true;
                        Some(p)
                    }
                }
            }
        };
        let Some(parameter) = parameter else {
            continue;
        };
        if given.contains(&parameter.name.as_str()) {
            let at = name_node
                .or(value)
                .map(|n| range(source, n))
                .unwrap_or_else(|| range(source, call));
            out.push(Diagnostic::error(
                codes::CQL_DUPLICATE_PARAMETER,
                format!(
                    "`{}` is given more than once to `{}`",
                    parameter.name, function.name
                ),
                at,
            ));
        } else {
            given.push(parameter.name.as_str());
        }
        if let Some(value) = value {
            parameter_value(function, parameter, value, source, out);
        }
    }
    if assigned {
        given.push("as");
    }
    let missing: Vec<&str> = function
        .parameters
        .iter()
        // A documented default fills a parameter the reference also calls required.
        .filter(|p| {
            p.required && p.default.is_none() && !p.deprecated && !given.contains(&p.name.as_str())
        })
        .map(|p| p.name.as_str())
        .collect();
    if !missing.is_empty() {
        let at = call
            .child_by_field_name("name")
            .map(|n| range(source, n))
            .unwrap_or_else(|| range(source, call));
        let list = missing
            .iter()
            .map(|m| format!("`{m}`"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(Diagnostic::error(
            codes::CQL_MISSING_PARAMETER,
            format!("`{}` needs {list}", function.name),
            at,
        ));
    }
}

/// `Name: { ... }`, possibly followed by attributes (`include: [a, b]`).
fn is_named_subquery(value: Node) -> bool {
    match value.kind() {
        "named_subquery" => true,
        "attributed_expression" => value
            .child_by_field_name("expression")
            .is_some_and(|e| e.kind() == "named_subquery"),
        _ => false,
    }
}

/// A literal value: a bare word or number, or a quoted string. Anything else
/// (a field reference in an expression, a call, a `?param`) is not checked.
fn literal<'s>(node: Node, source: &'s str) -> Option<&'s str> {
    match node.kind() {
        "unquoted_pattern" | "field_name" | "number" | "boolean" | "tag" => {
            Some(text(node, source))
        }
        "string" => Some(unquote(text(node, source))),
        _ => None,
    }
}

fn parameter_value(
    function: &Function,
    parameter: &Parameter,
    value: Node,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if parameter.values.is_empty() && parameter.min.is_none() && parameter.max.is_none() {
        return;
    }
    let mut values: Vec<Node> = Vec::new();
    if value.kind() == "array" {
        if !parameter.multi {
            return;
        }
        let mut cursor = value.walk();
        values.extend(value.children_by_field_name("element", &mut cursor));
    } else {
        values.push(value);
    }
    for node in values {
        let Some(lit) = literal(node, source) else {
            continue;
        };
        if let Some(problem) = value_problem(parameter, lit) {
            out.push(Diagnostic::error(
                codes::CQL_PARAMETER_VALUE,
                format!("`{}` of `{}` {problem}", parameter.name, function.name),
                range(source, node),
            ));
        }
    }
}

/// Why `lit` is not a value `parameter` takes, or `None` when it is.
fn value_problem(parameter: &Parameter, lit: &str) -> Option<String> {
    let number = lit.parse::<f64>().ok();
    let integer_param = matches!(parameter.ty.as_str(), "integer" | "number");
    if let Some(n) = number.filter(|_| integer_param || parameter.values_open) {
        if let Some(min) = parameter.min.filter(|&m| n < m as f64) {
            return Some(format!("is at least {min}, not {lit}"));
        }
        if let Some(max) = parameter.max.filter(|&m| n > m as f64) {
            return Some(format!("is at most {max}, not {lit}"));
        }
        if parameter.values.is_empty() || parameter.values_open || integer_param {
            return None;
        }
    }
    // Only an enumerated parameter has a closed set: a string parameter's
    // `values` are keywords beside free text (`parseTimestamp(format=...)`).
    let closed = parameter.ty.contains("enum") || integer_param || parameter.values_open;
    if parameter.values.is_empty() || !closed {
        return None;
    }
    // A wildcard or an empty value is not a choice the engine can judge.
    if lit.is_empty() || lit.contains('*') {
        return None;
    }
    // CrowdStrike's own content writes `order=des`, `asce`, `ascending`: LogScale
    // reads these values more loosely than the reference lists them, so a value
    // that a listed one starts with, or that starts with a listed one, passes.
    let lower = lit.to_ascii_lowercase();
    let known = parameter
        .values
        .iter()
        .chain(&parameter.deprecated_values)
        .map(|v| v.to_ascii_lowercase())
        .any(|v| v.starts_with(&lower) || lower.starts_with(&v));
    if known {
        return None;
    }
    let choices = parameter
        .values
        .iter()
        .map(|v| format!("`{v}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let numbers = if parameter.values_open {
        " or a number"
    } else {
        ""
    };
    Some(format!("is one of {choices}{numbers}, not `{lit}`"))
}

fn regex(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let Some(flags) = node.child_by_field_name("flags") else {
        return;
    };
    let bad: String = text(flags, source)
        .chars()
        .filter(|c| !REGEX_FLAGS.contains(*c))
        .collect();
    if !bad.is_empty() {
        out.push(Diagnostic::error(
            codes::CQL_REGEX_FLAG,
            format!("unknown regex flag `{bad}`: CQL takes d, g, i, m and F"),
            range(source, flags),
        ));
    }
}

/// A string bound to a regex parameter (`regex("\d+")`) goes to the regex
/// engine, where `\d` is meant; only other strings get the escape warning.
fn regex_argument(ancestors: &[Node], source: &str) -> bool {
    // string <- argument <- argument_list <- function_call
    let [.., call, _list, arg] = ancestors else {
        return false;
    };
    let (call, arg) = (*call, *arg);
    if call.kind() != "function_call" {
        return false;
    }
    let Some(function) = Catalog::cached().function(call_name(call, source)) else {
        return true;
    };
    let parameter = match arg.kind() {
        "argument" => function.unnamed_parameter(),
        "named_argument" => arg
            .child_by_field_name("name")
            .and_then(|n| function.parameter(name_text(n, source))),
        _ => None,
    };
    parameter.is_some_and(|p| p.ty == "regex")
        || function.category.iter().any(|c| c == "regular-expression")
}

fn string(node: Node, ancestors: &[Node], source: &str, out: &mut Vec<Diagnostic>) {
    // A quoted name (`"user name" = x`, `"name"=value` in a call) is not a value.
    let raw = text(node, source);
    if !raw.contains('\\') || regex_argument(ancestors, source) {
        return;
    }
    let mut chars = raw.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            continue;
        }
        let Some((_, next)) = chars.next() else {
            break;
        };
        if !STRING_ESCAPES.contains(&next) {
            let start = node.start_byte() + i;
            let span = opentide_core::ByteSpan::new(start, start + 1 + next.len_utf8());
            out.push(Diagnostic::warning(
                codes::CQL_STRING_ESCAPE,
                format!(
                    "`\\{next}` is not a CQL string escape, so LogScale keeps the backslash; write `\\\\` for a literal backslash"
                ),
                opentide_core::span_to_range(source, span),
            ));
        }
    }
}

/// Whether a step aggregates: an aggregate function, possibly negated or
/// assigned, or a `[...]` stats shorthand.
fn aggregates(step: Node, source: &str, catalog: &Catalog) -> bool {
    let call = match step.kind() {
        "stats_shorthand" => return true,
        "function_call" => Some(step),
        "negated_function_call" => step.child_by_field_name("function"),
        "assignment" => step
            .child_by_field_name("value")
            .filter(|v| v.kind() == "function_call"),
        "field_shorthand" => step.child_by_field_name("function").map(|f| {
            if f.kind() == "negated_function_call" {
                f.child_by_field_name("function").unwrap_or(f)
            } else {
                f
            }
        }),
        _ => None,
    };
    call.and_then(|c| catalog.function(call_name(c, source)))
        .is_some_and(|f| f.aggregate)
}

/// Free text after the first aggregate of a pipeline (refused since 1.190).
fn pipeline(node: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let mut aggregated = false;
    for step in node.children_by_field_name("step", &mut cursor) {
        if aggregated {
            walk_with_ancestors(step, |n, below_step| {
                if n.kind() != "free_text" {
                    return;
                }
                // A bare regex searches fields; only text search is refused.
                let regex = n
                    .child_by_field_name("value")
                    .is_some_and(|v| v.kind() == "regex");
                // A `{ ... }`, `case` or `match` body is its own pipeline,
                // checked on its own.
                let nested = below_step.iter().any(|a| a.kind() == "pipeline");
                if !regex && !nested {
                    out.push(Diagnostic::error(
                        codes::CQL_FREE_TEXT_AFTER_AGGREGATE,
                        "free-text search cannot follow an aggregate function: filter on a field, or move it before the aggregate",
                        range(source, n),
                    ));
                }
            });
        }
        if aggregates(step, source, catalog) {
            aggregated = true;
        }
    }
}

/// `a <=> B.b` links two correlate() queries; anywhere else it is an error.
fn link_constraint(node: Node, ancestors: &[Node], source: &str, out: &mut Vec<Diagnostic>) {
    if ancestors.iter().any(|n| is_correlate(*n, source)) {
        return;
    }
    out.push(Diagnostic::error(
        codes::CQL_LINK_OUTSIDE_CORRELATE,
        "`<=>` links the queries of correlate(); it is not a filter",
        range(source, node),
    ));
}

/// `#event_simpleName=Name` where no Falcon event has that name.
fn event_name(node: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let (Some(field), Some(value)) = (
        node.child_by_field_name("field"),
        node.child_by_field_name("value"),
    ) else {
        return;
    };
    let field = unquote(text(field, source));
    if field != "#event_simpleName" && field != "event_simpleName" {
        return;
    }
    let operator = node
        .child_by_field_name("operator")
        .map(|o| text(o, source))
        .unwrap_or("");
    if operator != "=" && operator != "!=" {
        return;
    }
    if !matches!(value.kind(), "unquoted_pattern" | "string" | "field_name") {
        return;
    }
    let name = unquote(text(value, source));
    if name.is_empty() || name.contains('*') || catalog.event(name).is_some() {
        return;
    }
    let mut d = Diagnostic::warning(
        codes::CQL_UNKNOWN_EVENT,
        format!(
            "`{name}` is not a Falcon event the engine knows (names are case-sensitive; a newer sensor may send events the catalog lacks)"
        ),
        range(source, value),
    );
    if let Some(s) = catalog.suggest_event(name) {
        d = d.with_suggestion(s);
    }
    out.push(d);
}

fn is_correlate(node: Node, source: &str) -> bool {
    node.kind() == "function_call" && call_name(node, source).eq_ignore_ascii_case("correlate")
}

/// Next-Gen SIEM: `correlate()` takes no other aggregate in the same query.
fn correlation_rule(root: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let mut has_correlate = false;
    let mut outside: Vec<(Node, &str)> = Vec::new();
    walk_with_ancestors(root, |n, ancestors| {
        if n.kind() != "function_call" {
            return;
        }
        if is_correlate(n, source) {
            has_correlate = true;
            return;
        }
        // Aggregates inside correlate()'s own arguments follow its rules.
        if ancestors.iter().any(|a| is_correlate(*a, source)) {
            return;
        }
        if let Some(function) = catalog
            .function(call_name(n, source))
            .filter(|f| f.aggregate)
        {
            outside.push((n, function.name.as_str()));
        }
    });
    if !has_correlate {
        return;
    }
    for (n, name) in outside {
        let at = n
            .child_by_field_name("name")
            .map(|x| range(source, x))
            .unwrap_or_else(|| range(source, n));
        out.push(Diagnostic::error(
            codes::CQL_CORRELATE_AGGREGATE,
            format!("a correlation rule cannot combine correlate() with the aggregate `{name}`"),
            at,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(
        ty: &str,
        values: &[&str],
        open: bool,
        min: Option<i64>,
        max: Option<i64>,
    ) -> Parameter {
        Parameter {
            name: "p".into(),
            ty: ty.into(),
            required: false,
            unnamed: false,
            multi: false,
            query: false,
            default: None,
            values: values.iter().map(|v| v.to_string()).collect(),
            values_open: open,
            deprecated_values: Vec::new(),
            min,
            max,
            aliases: Vec::new(),
            deprecated: false,
            deprecated_since: None,
        }
    }

    #[test]
    fn value_problems() {
        let order = param("enum", &["asc", "desc"], false, None, None);
        assert_eq!(value_problem(&order, "desc"), None);
        assert_eq!(value_problem(&order, "DESC"), None);
        // As CrowdStrike's own content writes them.
        assert_eq!(value_problem(&order, "des"), None);
        assert_eq!(value_problem(&order, "ascending"), None);
        // A string parameter's values are keywords beside free text.
        let format = param("string", &["seconds", "millis"], false, None, None);
        assert_eq!(value_problem(&format, "yyyy-MM-dd"), None);
        assert!(
            value_problem(&order, "down")
                .unwrap()
                .contains("`asc`, `desc`")
        );
        let limit = param("integer", &["max"], true, None, Some(200_000));
        assert_eq!(value_problem(&limit, "max"), None);
        assert_eq!(value_problem(&limit, "500"), None);
        assert!(
            value_problem(&limit, "300000")
                .unwrap()
                .contains("at most 200000")
        );
        assert!(
            value_problem(&limit, "all")
                .unwrap()
                .contains("or a number")
        );
        let bounded = param("integer", &[], false, Some(1), Some(1500));
        assert!(value_problem(&bounded, "0").is_some());
        assert_eq!(value_problem(&bounded, "12"), None);
    }
}
