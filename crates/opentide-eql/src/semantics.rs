//! Checks Elasticsearch makes after parsing, that need no index mapping:
//! literal argument types (the Verifier's type resolution) and comparisons
//! between two fields (rejected when the filter is translated to a query).
//!
//! Without a field catalog a field's type is unknown, so only literals,
//! function results, and arithmetic are typed here. Every type rule accepts
//! `null`, as Elasticsearch's `TypeResolutions.isType` does.

use opentide_core::{ByteSpan, Diagnostic, Range, Severity, codes, span_to_range};
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Str,
    Int,
    Double,
    /// Numeric of unknown width (arithmetic over a field).
    Num,
    Bool,
    Null,
    /// A field, or anything this check cannot type.
    Unknown,
}

impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::Str => "string",
            Ty::Int => "integer",
            Ty::Double => "double",
            Ty::Num => "number",
            Ty::Bool => "boolean",
            Ty::Null => "null",
            Ty::Unknown => "value",
        }
    }

    fn numeric(self) -> bool {
        matches!(self, Ty::Int | Ty::Double | Ty::Num)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Want {
    Str,
    Int,
    Bool,
    Numeric,
    /// `cidrMatch`'s first argument: an `ip` field.
    Ip,
    /// `cidrMatch`'s CIDR blocks: string constants.
    StrConst,
}

impl Want {
    fn accepts(self, ty: Ty) -> bool {
        match (self, ty) {
            (_, Ty::Null | Ty::Unknown) => true,
            (Want::Str | Want::StrConst, t) => t == Ty::Str,
            (Want::Int, t) => matches!(t, Ty::Int | Ty::Num),
            (Want::Bool, t) => t == Ty::Bool,
            (Want::Numeric, t) => t.numeric(),
            (Want::Ip, _) => false,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Want::Str | Want::StrConst => "a string",
            Want::Int => "an integer",
            Want::Bool => "a boolean",
            Want::Numeric => "a number",
            Want::Ip => "an ip field",
        }
    }
}

/// Parameter types each function's `resolveType` enforces, by lower-case
/// registry name (`EqlFunctionRegistry`). The last entry repeats for
/// variadic functions.
pub(crate) fn parameters(name: &str) -> Option<(&'static [Want], bool)> {
    use Want::*;
    Some(match name {
        "between" => (&[Str, Str, Str, Bool], false),
        "cidrmatch" => (&[Ip, StrConst], true),
        "endswith" | "startswith" | "stringcontains" => (&[Str, Str], false),
        "indexof" => (&[Str, Str, Int], false),
        "length" => (&[Str], false),
        "number" => (&[Str, Int], false),
        "substring" => (&[Str, Int, Int], false),
        "add" | "subtract" | "multiply" | "divide" | "modulo" => (&[Numeric, Numeric], false),
        _ => return None,
    })
}

// Operator operands are verified like function arguments; every release from
// 8.19 to 9.5 rejects a wrong literal type, mapped field or not
// (testdata/oracles/elasticsearch/eql-argument-types).
const OPERAND_STRING: (Want, Severity) = (Want::Str, Severity::Error);
const OPERAND_NUMBER: (Want, Severity) = (Want::Numeric, Severity::Error);

pub(crate) fn named_children<'t>(node: Node<'t>, field: &str) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(|n| n.is_named() && n.kind() != "comment")
        .collect()
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(crate) fn function_name(node: Node, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|n| text(n, source).trim_end_matches('~').to_ascii_lowercase())
        .unwrap_or_default()
}

fn ty(node: Node, source: &str) -> Ty {
    match node.kind() {
        "string" => Ty::Str,
        "boolean" => Ty::Bool,
        "null" => Ty::Null,
        // An integer literal too large for a long becomes a double.
        "number" => {
            let t = text(node, source);
            if t.bytes().all(|b| b.is_ascii_digit()) && t.parse::<i64>().is_ok() {
                Ty::Int
            } else {
                Ty::Double
            }
        }
        "parenthesized_expression" => node
            .named_children(&mut node.walk())
            .find(|n| n.kind() != "comment")
            .map_or(Ty::Unknown, |n| ty(n, source)),
        "comparison"
        | "predicate_expression"
        | "and_expression"
        | "or_expression"
        | "not_expression" => Ty::Bool,
        "unary_expression" => {
            let operand = node
                .child_by_field_name("operand")
                .map_or(Ty::Unknown, |n| ty(n, source));
            if operand.numeric() {
                operand
            } else {
                Ty::Unknown
            }
        }
        "binary_expression" => {
            let side = |f: &str| {
                node.child_by_field_name(f)
                    .map_or(Ty::Unknown, |n| ty(n, source))
            };
            arithmetic(side("left"), side("right"))
        }
        "function_call" => {
            let name = function_name(node, source);
            match name.as_str() {
                "between" | "concat" | "string" | "substring" => Ty::Str,
                "length" | "indexof" => Ty::Int,
                // `ToNumber` is declared double.
                "number" => Ty::Double,
                "cidrmatch" | "endswith" | "startswith" | "stringcontains" => Ty::Bool,
                "add" | "subtract" | "multiply" | "divide" | "modulo" => {
                    let args = named_children(node, "arguments");
                    if args.len() == 2 {
                        arithmetic(ty(args[0], source), ty(args[1], source))
                    } else {
                        Ty::Unknown
                    }
                }
                _ => Ty::Unknown,
            }
        }
        _ => Ty::Unknown,
    }
}

/// Result of `+ - * / %`: the common numeric type. A non-numeric operand is
/// reported on its own, so the result is left untyped to avoid a cascade.
fn arithmetic(left: Ty, right: Ty) -> Ty {
    let known = |t: Ty| t.numeric() || t == Ty::Null || t == Ty::Unknown;
    if !known(left) || !known(right) {
        return Ty::Unknown;
    }
    match (left, right) {
        (Ty::Int, Ty::Int) => Ty::Int,
        (Ty::Double, r) if r.numeric() => Ty::Double,
        (l, Ty::Double) if l.numeric() => Ty::Double,
        _ => Ty::Num,
    }
}

/// `a-b` written without spaces where `a` is a field: the name the author
/// probably meant.
fn hyphenated_name(node: Node, source: &str) -> Option<String> {
    let left = node.child_by_field_name("left")?;
    let op = node.child_by_field_name("operator")?;
    let right = node.child_by_field_name("right")?;
    if left.kind() != "field"
        || left.end_byte() != op.start_byte()
        || op.end_byte() != right.start_byte()
    {
        return None;
    }
    let mut first = right;
    while let Some(child) = first.named_child(0) {
        if first.kind() == "field" {
            break;
        }
        first = child;
    }
    if first.kind() != "field" {
        return None;
    }
    Some(format!("{}-{}", text(left, source), text(first, source)))
}

/// Field references inside an expression: `(required, optional_only)`.
/// An optional field (`?x`) that is not mapped becomes `null`, a constant.
fn field_refs(node: Node) -> (bool, bool) {
    let mut required = false;
    let mut optional = false;
    let mut cursor = node.walk();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "field" {
            if n.child_by_field_name("optional").is_some() {
                optional = true;
            } else {
                required = true;
            }
            continue;
        }
        stack.extend(n.named_children(&mut cursor));
    }
    (required, optional && !required)
}

fn diag(severity: Severity, code: &str, message: String, range: Range) -> Diagnostic {
    let mut d = Diagnostic::error(code, message, range);
    d.severity = severity;
    d
}

fn ordinal(i: usize) -> &'static str {
    ["first", "second", "third", "fourth", "fifth"]
        .get(i)
        .copied()
        .unwrap_or("next")
}

fn literal_desc(node: Node, source: &str, found: Ty) -> String {
    let t = text(node, source);
    let short: String = t.chars().take(40).collect();
    let ellipsis = if short.len() < t.len() { "…" } else { "" };
    format!("{} `{short}{ellipsis}`", found.name())
}

fn check_value(
    node: Node,
    (want, severity): (Want, Severity),
    what: &str,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let span = ByteSpan::new(node.start_byte(), node.end_byte());
    let range = span_to_range(source, span);
    if want == Want::StrConst {
        let (required, optional_only) = field_refs(node);
        if required || optional_only {
            // Mapped, a field is not a constant; unmapped, an optional field
            // makes Elasticsearch fail with a server error. Both fail.
            let (severity, tail) = if required {
                (Severity::Error, "")
            } else {
                (Severity::Error, " (an unmapped optional field fails too)")
            };
            out.push(diag(
                severity,
                codes::EQL_ARGUMENT_TYPE,
                format!("{what} must be a constant string, not a field{tail}"),
                range,
            ));
            return;
        }
    }
    if want == Want::Ip && node.kind() == "field" {
        let name = text(node, source).trim_start_matches('?').replace('`', "");
        if let Some(field) = opentide_ecs::field(&name).filter(|f| f.type_name != "ip") {
            out.push(diag(
                Severity::Hint,
                codes::EQL_ARGUMENT_TYPE,
                format!(
                    "{what} must be an ip field; ECS {} maps `{name}` as `{}`",
                    opentide_ecs::version(),
                    field.type_name
                ),
                range,
            ));
            return;
        }
    }
    let found = ty(node, source);
    if !want.accepts(found) {
        let hint = match (want, found) {
            (Want::Ip, _) => "; pass the ip field itself",
            (Want::Str, Ty::Int | Ty::Double) if what.contains("`:`") => {
                "; use `==` to compare numbers"
            }
            _ => "",
        };
        out.push(diag(
            severity,
            codes::EQL_ARGUMENT_TYPE,
            format!(
                "{what} must be {}, found {}{hint}",
                want.name(),
                literal_desc(node, source, found)
            ),
            range,
        ));
    }
}

/// Literal types the Verifier rejects in function arguments, arithmetic, and
/// the `:`, `in~`, `like`, and `regex` predicates.
///
/// Function arguments are errors (Elasticsearch's own planner tests cover
/// `between`, `cidrMatch`, `number`, and `stringContains`). Operator operands
/// are warnings: the Verifier code path is the same, but converted public
/// rules (Sigma's `EventID:4624`) use them widely and no cluster run has
/// confirmed the rejection for a string field on the left of `:`.
pub(crate) fn check_types(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    match node.kind() {
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
                let what = format!("the {} argument of `{display}`", ordinal(i));
                check_value(arg, (want, Severity::Error), &what, source, out);
            }
        }
        "binary_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            let before = out.len();
            for side in ["left", "right"] {
                if let Some(operand) = node.child_by_field_name(side) {
                    let what = format!("an operand of `{operator}`");
                    check_value(operand, OPERAND_NUMBER, &what, source, out);
                }
            }
            // `c-uri:"x"` reads as `c - (uri : "x")`: a field name with a
            // hyphen needs backticks.
            if out.len() > before && operator == "-" {
                if let Some(name) = hyphenated_name(node, source) {
                    for d in &mut out[before..] {
                        d.message.push_str(&format!(
                            "; `{name}` reads as a subtraction, so quote a field name that contains `-` with backticks (`` `{name}` ``)"
                        ));
                    }
                }
            }
        }
        // Unary `+` is dropped by the builder; only `-` is typed.
        "unary_expression"
            if node
                .child_by_field_name("operator")
                .is_some_and(|o| text(o, source) == "-") =>
        {
            if let Some(operand) = node.child_by_field_name("operand") {
                check_value(
                    operand,
                    OPERAND_NUMBER,
                    "the operand of unary `-`",
                    source,
                    out,
                );
            }
        }
        "predicate_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            // `in` checks exactness and list compatibility, not string types:
            // mixing string and number literals fails against any mapped
            // field. An unmapped optional field (`?x`) is null and passes.
            if operator == "in" {
                let values = named_children(node, "values");
                let has = |t: fn(Ty) -> bool| values.iter().any(|v| t(ty(*v, source)));
                let optional = node
                    .child_by_field_name("subject")
                    .is_some_and(|s| text(s, source).starts_with('?'));
                if has(|t| t == Ty::Str) && has(|t| t.numeric()) && !optional {
                    out.push(diag(
                        Severity::Error,
                        codes::EQL_ARGUMENT_TYPE,
                        "an `in` list mixes strings and numbers; Elasticsearch requires every value to match the field's type".into(),
                        span_to_range(source, ByteSpan::new(node.start_byte(), node.end_byte())),
                    ));
                }
                return;
            }
            if let Some(subject) = node.child_by_field_name("subject") {
                let what = format!("the left side of `{operator}`");
                check_value(subject, OPERAND_STRING, &what, source, out);
            }
            // `like` folds its patterns to text, so any constant is accepted.
            if operator.starts_with("like") {
                return;
            }
            for value in named_children(node, "values") {
                let what = format!("a pattern of `{operator}`");
                check_value(value, OPERAND_STRING, &what, source, out);
            }
        }
        _ => {}
    }
}

/// `eql_not_boolean`: a string or number literal where EQL needs a boolean:
/// the `where` condition, an operand of `and` / `or`, or of `not`.
/// Elasticsearch rejects it on every release ("Condition expression needs to
/// be boolean").
pub(crate) fn check_conditions(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let fields: &[&str] = match node.kind() {
        "and_expression" | "or_expression" => &["left", "right"],
        "not_expression" => &["operand"],
        _ => &["condition"],
    };
    for field in fields {
        let Some(child) = node.child_by_field_name(field) else {
            continue;
        };
        let literal = strip_parens(child);
        if matches!(literal.kind(), "string" | "number") {
            let t = ty(literal, source);
            out.push(diag(
                Severity::Error,
                codes::EQL_NOT_BOOLEAN,
                format!(
                    "{} is not a condition: EQL needs a boolean here (a comparison, a predicate, `true` or `false`)",
                    literal_desc(literal, source, t)
                ),
                span_to_range(source, ByteSpan::new(literal.start_byte(), literal.end_byte())),
            ));
        }
    }
}

/// Whether a node under `ancestors` is a condition Elasticsearch translates
/// to a query on its own: reached from the event filter through `and`, `or`,
/// `not`, and parentheses only. Comparisons elsewhere (function arguments)
/// run as scripts, which may compare fields. An `and`/`or` with a
/// `true`/`false` operand is folded away first, so those paths are skipped.
///
/// `cache` maps an ancestor's id to the answer for its children, so a long
/// `or` chain is not rescanned for every comparison in it.
fn translated_as_query(ancestors: &[Node], cache: &mut HashMap<usize, bool>) -> bool {
    let mut passed = Vec::new();
    let mut result = false;
    for &parent in ancestors.iter().rev() {
        if let Some(&known) = cache.get(&parent.id()) {
            result = known;
            break;
        }
        passed.push(parent.id());
        match parent.kind() {
            "parenthesized_expression" | "not_expression" => continue,
            "and_expression" | "or_expression" => {
                let has_literal = ["left", "right"].iter().any(|f| {
                    parent
                        .child_by_field_name(f)
                        .is_some_and(|n| strip_parens(n).kind() == "boolean")
                });
                if !has_literal {
                    continue;
                }
            }
            "event_query" | "subquery" => result = true,
            _ => {}
        }
        break;
    }
    for id in passed {
        cache.insert(id, result);
    }
    result
}

pub(crate) fn strip_parens(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match node
            .named_children(&mut node.walk())
            .find(|n| n.kind() != "comment")
        {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn field_comparison(
    (left, right): (Node, Node),
    operator: &str,
    span: ByteSpan,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let (l_req, l_opt) = field_refs(left);
    let (r_req, r_opt) = field_refs(right);
    if !(l_req || l_opt) || !(r_req || r_opt) {
        return;
    }
    let range = span_to_range(source, span);
    if l_req && r_req {
        out.push(diag(
            Severity::Error,
            codes::EQL_FIELD_COMPARISON,
            format!(
                "Elasticsearch EQL cannot compare a field with another field (`{operator}`); one side must be a constant"
            ),
            range,
        ));
    } else {
        out.push(diag(
            Severity::Warning,
            codes::EQL_FIELD_COMPARISON,
            format!(
                "`{operator}` compares two fields; Elasticsearch rejects this unless the optional (`?`) field is unmapped and reads as null"
            ),
            range,
        ));
    }
}

/// Comparisons whose both sides read fields. `==`, `!=`, `<`, `<=`, `>`,
/// `>=`, and `in~` fail when translated to a query; an `in` list must hold
/// constants wherever it appears.
pub(crate) fn check_field_comparisons(
    node: Node,
    ancestors: &[Node],
    translated: &mut HashMap<usize, bool>,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    match node.kind() {
        "comparison" if translated_as_query(ancestors, translated) => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            let span = ByteSpan::new(node.start_byte(), node.end_byte());
            field_comparison((left, right), operator, span, source, out);
        }
        "predicate_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, source))
                .unwrap_or("");
            let values = named_children(node, "values");
            match operator {
                "in" => {
                    for value in values {
                        let (required, optional_only) = field_refs(value);
                        if !(required || optional_only) {
                            continue;
                        }
                        let range = span_to_range(
                            source,
                            ByteSpan::new(value.start_byte(), value.end_byte()),
                        );
                        if required {
                            out.push(diag(
                                Severity::Error,
                                codes::EQL_FIELD_COMPARISON,
                                "`in` lists must hold constants; Elasticsearch EQL cannot compare against a field".into(),
                                range,
                            ));
                        } else {
                            out.push(diag(
                                Severity::Warning,
                                codes::EQL_FIELD_COMPARISON,
                                "`in` lists must hold constants; this optional (`?`) field is accepted only while it is unmapped".into(),
                                range,
                            ));
                        }
                    }
                }
                "in~" if translated_as_query(ancestors, translated) => {
                    let Some(subject) = node.child_by_field_name("subject") else {
                        return;
                    };
                    for value in values {
                        let span = ByteSpan::new(value.start_byte(), value.end_byte());
                        field_comparison((subject, value), "in~", span, source, out);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}
