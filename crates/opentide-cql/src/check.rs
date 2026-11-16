//! Checks on a parsed CQL query that the grammar cannot make: functions and
//! their arguments against the catalog, regex flags, string escapes, where free
//! text and `<=>` may appear, Falcon event names, and the Next-Gen SIEM
//! correlation-rule rules. Every check reads the tree only; none guesses at a
//! tenant's fields, saved searches, lookup files or repositories.

use crate::catalog::{Catalog, Function, Parameter};
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use crate::{Context, child, nth, range, text};
use opentide_core::{Diagnostic, codes};
use opentide_parse::SyntaxError;
use rowan::WalkEvent;

/// Regex flags CQL accepts (`d` dot-all, `g`, `i`, `m`, `F` regex engine v2).
pub const REGEX_FLAGS: &str = "dgimF";

/// String escapes CrowdStrike documents: `\"`, `\\`, `\n` (the grammar subset),
/// `\t` and `\uXXXX` (createEvents()), and `\xHH`, which the stripAnsiCodes()
/// example relies on (`"\x1b[93;41mColor"` becomes `Color`).
const STRING_ESCAPES: &[char] = &['"', '\\', 'n', 't', 'u', 'x'];

pub(crate) fn diagnostics(
    root: &SyntaxNode,
    errors: &[SyntaxError],
    source: &str,
    ctx: &Context,
) -> Vec<Diagnostic> {
    let catalog = Catalog::cached();
    let broken = Broken::new(errors);
    let mut out = Vec::new();
    // Checks that look upward read `ancestors` and `above`: a scan of
    // `ancestors` at every node makes a deeply nested query quadratic.
    walk_with_above(root, source, catalog, |node, ancestors, above| {
        const CHECKED: &[K] = &[
            K::FUNCTION_CALL,
            K::REGEX,
            K::STRING,
            K::LINK_CONSTRAINT,
            K::FIELD_FILTER,
            K::OR_FILTER,
        ];
        // Inside a syntax error the tree is a guess: its first error is the
        // finding, not what the guess looks like.
        if CHECKED.contains(&node.kind()) && (above.error || broken.contains(node)) {
            return;
        }
        match node.kind() {
            K::FUNCTION_CALL => function_call(node, ancestors, above, source, catalog, &mut out),
            K::REGEX => regex(node, source, &mut out),
            K::STRING => string(node, ancestors, source, &mut out),
            K::LINK_CONSTRAINT => link_constraint(node, above, source, &mut out),
            K::FIELD_FILTER => event_name(node, source, catalog, &mut out),
            K::OR_FILTER => regex_group_under_or(node, source, &mut out),
            _ => {}
        }
    });
    // Step order is only known in a tree without errors: after recovery the
    // text past a syntax error is a guess at steps, not what was written.
    if errors.is_empty() {
        free_text_after_aggregate(root, source, catalog, &mut out);
    }
    if ctx.correlation_rule {
        correlation_rule(root, source, catalog, &mut out);
    }
    out
}

/// Where the parse errors are, to find the nodes they break. tree-sitter wrapped a broken
/// construct in an ERROR node or gave it a MISSING child; the rowan tree keeps the construct
/// and records the fault as a gap, often at the construct's end (`foo((` before a `|` is a
/// call with two `)` missing at its end). Both lists are sorted offsets.
struct Broken {
    /// Where each error is.
    any: Vec<u32>,
    /// Where an error says something is missing or expected: the construct that ends there
    /// was not finished. (An `unexpected` token after a node is not the node's fault.)
    unfinished: Vec<u32>,
}

impl Broken {
    fn new(errors: &[SyntaxError]) -> Self {
        let at = |e: &SyntaxError| u32::from(e.gap.start());
        let mut any: Vec<u32> = errors.iter().map(at).collect();
        let mut unfinished: Vec<u32> = errors
            .iter()
            .filter(|e| e.message.starts_with("missing ") || e.message.starts_with("expected "))
            .map(at)
            .collect();
        any.sort_unstable();
        unfinished.sort_unstable();
        Self { any, unfinished }
    }

    /// Whether a parse error is inside `node`, or one at its end says it was not finished.
    /// Two binary searches: no scan of the errors per node.
    fn contains(&self, node: &SyntaxNode) -> bool {
        let r = node.text_range();
        let (start, end) = (u32::from(r.start()), u32::from(r.end()));
        let first_after = |v: &[u32]| v.get(v.partition_point(|&o| o <= start)).copied();
        first_after(&self.any).is_some_and(|o| o < end)
            || first_after(&self.unfinished).is_some_and(|o| o <= end)
    }
}

/// What the ancestors of a node add up to, so that no check scans them: one
/// scan per node is quadratic in the nesting depth (`groupBy(a, function=`
/// 3000 times). Indexes are into the `ancestors` slice.
#[derive(Debug, Clone, Copy, Default)]
struct Above {
    /// An ancestor is a syntax error.
    error: bool,
    /// The nearest enclosing `function_call`.
    call: Option<usize>,
    /// The nearest enclosing `correlate()` call.
    correlate: Option<usize>,
    /// An ancestor is a `correlate()` call or a call to an aggregate.
    correlate_or_aggregate: bool,
}

/// Every node in pre-order with its ancestors (root first) and [`Above`] for
/// them, iteratively: each ancestor is summarised once, when the walk enters
/// its children.
fn walk_with_above(
    root: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    mut f: impl FnMut(&SyntaxNode, &[SyntaxNode], Above),
) {
    let mut ancestors: Vec<SyntaxNode> = Vec::new();
    // `summary[i]` covers `ancestors[..=i]`.
    let mut summary: Vec<Above> = Vec::new();
    for event in root.preorder() {
        match event {
            WalkEvent::Enter(node) => {
                let prev = summary.last().copied().unwrap_or_default();
                f(&node, &ancestors, prev);
                let i = ancestors.len();
                let is_call = node.kind() == K::FUNCTION_CALL;
                let correlate = is_call && is_correlate(&node, source);
                let aggregate = is_call
                    && catalog
                        .function(call_name(&node, source))
                        .is_some_and(|f| f.aggregate);
                summary.push(Above {
                    error: prev.error || node.kind() == K::ERROR,
                    call: if is_call { Some(i) } else { prev.call },
                    correlate: if correlate { Some(i) } else { prev.correlate },
                    correlate_or_aggregate: prev.correlate_or_aggregate || correlate || aggregate,
                });
                ancestors.push(node);
            }
            WalkEvent::Leave(_) => {
                ancestors.pop();
                summary.pop();
            }
        }
    }
}

/// The name a call is written with (`groupBy`, `array:filter`).
pub(crate) fn call_name<'s>(call: &SyntaxNode, source: &'s str) -> &'s str {
    child(call, K::FUNCTION_NAME).map_or("", |n| text(&n, source))
}

/// The arguments of a call: `(name node, value node)`, the name absent when
/// the argument has none.
pub(crate) fn call_arguments(call: &SyntaxNode) -> Vec<(Option<SyntaxNode>, Option<SyntaxNode>)> {
    let Some(list) = child(call, K::ARGUMENT_LIST) else {
        return Vec::new();
    };
    list.children()
        .filter_map(|arg| match arg.kind() {
            K::NAMED_ARGUMENT => Some((nth(&arg, 0), nth(&arg, 1))),
            K::ARGUMENT => Some((None, nth(&arg, 0))),
            _ => None,
        })
        .collect()
}

/// An argument or parameter name, without the quotes of `"name"=...`.
pub(crate) fn name_text<'s>(node: &SyntaxNode, source: &'s str) -> &'s str {
    unquote(text(node, source))
}

pub(crate) fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// The range of a call's name, or of the call when it has none.
fn name_range(call: &SyntaxNode, source: &str) -> opentide_core::Range {
    child(call, K::FUNCTION_NAME).map_or_else(|| range(source, call), |n| range(source, &n))
}

fn function_call(
    call: &SyntaxNode,
    ancestors: &[SyntaxNode],
    above: Above,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let Some(name_node) = child(call, K::FUNCTION_NAME) else {
        return;
    };
    let name = text(&name_node, source);
    // Computed only for a finding: a range counts lines from the start.
    let name_range = || range(source, &name_node);
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
    placement(call, function, ancestors, above, source, out);
    let implied = implied_parameters(call, ancestors);
    arguments(call, function, implied, source, catalog, out);
}

/// Where a call may stand: correlate() not inside another function's
/// arguments (a defineTable() subquery runs on its own and may hold it), no
/// aggregate in correlate()'s queries (its `aggregation=` takes them), and no
/// aggregate as a `match` guard, which must be a filter.
fn placement(
    call: &SyntaxNode,
    function: &Function,
    ancestors: &[SyntaxNode],
    above: Above,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if function.name == "correlate"
        && let Some(outer) = above.call.and_then(|i| ancestors.get(i))
    {
        let outer_name = call_name(outer, source);
        if !outer_name.eq_ignore_ascii_case("defineTable") {
            out.push(Diagnostic::error(
                codes::CQL_CORRELATE_PLACEMENT,
                format!("correlate() cannot be an argument of {outer_name}()"),
                name_range(call, source),
            ));
        }
    }
    if function.aggregate {
        // The nearest enclosing correlate(), and the argument of it we are in.
        if let Some(i) = above.correlate {
            let in_aggregation = ancestors.get(i + 2).is_some_and(|arg| {
                arg.kind() == K::NAMED_ARGUMENT
                    && nth(arg, 0)
                        .is_some_and(|n| name_text(&n, source).eq_ignore_ascii_case("aggregation"))
            });
            if !in_aggregation {
                out.push(Diagnostic::error(
                    codes::CQL_CORRELATE_PLACEMENT,
                    format!(
                        "correlate()'s queries take filters only, not the aggregate `{}`",
                        function.name
                    ),
                    name_range(call, source),
                ));
            }
        }
        let guard = ancestors
            .last()
            .is_some_and(|p| p.kind() == K::MATCH_BRANCH && nth(p, 0).as_ref() == Some(call));
        if guard {
            out.push(Diagnostic::error(
                codes::CQL_MATCH_GUARD,
                format!(
                    "a match guard must be a filter, not the aggregate `{}`",
                    function.name
                ),
                name_range(call, source),
            ));
        }
    }
}

/// What the call's position supplies without an argument: `x =~ f()` gives
/// `field`, `x := f()` gives `as`, and a `match` guard gives `field`.
fn implied_parameters(call: &SyntaxNode, ancestors: &[SyntaxNode]) -> (bool, bool) {
    let mut up = ancestors.iter().rev();
    let mut parent = up.next();
    if parent.is_some_and(|p| p.kind() == K::NEGATED_FUNCTION_CALL) {
        parent = up.next();
    }
    let Some(parent) = parent else {
        return (false, false);
    };
    let field = matches!(parent.kind(), K::FIELD_SHORTHAND | K::MATCH_BRANCH);
    let assigned = parent.kind() == K::ASSIGNMENT && nth(parent, 1).as_ref() == Some(call);
    (field, assigned)
}

fn arguments(
    call: &SyntaxNode,
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
        let parameter: Option<&Parameter> = match &name_node {
            Some(n) => {
                let name = name_text(n, source);
                if let Some(p) = function.parameter(name) {
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
                } else {
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
            None => {
                // `correlate(A: {...}, B: {...})`: every named subquery binds `query`.
                let named_subquery = value.as_ref().is_some_and(is_named_subquery);
                let query_given = function
                    .unnamed_parameter()
                    .is_some_and(|p| given.contains(&p.name.as_str()));
                // `correlate(query=A: {...}, B: {...})` is `correlate(A: {...}, B: {...})`.
                if named_subquery && (unnamed_seen || query_given) {
                    continue;
                }
                let at = || {
                    value
                        .as_ref()
                        .map_or_else(|| range(source, call), |v| range(source, v))
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
                    // An array parameter gathers several (`readFile("a.csv",
                    // "b.csv")`, `table(a, b)`, as CrowdStrike's examples
                    // write them); any other takes one.
                    Some(p) if unnamed_seen && p.multi => continue,
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
                .as_ref()
                .or(value.as_ref())
                .map_or_else(|| range(source, call), |n| range(source, n));
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
        if let Some(value) = &value {
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
        let list = missing
            .iter()
            .map(|m| format!("`{m}`"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(Diagnostic::error(
            codes::CQL_MISSING_PARAMETER,
            format!("`{}` needs {list}", function.name),
            name_range(call, source),
        ));
    }
}

/// `Name: { ... }`, possibly followed by attributes (`include: [a, b]`).
fn is_named_subquery(value: &SyntaxNode) -> bool {
    match value.kind() {
        K::NAMED_SUBQUERY => true,
        K::ATTRIBUTED_EXPRESSION => nth(value, 0).is_some_and(|e| e.kind() == K::NAMED_SUBQUERY),
        _ => false,
    }
}

/// A literal value: a bare word or number, or a quoted string. Anything else
/// (a field reference in an expression, a call, a `?param`) is not checked.
fn literal<'s>(node: &SyntaxNode, source: &'s str) -> Option<&'s str> {
    match node.kind() {
        K::UNQUOTED_PATTERN | K::FIELD_NAME | K::NUMBER | K::BOOLEAN | K::TAG => {
            Some(text(node, source))
        }
        K::STRING => Some(unquote(text(node, source))),
        _ => None,
    }
}

fn parameter_value(
    function: &Function,
    parameter: &Parameter,
    value: &SyntaxNode,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if parameter.values.is_empty()
        && parameter.min.is_none()
        && parameter.max.is_none()
        && parameter.ty != "boolean"
    {
        return;
    }
    let mut values: Vec<SyntaxNode> = Vec::new();
    if value.kind() == K::ARRAY {
        if !parameter.multi {
            return;
        }
        values.extend(value.children().filter(|c| c.kind() != K::ERROR));
    } else {
        values.push(value.clone());
    }
    for node in values {
        let Some(lit) = literal(&node, source) else {
            continue;
        };
        if let Some(problem) = value_problem(parameter, lit) {
            out.push(Diagnostic::error(
                codes::CQL_PARAMETER_VALUE,
                format!("`{}` of `{}` {problem}", parameter.name, function.name),
                range(source, &node),
            ));
        }
    }
}

/// Why `lit` is not a value `parameter` takes, or `None` when it is.
#[expect(
    clippy::cast_precision_loss,
    reason = "the catalog's bounds are small integers, exact in an f64"
)]
fn value_problem(parameter: &Parameter, lit: &str) -> Option<String> {
    // Booleans are `true` or `false`. The data-types page says "strictly in
    // lowercase", but CrowdStrike's own function examples write
    // `count(..., distinct=True)`, so case is not judged.
    if parameter.ty == "boolean" {
        let ok = lit.eq_ignore_ascii_case("true") || lit.eq_ignore_ascii_case("false");
        return (!ok).then(|| format!("is `true` or `false`, not `{lit}`"));
    }
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
    // Exact, ignoring case. Spellings CrowdStrike's own content uses beyond the
    // reference (`order=des`) are listed in the catalog's `deprecated_values`.
    let known = parameter
        .values
        .iter()
        .chain(&parameter.deprecated_values)
        .any(|v| v.eq_ignore_ascii_case(lit));
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

fn regex(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let Some(flags) = child(node, K::REGEX_FLAGS) else {
        return;
    };
    let bad: String = text(&flags, source)
        .chars()
        .filter(|c| !REGEX_FLAGS.contains(*c))
        .collect();
    if !bad.is_empty() {
        out.push(Diagnostic::error(
            codes::CQL_REGEX_FLAG,
            format!("unknown regex flag `{bad}`: CQL takes d, g, i, m and F"),
            range(source, &flags),
        ));
    }
}

/// A string bound to a regex parameter (`regex("\d+")`) goes to the regex
/// engine, where `\d` is meant; only other strings get the escape warning.
fn regex_argument(ancestors: &[SyntaxNode], source: &str) -> bool {
    // string <- argument <- argument_list <- function_call
    let [.., call, _list, arg] = ancestors else {
        return false;
    };
    if call.kind() != K::FUNCTION_CALL {
        return false;
    }
    let Some(function) = Catalog::cached().function(call_name(call, source)) else {
        return true;
    };
    let parameter = match arg.kind() {
        K::ARGUMENT => function.unnamed_parameter(),
        K::NAMED_ARGUMENT => nth(arg, 0).and_then(|n| function.parameter(name_text(&n, source))),
        _ => None,
    };
    parameter.is_some_and(|p| p.ty == "regex")
        || function.category.iter().any(|c| c == "regular-expression")
}

fn string(node: &SyntaxNode, ancestors: &[SyntaxNode], source: &str, out: &mut Vec<Diagnostic>) {
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
        // A backslash may end a line of a string that spans lines.
        if next == '\n' || next == '\r' {
            continue;
        }
        if !STRING_ESCAPES.contains(&next) {
            let start = usize::from(node.text_range().start()) + i;
            let span = opentide_core::ByteSpan::new(start, start + 1 + next.len_utf8());
            out.push(Diagnostic::warning(
                codes::CQL_STRING_ESCAPE,
                format!(
                    "`\\{next}` is not a string escape CrowdStrike documents (`\\\"`, `\\\\`, `\\n`, `\\t`, `\\u`, `\\x`); write `\\\\` for a literal backslash"
                ),
                opentide_core::span_to_range(source, span),
            ));
        }
    }
}

/// The call a negated call, or a shorthand's function, makes.
fn negated_inner(call: SyntaxNode) -> SyntaxNode {
    if call.kind() == K::NEGATED_FUNCTION_CALL {
        child(&call, K::FUNCTION_CALL).unwrap_or(call)
    } else {
        call
    }
}

/// Whether a step aggregates: an aggregate function, possibly negated or
/// assigned, or a `[...]` stats shorthand.
fn aggregates(step: &SyntaxNode, source: &str, catalog: &Catalog) -> bool {
    let call = match step.kind() {
        K::STATS_SHORTHAND => return true,
        K::FUNCTION_CALL => Some(step.clone()),
        K::NEGATED_FUNCTION_CALL => child(step, K::FUNCTION_CALL),
        K::ASSIGNMENT => nth(step, 1).filter(|v| v.kind() == K::FUNCTION_CALL),
        K::FIELD_SHORTHAND => nth(step, 1)
            .filter(|f| matches!(f.kind(), K::FUNCTION_CALL | K::NEGATED_FUNCTION_CALL))
            .map(negated_inner),
        _ => None,
    };
    call.and_then(|c| catalog.function(call_name(&c, source)))
        .is_some_and(|f| f.aggregate)
}

/// Free text after the first aggregate of a pipeline (refused since 1.190).
///
/// One pass over the tree, linear in its size: each pipeline walks only its
/// own steps, stopping at nested pipelines, which it queues. A `case` branch
/// or a `match` body runs on the events its step receives, so it starts
/// aggregated when its step comes after an aggregate; a `{ ... }` subquery
/// (`join`, `defineTable`, `correlate`) reads events of its own, so it does not.
/// An aggregate inside a branch is not carried out of it: a miss, never a
/// false finding.
fn free_text_after_aggregate(
    root: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let mut queue: Vec<(SyntaxNode, bool)> = root
        .children()
        .filter(|n| n.kind() == K::PIPELINE)
        .map(|n| (n, false))
        .collect();
    while let Some((pipeline, inherited)) = queue.pop() {
        let mut aggregated = inherited;
        let mut after_source = false;
        for step in pipeline.children() {
            let mut walk = step.preorder();
            while let Some(event) = walk.next() {
                let WalkEvent::Enter(n) = event else {
                    continue;
                };
                if n.kind() == K::ERROR {
                    walk.skip_subtree();
                } else if n.kind() == K::PIPELINE {
                    let body = n
                        .parent()
                        .is_some_and(|p| matches!(p.kind(), K::CASE_BRANCH | K::MATCH_BRANCH));
                    queue.push((n, aggregated && body));
                    walk.skip_subtree();
                } else if aggregated && n.kind() == K::FREE_TEXT {
                    // A bare regex is free text too ("Regex literals that are not
                    // particular to a field ... are also free-text-searches"); `*`
                    // (a `case` branch that takes every event) is no search.
                    let everything = nth(&n, 0).is_some_and(|v| text(&v, source) == "*");
                    if !everything {
                        out.push(Diagnostic::error(
                            codes::CQL_FREE_TEXT_AFTER_AGGREGATE,
                            "free-text search cannot follow an aggregate function: filter on a field, or move it before the aggregate",
                            range(source, &n),
                        ));
                    }
                }
            }
            if let Some(call) = step_call(&step) {
                let name = call_name(&call, source);
                order_checks(&call, name, aggregated, after_source, source, out);
                if catalog
                    .function(name)
                    .is_some_and(|f| f.kind.iter().any(|k| k == "source"))
                {
                    after_source = true;
                }
            }
            if aggregates(&step, source, catalog) {
                aggregated = true;
            }
        }
    }
}

/// The call a step makes, negated or not.
fn step_call(step: &SyntaxNode) -> Option<SyntaxNode> {
    match step.kind() {
        K::FUNCTION_CALL => Some(step.clone()),
        K::NEGATED_FUNCTION_CALL => child(step, K::FUNCTION_CALL),
        _ => None,
    }
}

/// What a call may not do after an aggregate or a source function, as the
/// 1.188/1.190 release notes and the correlate() page say.
fn order_checks(
    call: &SyntaxNode,
    name: &str,
    aggregated: bool,
    after_source: bool,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let lower = name.to_ascii_lowercase();
    if aggregated && lower == "wildcard" && !call_has_parameter(call, "field", source) {
        out.push(Diagnostic::error(
            codes::CQL_FREE_TEXT_AFTER_AGGREGATE,
            "wildcard() without `field` searches the raw event, which cannot follow an aggregate function",
            name_range(call, source),
        ));
    }
    if aggregated
        && matches!(
            lower.as_str(),
            "eventsize" | "eventinternals" | "eventfieldcount"
        )
    {
        out.push(Diagnostic::error(
            codes::CQL_EVENT_FUNCTION_AFTER_AGGREGATE,
            format!(
                "{name}() reads the raw event, which is gone after the first aggregate function"
            ),
            name_range(call, source),
        ));
    }
    if lower == "correlate" && (aggregated || after_source) {
        let what = if aggregated {
            "an aggregate function"
        } else {
            "a source function (readFile(), createEvents())"
        };
        out.push(Diagnostic::error(
            codes::CQL_CORRELATE_PLACEMENT,
            format!("correlate() cannot follow {what}"),
            name_range(call, source),
        ));
    }
}

/// Whether `call` names `parameter` among its arguments.
fn call_has_parameter(call: &SyntaxNode, parameter: &str, source: &str) -> bool {
    call_arguments(call)
        .into_iter()
        .any(|(n, _)| n.is_some_and(|n| name_text(&n, source).eq_ignore_ascii_case(parameter)))
}

/// A regex with named groups under `or` extracts nothing: the grammar subset
/// says an OR operand "cannot be a Regex with named groups", and the field
/// page shows `type=FOO or /disk_free=(?<space>[0-9]+)/` as one that does not
/// work.
///
/// The tree holds a run of `or` as one node; the warnings come in the order of
/// the left-nested binary tree that tree-sitter built (`((a or b) or c) or d`,
/// each node visited before its left side): the last operand first, down to the
/// third, then the first and the second.
fn regex_group_under_or(node: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let operands: Vec<SyntaxNode> = node
        .children()
        .filter(|c| !matches!(c.kind(), K::OR | K::ERROR))
        .collect();
    let order = operands.iter().skip(2).rev().chain(operands.iter().take(2));
    for side in order {
        if side.kind() != K::FREE_TEXT {
            continue;
        }
        let Some(regex) = nth(side, 0).filter(|v| v.kind() == K::REGEX) else {
            continue;
        };
        let pattern = child(&regex, K::REGEX_PATTERN).map_or("", |p| text(&p, source));
        if pattern.contains("(?<") || pattern.contains("(?P<") {
            out.push(Diagnostic::warning(
                codes::CQL_REGEX_GROUP_UNDER_OR,
                "a regex under `or` extracts no fields: its named groups are ignored; run it as its own step",
                range(source, &regex),
            ));
        }
    }
}

/// `a <=> B.b` links two correlate() queries; anywhere else it is an error.
fn link_constraint(node: &SyntaxNode, above: Above, source: &str, out: &mut Vec<Diagnostic>) {
    if above.correlate.is_some() {
        return;
    }
    out.push(Diagnostic::error(
        codes::CQL_LINK_OUTSIDE_CORRELATE,
        "`<=>` links the queries of correlate(); it is not a filter",
        range(source, node),
    ));
}

/// `#event_simpleName=Name` where no Falcon event has that name.
fn event_name(node: &SyntaxNode, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let (Some(field), Some(value)) = (nth(node, 0), nth(node, 1)) else {
        return;
    };
    let field = unquote(text(&field, source));
    if field != "#event_simpleName" && field != "event_simpleName" {
        return;
    }
    let operator = node
        .children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .find(|t| !matches!(t.kind(), K::WHITESPACE | K::LINE_COMMENT | K::BLOCK_COMMENT))
        .map_or(K::ERROR, |t| t.kind());
    if !matches!(operator, K::EQ | K::NOT_EQ) {
        return;
    }
    if !matches!(
        value.kind(),
        K::UNQUOTED_PATTERN | K::STRING | K::FIELD_NAME
    ) {
        return;
    }
    let name = unquote(text(&value, source));
    if name.is_empty() || name.contains('*') || catalog.event(name).is_some() {
        return;
    }
    let mut d = Diagnostic::warning(
        codes::CQL_UNKNOWN_EVENT,
        format!(
            "`{name}` is not a Falcon event the engine knows (names are case-sensitive; a newer sensor may send events the catalog lacks)"
        ),
        range(source, &value),
    );
    if let Some(s) = catalog.suggest_event(name) {
        d = d.with_suggestion(s);
    }
    out.push(d);
}

fn is_correlate(node: &SyntaxNode, source: &str) -> bool {
    node.kind() == K::FUNCTION_CALL && call_name(node, source).eq_ignore_ascii_case("correlate")
}

/// Next-Gen SIEM: `correlate()` takes no other aggregate in the same query.
fn correlation_rule(root: &SyntaxNode, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let mut has_correlate = false;
    let mut outside: Vec<(SyntaxNode, &str)> = Vec::new();
    walk_with_above(root, source, catalog, |n, _, above| {
        if n.kind() != K::FUNCTION_CALL {
            return;
        }
        if is_correlate(n, source) {
            has_correlate = true;
            return;
        }
        // Aggregates inside correlate()'s own arguments follow its rules, and
        // one inside another aggregate (`groupBy(x, function=count())`) is
        // that aggregate's finding.
        if above.correlate_or_aggregate {
            return;
        }
        if let Some(function) = catalog
            .function(call_name(n, source))
            .filter(|f| f.aggregate)
        {
            outside.push((n.clone(), function.name.as_str()));
        }
    });
    if !has_correlate {
        return;
    }
    for (n, name) in outside {
        out.push(Diagnostic::error(
            codes::CQL_CORRELATE_AGGREGATE,
            format!("a correlation rule cannot combine correlate() with the aggregate `{name}`"),
            name_range(&n, source),
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
        // No loose matching: a spelling beyond the reference must be recorded
        // (the catalog lists `des` for sort/table order, as CrowdStrike's
        // dashboards write it).
        assert!(value_problem(&order, "des").is_some());
        let mut recorded = param("enum", &["asc", "desc"], false, None, None);
        recorded.deprecated_values = vec!["des".into()];
        assert_eq!(value_problem(&recorded, "des"), None);
        assert!(value_problem(&recorded, "descending_by_time").is_some());
        let boolean = param("boolean", &[], false, None, None);
        assert_eq!(value_problem(&boolean, "true"), None);
        assert_eq!(value_problem(&boolean, "True"), None);
        assert!(value_problem(&boolean, "maybe").is_some());
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
