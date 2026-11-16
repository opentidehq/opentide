//! Checks Elasticsearch makes after parsing, that need no index mapping:
//! literal argument types (the Verifier's type resolution) and comparisons
//! between two fields (rejected when the filter is translated to a query).
//!
//! Without a field catalog a field's type is unknown, so only literals,
//! function results, and arithmetic are typed here. Every type rule accepts
//! `null`, as Elasticsearch's `TypeResolutions.isType` does.
//!
//! A run of `or`, `and` or arithmetic is one flat node. The checks read it as the levels
//! Elasticsearch's builder nests it in, the left one innermost ([`Run`]): each level's operands
//! are checked, the outermost level first, and an `and`/`or` level with a `true` or `false`
//! operand is folded away before translation.

use crate::ast;
use crate::nav::{span, text};
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::{ByteSpan, Diagnostic, Range, Severity, codes, span_to_range};
use opentide_parse::ast::AstNode;
use rowan::NodeOrToken;
use std::collections::HashMap;

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
    // `allow`, not `expect`: clippy's glob-import lints never fulfil an expectation.
    #[allow(
        clippy::enum_glob_use,
        reason = "the table reads as EQL's function signatures"
    )]
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
// (crates/testdata/oracles/elasticsearch/eql-argument-types).
const OPERAND_STRING: (Want, Severity) = (Want::Str, Severity::Error);
const OPERAND_NUMBER: (Want, Severity) = (Want::Numeric, Severity::Error);

/// A call's name, lower case and without `~`.
pub(crate) fn function_name(call: &ast::FunctionCall, source: &str) -> String {
    call.name()
        .map(|n| {
            text(n.syntax(), source)
                .trim_end_matches('~')
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

/// One part of a run level: the level below it, a node, or a token.
#[derive(Clone)]
enum Slot {
    Below,
    Node(SyntaxNode),
    Token(SyntaxToken),
}

/// A run of `or`, `and` or arithmetic, read as the levels it nests in: the first holds the
/// run's first three visible children, each next one the level below and the next two, the
/// last one the level below and the last two. (On broken input, with a doubled or a missing
/// operator, the last level may hold a node the one below holds too, as the builder's reading
/// of the tree did.)
pub(crate) struct Run {
    /// The parts of each level, the innermost first.
    levels: Vec<Vec<Slot>>,
    /// Where each level's span ends; every level starts where the run does.
    ends: Vec<usize>,
    start: usize,
}

impl Run {
    pub(crate) fn of(node: &SyntaxNode) -> Run {
        let kids: Vec<Slot> = node
            .children_with_tokens()
            .filter_map(|e| match e {
                NodeOrToken::Node(n) => Some(Slot::Node(n)),
                NodeOrToken::Token(t) if !t.kind().is_trivia() => Some(Slot::Token(t)),
                NodeOrToken::Token(_) => None,
            })
            .collect();
        let start = match kids.first() {
            Some(Slot::Node(n)) => span(n).start,
            Some(Slot::Token(t)) => usize::from(t.text_range().start()),
            _ => span(node).start,
        };
        let end_of = |slot: &Slot| match slot {
            Slot::Node(n) => span(n).end,
            Slot::Token(t) => usize::from(t.text_range().end()),
            Slot::Below => start,
        };
        let mut levels = Vec::new();
        if kids.len() <= 3 {
            levels.push(kids.clone());
        } else {
            levels.push(kids[..3].to_vec());
            let mut i = 3;
            while i + 2 < kids.len() {
                levels.push(vec![Slot::Below, kids[i].clone(), kids[i + 1].clone()]);
                i += 2;
            }
            let n = kids.len();
            levels.push(vec![Slot::Below, kids[n - 2].clone(), kids[n - 1].clone()]);
        }
        let ends = levels
            .iter()
            .map(|l| l.last().map_or(start, end_of))
            .collect();
        Run {
            levels,
            ends,
            start,
        }
    }

    /// The number of levels.
    pub(crate) fn len(&self) -> usize {
        self.levels.len()
    }

    /// A level's span.
    pub(crate) fn span(&self, level: usize) -> ByteSpan {
        ByteSpan::new(self.start, self.ends[level])
    }

    /// A level's left and right operands: its first and second node (the level below counts as
    /// a node).
    fn sides(&self, level: usize) -> (Option<&Slot>, Option<&Slot>) {
        let mut named = self.levels[level]
            .iter()
            .filter(|s| !matches!(s, Slot::Token(_)));
        (named.next(), named.next())
    }

    /// A level's operator: its first token.
    fn operator(&self, level: usize) -> Option<&SyntaxToken> {
        self.levels[level].iter().find_map(|s| match s {
            Slot::Token(t) => Some(t),
            _ => None,
        })
    }

    /// The first level that holds each node of the run.
    fn levels_of(&self) -> HashMap<SyntaxNode, usize> {
        let mut first = HashMap::new();
        for (i, level) in self.levels.iter().enumerate() {
            for slot in level {
                if let Slot::Node(n) = slot {
                    first.entry(n.clone()).or_insert(i);
                }
            }
        }
        first
    }
}

/// The node of a slot, unless it is the level below.
fn node_of(slot: Option<&Slot>) -> Option<&SyntaxNode> {
    match slot {
        Some(Slot::Node(n)) => Some(n),
        _ => None,
    }
}

/// The type of an expression. Parentheses and signs pass a type through (a sign only a
/// number's): they are unwound in a loop, as a run is folded in one.
fn ty(node: &SyntaxNode, source: &str) -> Ty {
    let mut node = node.clone();
    let mut signed = false;
    loop {
        match node.kind() {
            K::PARENTHESIZED_EXPRESSION | K::UNARY_EXPRESSION => {
                signed |= node.kind() == K::UNARY_EXPRESSION;
                match node.first_child() {
                    Some(inner) => node = inner,
                    None => return Ty::Unknown,
                }
            }
            _ => {
                let t = ty_of(&node, source);
                return if signed && !t.numeric() {
                    Ty::Unknown
                } else {
                    t
                };
            }
        }
    }
}

/// The type of an expression that is neither parenthesized nor signed.
fn ty_of(node: &SyntaxNode, source: &str) -> Ty {
    match node.kind() {
        K::STRING => Ty::Str,
        K::BOOLEAN => Ty::Bool,
        K::NULL => Ty::Null,
        // An integer literal too large for a long becomes a double.
        K::NUMBER => {
            let t = text(node, source);
            if t.bytes().all(|b| b.is_ascii_digit()) && t.parse::<i64>().is_ok() {
                Ty::Int
            } else {
                Ty::Double
            }
        }
        K::COMPARISON
        | K::PREDICATE_EXPRESSION
        | K::AND_EXPRESSION
        | K::OR_EXPRESSION
        | K::NOT_EXPRESSION => Ty::Bool,
        K::BINARY_EXPRESSION => {
            if let Some(known) = TYPES.with(|t| t.borrow().get(node).copied()) {
                return known;
            }
            let t = run_ty(&Run::of(node), source);
            TYPES.with(|types| types.borrow_mut().insert(node.clone(), t));
            t
        }
        K::FUNCTION_CALL => {
            let Some(call) = ast::FunctionCall::cast(node.clone()) else {
                return Ty::Unknown;
            };
            match function_name(&call, source).as_str() {
                "between" | "concat" | "string" | "substring" => Ty::Str,
                "length" | "indexof" => Ty::Int,
                // `ToNumber` is declared double.
                "number" => Ty::Double,
                "cidrmatch" | "endswith" | "startswith" | "stringcontains" => Ty::Bool,
                "add" | "subtract" | "multiply" | "divide" | "modulo" => {
                    let args: Vec<ast::Expr> = call.exprs().collect();
                    match args.as_slice() {
                        [a, b] => arithmetic(ty(a.syntax(), source), ty(b.syntax(), source)),
                        _ => Ty::Unknown,
                    }
                }
                _ => Ty::Unknown,
            }
        }
        _ => Ty::Unknown,
    }
}

thread_local! {
    /// Each run of arithmetic's type, while one query is analysed: a run nested in
    /// parentheses is the left operand of the run around it, and each level of each run checks
    /// its operands' types, so without it `((1 + 1) + 1) …` would be typed again at every depth.
    static TYPES: std::cell::RefCell<HashMap<SyntaxNode, Ty>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Forgets the types of the last query's runs (its tree is gone).
pub(crate) fn forget_types() {
    TYPES.with(|t| t.borrow_mut().clear());
}

/// The type of a run of `+ - * / %`: each level's right operand folded in, from the innermost
/// level, in a loop.
fn run_ty(run: &Run, source: &str) -> Ty {
    let side = |slot: Option<&Slot>| node_of(slot).map_or(Ty::Unknown, |n| ty(n, source));
    let mut acc = side(run.sides(0).0);
    for level in 0..run.len() {
        acc = arithmetic(acc, side(run.sides(level).1));
    }
    acc
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

/// `a-b` written without spaces where `a` is a field: the name the author probably meant.
fn hyphenated_name(run: &Run, level: usize, source: &str) -> Option<String> {
    let (left, right) = run.sides(level);
    let (left, right) = (node_of(left)?, node_of(right)?);
    let op = run.operator(level)?.text_range();
    if left.kind() != K::FIELD
        || span(left).end != usize::from(op.start())
        || usize::from(op.end()) != span(right).start
    {
        return None;
    }
    let mut first = right.clone();
    while first.kind() != K::FIELD {
        first = first.first_child()?;
    }
    Some(format!("{}-{}", text(left, source), text(&first, source)))
}

/// Field references inside an expression: `(required, optional_only)`.
/// An optional field (`?x`) that is not mapped becomes `null`, a constant.
fn field_refs(node: &SyntaxNode) -> (bool, bool) {
    let mut required = false;
    let mut optional = false;
    let mut walk = node.preorder();
    while let Some(event) = walk.next() {
        let rowan::WalkEvent::Enter(n) = event else {
            continue;
        };
        if n.kind() == K::FIELD {
            if n.children().any(|c| c.kind() == K::OPTIONAL_MARKER) {
                optional = true;
            } else {
                required = true;
            }
            walk.skip_subtree();
        }
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

fn literal_desc(node: &SyntaxNode, source: &str, found: Ty) -> String {
    let t = text(node, source);
    let short: String = t.chars().take(40).collect();
    let ellipsis = if short.len() < t.len() { "…" } else { "" };
    format!("{} `{short}{ellipsis}`", found.name())
}

fn check_value(
    node: &SyntaxNode,
    (want, severity): (Want, Severity),
    what: &str,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    // Only for a finding: every operand of a long run is checked, and most have none.
    let range = || span_to_range(source, span(node));
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
                range(),
            ));
            return;
        }
    }
    if want == Want::Ip && node.kind() == K::FIELD {
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
                range(),
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
            range(),
        ));
    }
}

/// Literal types the Verifier rejects in a function's arguments (errors: Elasticsearch's own
/// planner tests cover `between`, `cidrMatch`, `number`, and `stringContains`).
pub(crate) fn check_call_types(call: &ast::FunctionCall, source: &str, out: &mut Vec<Diagnostic>) {
    let name = function_name(call, source);
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
        let what = format!("the {} argument of `{display}`", ordinal(i));
        check_value(arg.syntax(), (want, Severity::Error), &what, source, out);
    }
}

/// The operands of one arithmetic level: numbers. The level below is a number or untyped, so
/// only the run's own operands are checked.
pub(crate) fn check_level_types(run: &Run, level: usize, source: &str, out: &mut Vec<Diagnostic>) {
    let operator = run.operator(level).map_or("", |o| o.text());
    let before = out.len();
    let (left, right) = run.sides(level);
    for side in [left, right] {
        if let Some(operand) = node_of(side) {
            let what = format!("an operand of `{operator}`");
            check_value(operand, OPERAND_NUMBER, &what, source, out);
        }
    }
    // `c-uri:"x"` reads as `c - (uri : "x")`: a field name with a hyphen needs backticks.
    if out.len() > before
        && operator == "-"
        && let Some(name) = hyphenated_name(run, level, source)
    {
        for d in &mut out[before..] {
            d.message.push_str(&format!(
                "; `{name}` reads as a subtraction, so quote a field name that contains `-` with backticks (`` `{name}` ``)"
            ));
        }
    }
}

/// Unary `+` is dropped by the builder; only `-` is typed.
pub(crate) fn check_unary_types(
    node: &ast::UnaryExpression,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if node.operator().is_some_and(|o| o.kind() == K::MINUS)
        && let Some(operand) = node.operand()
    {
        check_value(
            operand.syntax(),
            OPERAND_NUMBER,
            "the operand of unary `-`",
            source,
            out,
        );
    }
}

/// The literal types of a predicate's subject and patterns: `:`, `in~`, `like` and `regex`
/// take strings.
pub(crate) fn check_predicate_types(
    node: &ast::PredicateExpression,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let operator = node
        .operator()
        .map(|o| o.text().to_owned())
        .unwrap_or_default();
    let operator = operator.as_str();
    let mut exprs = node.exprs();
    let subject = exprs.next();
    let values: Vec<ast::Expr> = exprs.collect();
    // `in` checks exactness and list compatibility, not string types: mixing string and
    // number literals fails against any mapped field. An unmapped optional field (`?x`) is
    // null and passes.
    if operator == "in" {
        let has = |t: fn(Ty) -> bool| values.iter().any(|v| t(ty(v.syntax(), source)));
        let optional = subject
            .as_ref()
            .is_some_and(|s| text(s.syntax(), source).starts_with('?'));
        if has(|t| t == Ty::Str) && has(Ty::numeric) && !optional {
            out.push(diag(
                Severity::Error,
                codes::EQL_ARGUMENT_TYPE,
                "an `in` list mixes strings and numbers; Elasticsearch requires every value to match the field's type".into(),
                span_to_range(source, span(node.syntax())),
            ));
        }
        return;
    }
    if let Some(subject) = subject {
        let what = format!("the left side of `{operator}`");
        check_value(subject.syntax(), OPERAND_STRING, &what, source, out);
    }
    // `like` folds its patterns to text, so any constant is accepted.
    if operator.starts_with("like") {
        return;
    }
    for value in values {
        let what = format!("a pattern of `{operator}`");
        check_value(value.syntax(), OPERAND_STRING, &what, source, out);
    }
}

/// `eql_not_boolean`: a string or number literal where EQL needs a boolean (Elasticsearch
/// rejects it on every release: "Condition expression needs to be boolean").
fn not_boolean(child: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    let literal = strip_parens(child.clone());
    if matches!(literal.kind(), K::STRING | K::NUMBER) {
        let t = ty(&literal, source);
        out.push(diag(
            Severity::Error,
            codes::EQL_NOT_BOOLEAN,
            format!(
                "{} is not a condition: EQL needs a boolean here (a comparison, a predicate, `true` or `false`)",
                literal_desc(&literal, source, t)
            ),
            span_to_range(source, span(&literal)),
        ));
    }
}

/// The operands of one `and`/`or` level.
pub(crate) fn check_level_conditions(
    run: &Run,
    level: usize,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let (left, right) = run.sides(level);
    for side in [left, right] {
        if let Some(operand) = node_of(side) {
            not_boolean(operand, source, out);
        }
    }
}

/// The operand of `not`, or the condition of a `where`.
pub(crate) fn check_condition(
    condition: Option<ast::Expr>,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if let Some(condition) = condition {
        not_boolean(condition.syntax(), source, out);
    }
}

/// The answers of `translated_as_query`, kept so that a long chain or a deep nesting is not
/// climbed again for every comparison in it: a node's answer for its children (for a run, the
/// answer above it), and each `and`/`or` run's levels.
#[derive(Default)]
pub(crate) struct Translated {
    above: HashMap<SyntaxNode, bool>,
    runs: HashMap<SyntaxNode, (HashMap<SyntaxNode, usize>, Vec<bool>)>,
}

impl Translated {
    /// Whether `child` of `run` is folded away: from the first level that holds it outwards,
    /// some level has a `true` or `false` operand.
    fn folded(&mut self, run: &SyntaxNode, child: &SyntaxNode) -> bool {
        let (levels, folded) = self.runs.entry(run.clone()).or_insert_with(|| {
            let levels = Run::of(run);
            let mut folded = vec![false; levels.len()];
            let mut any = false;
            for level in (0..levels.len()).rev() {
                let (left, right) = levels.sides(level);
                any |= [left, right].into_iter().any(|side| {
                    node_of(side).is_some_and(|n| strip_parens(n.clone()).kind() == K::BOOLEAN)
                });
                folded[level] = any;
            }
            (levels.levels_of(), folded)
        });
        levels.get(child).is_some_and(|&level| folded[level])
    }
}

/// Whether `node` is a condition Elasticsearch translates to a query on its own: reached from
/// the event filter through `and`, `or`, `not`, and parentheses only. Comparisons elsewhere
/// (function arguments) run as scripts, which may compare fields. An `and`/`or` with a
/// `true`/`false` operand is folded away first, so those paths are skipped.
fn translated_as_query(node: &SyntaxNode, cache: &mut Translated) -> bool {
    let mut passed = Vec::new();
    let mut child = node.clone();
    let result = loop {
        let Some(parent) = child.parent() else {
            break false;
        };
        let run = matches!(parent.kind(), K::AND_EXPRESSION | K::OR_EXPRESSION);
        if run && cache.folded(&parent, &child) {
            break false;
        }
        if let Some(&known) = cache.above.get(&parent) {
            break known;
        }
        passed.push(parent.clone());
        match parent.kind() {
            K::PARENTHESIZED_EXPRESSION
            | K::NOT_EXPRESSION
            | K::AND_EXPRESSION
            | K::OR_EXPRESSION => child = parent,
            K::EVENT_QUERY | K::SUBQUERY => break true,
            _ => break false,
        }
    };
    for node in passed {
        cache.above.insert(node, result);
    }
    result
}

fn strip_parens(mut node: SyntaxNode) -> SyntaxNode {
    while node.kind() == K::PARENTHESIZED_EXPRESSION {
        match node.first_child() {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn field_comparison(
    (left, right): (&SyntaxNode, &SyntaxNode),
    operator: &str,
    at: ByteSpan,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let (l_req, l_opt) = field_refs(left);
    let (r_req, r_opt) = field_refs(right);
    if !(l_req || l_opt) || !(r_req || r_opt) {
        return;
    }
    let range = span_to_range(source, at);
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

/// A comparison whose both sides read fields fails when it is translated to a query.
pub(crate) fn check_comparison_fields(
    node: &ast::Comparison,
    translated: &mut Translated,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    if !translated_as_query(node.syntax(), translated) {
        return;
    }
    let (Some(left), Some(right)) = (node.left(), node.right()) else {
        return;
    };
    let operator = node
        .operator()
        .map(|o| o.text().to_owned())
        .unwrap_or_default();
    let operator = operator.as_str();
    let at = span(node.syntax());
    field_comparison((left.syntax(), right.syntax()), operator, at, source, out);
}

/// `in~` with a field on both sides fails when it is translated to a query, and an `in` list
/// must hold constants wherever it appears.
pub(crate) fn check_predicate_fields(
    node: &ast::PredicateExpression,
    translated: &mut Translated,
    source: &str,
    out: &mut Vec<Diagnostic>,
) {
    let operator = node
        .operator()
        .map(|o| o.text().to_owned())
        .unwrap_or_default();
    let operator = operator.as_str();
    let mut exprs = node.exprs();
    let subject = exprs.next();
    match operator {
        "in" => {
            for value in exprs {
                let (required, optional_only) = field_refs(value.syntax());
                if !(required || optional_only) {
                    continue;
                }
                let range = span_to_range(source, span(value.syntax()));
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
        "in~" if translated_as_query(node.syntax(), translated) => {
            let Some(subject) = subject else {
                return;
            };
            for value in exprs {
                let at = span(value.syntax());
                field_comparison((subject.syntax(), value.syntax()), "in~", at, source, out);
            }
        }
        _ => {}
    }
}
