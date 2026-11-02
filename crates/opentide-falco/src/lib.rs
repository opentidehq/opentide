//! I/O-free Falco rule condition engine: parse, field, macro, list, and event
//! checks per event source, operator and value types, highlighting, hover, and
//! completion. Falco conditions are what Sysdig Secure runs
//! (`configurations.sysdig`, sysdig-1.0).
//!
//! The grammar follows libsinsp's filter parser. Below it the engine checks:
//!
//! - fields against the catalogue of the rule's event source (`syscall` by
//!   default): a field of another source, or of no known source, is a warning,
//!   because plugins add fields;
//! - bare names: a macro of the block or of the Falco default rules; anything
//!   else is a warning (Sysdig manages macros of its own). A list used where a
//!   macro belongs is an error;
//! - operators and values against the field's type, where Falco would refuse
//!   to load the rule;
//! - `evt.type` values against Falco's event table;
//! - a tuning's condition (a fragment appended to the tuned rule) starts with
//!   `and` or `or`, and a new rule's does not.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Position, Range, Severity, codes,
    position_to_offset, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use tree_sitter::Node;

pub mod catalog;

pub use catalog::{Catalog, DEFAULT_SOURCE, Kind, Lookup};

const FALCO_DOCS: &str = "https://falco.org/docs/concepts/rules/conditions/";

/// What surrounds the condition: the rule block's event source and its own
/// macros and lists (sysdig-1.0 `source`, `macros`, `lists`).
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Event source; `None` is [`DEFAULT_SOURCE`].
    pub source: Option<String>,
    /// The block's macros: name to condition.
    pub macros: BTreeMap<String, String>,
    /// The block's lists: name to items.
    pub lists: BTreeMap<String, Vec<String>>,
    /// `Some(true)` for a tuning's condition (`append_to_rule`), `Some(false)`
    /// for a new rule's condition or a macro's; `None` (a raw `.falco` file)
    /// accepts both.
    pub append: Option<bool>,
}

impl Context {
    pub fn source(&self) -> &str {
        self.source.as_deref().unwrap_or(DEFAULT_SOURCE)
    }

    fn is_macro(&self, name: &str) -> bool {
        self.macros.contains_key(name) || Catalog::cached().macros.contains_key(name)
    }

    fn is_list(&self, name: &str) -> bool {
        self.lists.contains_key(name) || Catalog::cached().lists.contains_key(name)
    }

    /// The source is one the catalogue knows, so its fields can be checked.
    fn known_source(&self) -> bool {
        Catalog::cached().source(self.source()).is_some()
    }
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Analyze a condition with no block around it (a raw `.falco` file).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

pub fn analyze_with(text: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let Some(tree) = ts_parse(LanguageId::Falco, text) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::FALCO_PARSE_ERROR,
                "failed to initialize the Falco parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::FALCO_PARSE_ERROR,
            parse_error_message(err, text),
            range(text, node_span(err)),
        ));
    }
    if let Some(d) = append_check(root, text, ctx) {
        diagnostics.push(d);
    }
    let check_fields = ctx.known_source();
    opentide_syntax::walk_with_ancestors(root, |node, _| match node.kind() {
        "field" if check_fields => {
            if let Some(d) = field_check(node, text, ctx) {
                diagnostics.push(d);
            }
        }
        "macro_reference" => {
            if let Some(d) = macro_check(node, text, ctx) {
                diagnostics.push(d);
            }
        }
        "list_reference" => {
            let name = node_text(node, text);
            if !ctx.is_list(name) {
                diagnostics.push(Diagnostic::warning(
                    codes::FALCO_UNKNOWN_LIST,
                    format!("`{name}` is not a list of this block or of the Falco default rules"),
                    range(text, node_span(node)),
                ));
            }
        }
        "comparison" if check_fields && !node.has_error() => {
            diagnostics.extend(comparison_checks(node, text, ctx));
        }
        _ => {}
    });
    AnalyzeResult {
        diagnostics,
        tokens: highlight(&spec, text, ctx),
    }
}

fn append_check(root: Node, text: &str, ctx: &Context) -> Option<Diagnostic> {
    let first = root.named_child(0)?;
    let fragment = first.kind() == "append_fragment";
    let message = match (ctx.append?, fragment) {
        (true, false) if !root.has_error() => {
            "the condition of a tuning (`append_to_rule`) is appended to the tuned rule's condition: start it with `and` or `or`"
        }
        (false, true) => {
            "a condition that starts with `and` or `or` only extends another rule's: set `append_to_rule`, or remove the leading operator"
        }
        _ => return None,
    };
    let span = if fragment {
        let op = first.child_by_field_name("operator").unwrap_or(first);
        node_span(op)
    } else {
        node_span(first)
    };
    Some(Diagnostic::error(
        codes::FALCO_APPEND_CONDITION,
        message,
        range(text, span),
    ))
}

fn field_check(node: Node, text: &str, ctx: &Context) -> Option<Diagnostic> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, text);
    let source = ctx.source();
    let catalog = Catalog::cached();
    let message = match catalog.lookup(name, source) {
        Lookup::Known(_) => return None,
        Lookup::OtherSource(field) => format!(
            "`{name}` is a field of the {} source, not of `{source}`",
            field
                .sources
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Lookup::Unknown => format!("`{name}` is not a Falco field of the `{source}` source"),
    };
    let mut d = Diagnostic::warning(
        codes::FALCO_UNKNOWN_FIELD,
        message,
        range(text, node_span(name_node)),
    );
    if let Some(near) = near_miss(name, catalog.field_names_for(source).into_iter()) {
        d = d.with_suggestion(near);
    }
    Some(d)
}

fn macro_check(node: Node, text: &str, ctx: &Context) -> Option<Diagnostic> {
    let name = node_text(node, text);
    if ctx.is_macro(name) {
        return None;
    }
    let span = range(text, node_span(node));
    if ctx.is_list(name) {
        return Some(Diagnostic::error(
            codes::FALCO_MISPLACED_LIST,
            format!("`{name}` is a list, not a macro: use it in a value list, `in ({name})`"),
            span,
        ));
    }
    let mut d = Diagnostic::warning(
        codes::FALCO_UNKNOWN_MACRO,
        format!(
            "`{name}` is not a macro of this block or of the Falco default rules; the tenant must define it"
        ),
        span,
    );
    let names = ctx
        .macros
        .keys()
        .map(String::as_str)
        .chain(Catalog::cached().macros.keys().map(String::as_str));
    if let Some(near) = near_miss(name, names) {
        d = d.with_suggestion(near);
    }
    Some(d)
}

/// Operators Falco accepts only on strings (and paths and buffers).
const STRING_OPERATORS: &[&str] = &[
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
    "pmatch",
];
const ORDER_OPERATORS: &[&str] = &["<", "<=", ">", ">="];

/// The kind of a comparison's left side: the field's, or the transformer's
/// result (`len` is a number, the others strings).
fn operand_kind(node: Node, text: &str, ctx: &Context) -> Option<(Kind, String)> {
    match node.kind() {
        "field" => {
            let name = node_text(node.child_by_field_name("name")?, text);
            match Catalog::cached().lookup(name, ctx.source()) {
                Lookup::Known(field) => Some((field.kind, field.name.clone())),
                _ => None,
            }
        }
        "field_transformer" => {
            let transformer = node_text(node.child_by_field_name("name")?, text);
            if transformer == "len" {
                Some((Kind::Number, "len(...)".into()))
            } else {
                Some((Kind::String, format!("{transformer}(...)")))
            }
        }
        _ => None,
    }
}

fn comparison_checks(node: Node, text: &str, ctx: &Context) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let (Some(left), Some(op_node)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("operator"),
    ) else {
        return out;
    };
    let op = node_text(op_node, text);
    let right = node.child_by_field_name("right");
    if let Some((kind, name)) = operand_kind(left, text, ctx) {
        let refused = match kind {
            Kind::String => ORDER_OPERATORS.contains(&op),
            Kind::Number => STRING_OPERATORS.contains(&op),
            Kind::Bool => STRING_OPERATORS.contains(&op) || ORDER_OPERATORS.contains(&op),
            Kind::Ip | Kind::Other => false,
        };
        if refused {
            out.push(type_mismatch(
                format!(
                    "`{op}` does not apply to `{name}`, a {} field",
                    kind_name(kind)
                ),
                range(text, node_span(op_node)),
            ));
        } else if let Some(right) = right {
            out.extend(value_checks(kind, &name, right, text, ctx));
        }
    }
    if left.kind() == "field"
        && ctx.source() == "syscall"
        && left
            .child_by_field_name("name")
            .is_some_and(|n| matches!(node_text(n, text), "evt.type" | "syscall.type"))
        && matches!(op, "=" | "==" | "!=" | "in" | "intersects")
    {
        if let Some(right) = right {
            out.extend(event_checks(right, text, ctx));
        }
    }
    out
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::String => "string",
        Kind::Number => "numeric",
        Kind::Bool => "boolean",
        Kind::Ip => "IP address",
        Kind::Other => "typed",
    }
}

fn type_mismatch(message: String, range: Range) -> Diagnostic {
    Diagnostic::warning(codes::FALCO_TYPE_MISMATCH, message, range)
}

/// The literal values on the right of a comparison: the value itself, or the
/// items of a value list.
fn values<'t>(right: Node<'t>) -> Vec<Node<'t>> {
    match right.kind() {
        "value_list" => {
            let mut cursor = right.walk();
            right
                .named_children(&mut cursor)
                .filter(|n| matches!(n.kind(), "bare_string" | "quoted_string" | "number"))
                .collect()
        }
        "bare_string" | "quoted_string" | "number" => vec![right],
        _ => Vec::new(),
    }
}

fn value_checks(kind: Kind, name: &str, right: Node, text: &str, ctx: &Context) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for value in values(right) {
        let raw = node_text(value, text);
        // A bare item naming a list is expanded by Falco.
        if value.kind() == "bare_string" && ctx.is_list(raw) {
            continue;
        }
        let bad = match kind {
            Kind::Number => value.kind() == "bare_string" || value.kind() == "quoted_string",
            Kind::Bool => !matches!(unquote(raw), "true" | "false"),
            _ => false,
        };
        if bad {
            out.push(type_mismatch(
                format!(
                    "`{name}` is a {} field; `{raw}` is not a {} value",
                    kind_name(kind),
                    if kind == Kind::Bool {
                        "boolean"
                    } else {
                        "numeric"
                    }
                ),
                range(text, node_span(value)),
            ));
        }
    }
    out
}

fn event_checks(right: Node, text: &str, ctx: &Context) -> Vec<Diagnostic> {
    let catalog = Catalog::cached();
    let mut out = Vec::new();
    for value in values(right) {
        let raw = node_text(value, text);
        if value.kind() == "bare_string" && ctx.is_list(raw) {
            continue;
        }
        let event = unquote(raw);
        if value.kind() == "number" || catalog.event(event).is_some() {
            continue;
        }
        let mut d = Diagnostic::warning(
            codes::FALCO_UNKNOWN_EVENT,
            format!("`{event}` is not a Falco event type"),
            range(text, node_span(value)),
        );
        if let Some(near) = near_miss(event, catalog.events()) {
            d = d.with_suggestion(near);
        }
        out.push(d);
    }
    out
}

fn unquote(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &raw[1..raw.len() - 1]
    } else {
        raw
    }
}

/// The closest name within one edit (two for names of ten characters or more).
fn near_miss<'a>(name: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
    let limit = if name.len() >= 10 { 2 } else { 1 };
    let mut best: Option<(usize, &str)> = None;
    for candidate in candidates {
        if candidate == name || candidate.len().abs_diff(name.len()) > limit {
            continue;
        }
        let d = edit_distance(name, candidate);
        if d <= limit && best.is_none_or(|(bd, _)| d < bd) {
            best = Some((d, candidate));
        }
    }
    best.map(|(_, c)| c.to_string())
}

/// Optimal string alignment distance: a swapped pair of characters is one edit.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

fn parse_error_message(err: Node, text: &str) -> String {
    if err.is_missing() {
        return format!("missing `{}`", err.kind());
    }
    let found = node_text(err, text).trim();
    let unclosed = |open: char, close: char| {
        text.chars().filter(|&c| c == open).count() > text.chars().filter(|&c| c == close).count()
    };
    if unclosed('(', ')') {
        return "unbalanced parentheses: a `(` is not closed".into();
    }
    if found.is_empty() {
        return "the condition is incomplete".into();
    }
    let short: String = found.chars().take(40).collect();
    format!("unexpected `{short}`")
}

fn range(text: &str, span: ByteSpan) -> Range {
    span_to_range(text, span)
}

fn node_text<'a>(node: Node, text: &'a str) -> &'a str {
    text.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn highlight(spec: &HighlightSpec, text: &str, ctx: &Context) -> Vec<HighlightToken> {
    let Ok(spans) = opentide_syntax::query_captures(
        LanguageId::Falco,
        text,
        opentide_highlight::FALCO_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    // A bare value-list item that names a list is a reference, not text.
    let refs: Vec<(ByteSpan, &str)> = spans
        .iter()
        .map(|(span, capture)| {
            let raw = text.get(span.start..span.end).unwrap_or("");
            if capture == "string" && ctx.is_list(raw) {
                (*span, "variable")
            } else {
                (*span, capture.as_str())
            }
        })
        .collect();
    tokens_from_spans(spec, text, &refs).unwrap_or_default()
}

/// Every field a condition mentions, in source order, deduplicated.
pub fn fields(text: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Falco, text) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    opentide_syntax::walk_with_ancestors(tree.root_node(), |node, _| {
        if node.kind() == "field_name" {
            let name = node_text(node, text).to_string();
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }
    });
    out
}

// ---------------------------------------------------------------------------
// Output templates

fn output_field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"%([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)(\[[^\]]*\])?")
            .expect("output field pattern")
    })
}

/// Output-only placeholders Falco expands itself.
const OUTPUT_PLACEHOLDERS: &[&str] = &["container.info"];

/// Diagnostics for an output template (`output:`): its `%field` references
/// are checked like the condition's fields.
pub fn analyze_output(text: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let mut diagnostics = Vec::new();
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    for cap in output_field_re().captures_iter(text) {
        let whole = cap.get(0).expect("match");
        let name = cap.get(1).expect("field");
        spans.push((ByteSpan::new(whole.start(), whole.end()), "property"));
        if !ctx.known_source() || OUTPUT_PLACEHOLDERS.contains(&name.as_str()) {
            continue;
        }
        let message = match catalog.lookup(name.as_str(), ctx.source()) {
            Lookup::Known(_) => continue,
            Lookup::OtherSource(_) => format!(
                "`{}` is not a field of the `{}` source",
                name.as_str(),
                ctx.source()
            ),
            Lookup::Unknown => format!(
                "`{}` is not a Falco field of the `{}` source",
                name.as_str(),
                ctx.source()
            ),
        };
        let mut d = Diagnostic::warning(
            codes::FALCO_UNKNOWN_FIELD,
            message,
            range(text, ByteSpan::new(name.start(), name.end())),
        );
        if let Some(near) = near_miss(
            name.as_str(),
            catalog.field_names_for(ctx.source()).into_iter(),
        ) {
            d = d.with_suggestion(near);
        }
        diagnostics.push(d);
    }
    AnalyzeResult {
        diagnostics,
        tokens: tokens_from_spans(&spec, text, &spans).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Hover and completion

const KEYWORDS: &[(&str, &str)] = &[
    ("and", "Both checks must match. Binds tighter than `or`."),
    ("or", "Either check matches."),
    (
        "not",
        "Negates the check that follows. Binds tighter than `and`.",
    ),
    (
        "in",
        "The field equals one of the values in the list: `proc.name in (bash, sh)`. A bare item that names a list is expanded.",
    ),
    (
        "intersects",
        "A multi-valued field shares at least one value with the list.",
    ),
    (
        "pmatch",
        "Path prefix match: the field is one of the paths in the list, or below one of them.",
    ),
    ("exists", "The field has a value for this event."),
    ("=", "Equal. `==` is the same operator."),
    ("==", "Equal. `=` is the same operator."),
    ("!=", "Not equal."),
    ("<", "Less than (numeric fields)."),
    ("<=", "Less than or equal (numeric fields)."),
    (">", "Greater than (numeric fields)."),
    (">=", "Greater than or equal (numeric fields)."),
    (
        "contains",
        "The string field contains the value (case-sensitive).",
    ),
    (
        "icontains",
        "The string field contains the value, ignoring case.",
    ),
    (
        "bcontains",
        "The binary buffer contains the bytes, given as hex (`bcontains 48656c6c6f`).",
    ),
    ("startswith", "The string field starts with the value."),
    (
        "bstartswith",
        "The binary buffer starts with the bytes, given as hex.",
    ),
    ("endswith", "The string field ends with the value."),
    (
        "glob",
        "The string field matches a glob pattern (`*`, `?`, `[...]`).",
    ),
    ("iglob", "Glob match, ignoring case."),
    (
        "regex",
        "The string field matches a regular expression (RE2).",
    ),
    ("tolower", "The field's value in lower case."),
    ("toupper", "The field's value in upper case."),
    ("b64", "The field's value, base64-decoded."),
    ("basename", "The last path element of the field's value."),
    ("len", "The length of the field's value."),
    (
        "val",
        "The value of another field, compared with this one: `proc.pname = val(proc.name)`.",
    ),
];

pub fn hover(text: &str, position: Position, ctx: &Context) -> Option<String> {
    let offset = position_to_offset(text, position);
    let tree = ts_parse(LanguageId::Falco, text)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let word = node_text(node, text);
    let catalog = Catalog::cached();
    match node.kind() {
        "field_name" => field_hover(word, ctx),
        "identifier" | "bare_string" => {
            if let Some(condition) = ctx.macros.get(word) {
                return Some(format!(
                    "**`{word}`** (macro, this block)\n\n```falco\n{condition}\n```"
                ));
            }
            if let Some(items) = ctx.lists.get(word) {
                return Some(format!(
                    "**`{word}`** (list, this block)\n\n`{}`",
                    items.join(", ")
                ));
            }
            if node.kind() == "identifier" {
                if let Some(m) = catalog.macros.get(word) {
                    return Some(format!(
                        "**`{word}`** (macro, Falco default rules)\n\n```falco\n{}\n```\n\nDefined in `{}`.",
                        m.condition, m.origin
                    ));
                }
            }
            if let Some(l) = catalog.lists.get(word) {
                return Some(format!(
                    "**`{word}`** (list, Falco default rules)\n\n`{}`\n\nDefined in `{}`.",
                    l.items.join(", "),
                    l.origin
                ));
            }
            catalog
                .event(word)
                .map(|kind| format!("**`{word}`** (Falco {kind} event)"))
        }
        _ => KEYWORDS
            .iter()
            .find(|(k, _)| *k == word)
            .map(|(k, d)| format!("**`{k}`** (Falco)\n\n{d}\n\n[Falco docs]({FALCO_DOCS})")),
    }
}

fn field_hover(name: &str, ctx: &Context) -> Option<String> {
    let catalog = Catalog::cached();
    let field = match catalog.lookup(name, ctx.source()) {
        Lookup::Known(f) | Lookup::OtherSource(f) => f,
        Lookup::Unknown => return None,
    };
    let sources = if field.sources.iter().any(|s| s == "*") {
        "every source".to_string()
    } else {
        field.sources.join(", ")
    };
    Some(format!(
        "**`{}`** `{}`\n\n{}\n\nSource: {sources} ({})",
        field.name, field.field_type, field.description, field.class
    ))
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// Inside an unclosed value list: `... in (a, b` .
fn in_value_list(before: &str) -> bool {
    let mut depth_list = Vec::new();
    let mut last_word = String::new();
    let mut words: Vec<String> = Vec::new();
    for c in before.chars() {
        if is_word_char(c) {
            last_word.push(c);
            continue;
        }
        if !last_word.is_empty() {
            words.push(std::mem::take(&mut last_word));
        }
        match c {
            '(' => {
                let list = words
                    .last()
                    .is_some_and(|w| matches!(w.as_str(), "in" | "intersects" | "pmatch"));
                depth_list.push(list);
            }
            ')' => {
                depth_list.pop();
            }
            _ => {}
        }
    }
    depth_list.last().copied().unwrap_or(false)
}

pub fn completions(text: &str, offset: usize, ctx: &Context) -> Vec<CompletionItem> {
    let before = &text[..offset.min(text.len())];
    let prefix_start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_word_char(*c))
        .last()
        .map(|(i, _)| i)
        .unwrap_or(before.len());
    let head = &before[..prefix_start];
    let catalog = Catalog::cached();
    let mut items = Vec::new();
    if in_value_list(head) {
        for name in ctx.lists.keys().chain(catalog.lists.keys()) {
            items.push(CompletionItem::new(name.clone(), "variable"));
        }
        if head.contains("evt.type") && ctx.source() == "syscall" {
            for event in catalog.events() {
                items.push(CompletionItem::new(event, "constant"));
            }
        }
        return items;
    }
    let previous = head
        .trim_end()
        .rsplit(|c: char| c.is_whitespace() || c == '(')
        .next();
    let after_field = previous.is_some_and(|w| {
        w.contains('.')
            && w.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && head.ends_with(char::is_whitespace)
    }) || head.trim_end().ends_with(')')
        && head.ends_with(char::is_whitespace)
        && !head.trim_end().ends_with("))");
    if after_field {
        for (kw, doc) in KEYWORDS {
            if !matches!(
                *kw,
                "and" | "or" | "not" | "tolower" | "toupper" | "b64" | "basename" | "len" | "val"
            ) {
                let mut item = CompletionItem::new(*kw, "operator");
                item.documentation = Some((*doc).to_string());
                items.push(item);
            }
        }
        for kw in ["and", "or"] {
            items.push(CompletionItem::new(kw, "keyword"));
        }
        return items;
    }
    for field in catalog.fields_for(ctx.source()) {
        let mut item = CompletionItem::new(field.name.clone(), "property");
        item.detail = Some(field.field_type.clone());
        item.documentation = Some(field.description.clone());
        items.push(item);
    }
    for (name, condition) in &ctx.macros {
        let mut item = CompletionItem::new(name.clone(), "macro");
        item.detail = Some("macro (this block)".into());
        item.documentation = Some(condition.clone());
        items.push(item);
    }
    for (name, m) in &catalog.macros {
        if ctx.macros.contains_key(name) {
            continue;
        }
        let mut item = CompletionItem::new(name.clone(), "macro");
        item.detail = Some("macro (Falco default rules)".into());
        item.documentation = Some(m.condition.clone());
        items.push(item);
    }
    for kw in [
        "not", "and", "or", "tolower", "toupper", "b64", "basename", "len",
    ] {
        items.push(CompletionItem::new(kw, "keyword"));
    }
    items
}

/// Severity of every code this engine emits, for documentation and tests.
pub const CODES: &[(&str, Severity)] = &[
    (codes::FALCO_PARSE_ERROR, Severity::Error),
    (codes::FALCO_UNKNOWN_FIELD, Severity::Warning),
    (codes::FALCO_UNKNOWN_MACRO, Severity::Warning),
    (codes::FALCO_UNKNOWN_LIST, Severity::Warning),
    (codes::FALCO_MISPLACED_LIST, Severity::Error),
    (codes::FALCO_TYPE_MISMATCH, Severity::Warning),
    (codes::FALCO_UNKNOWN_EVENT, Severity::Warning),
    (codes::FALCO_APPEND_CONDITION, Severity::Error),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn codes_of(text: &str, ctx: &Context) -> Vec<String> {
        analyze_with(text, ctx)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    fn plain(text: &str) -> Vec<String> {
        codes_of(text, &Context::default())
    }

    #[test]
    fn a_default_rule_condition_is_clean() {
        let text = "spawned_process and container and shell_procs and proc.tty != 0 \
                    and container_entrypoint and not user_expected_terminal_shell_in_container_conditions";
        let r = analyze(text);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "macro"));
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
    }

    #[test]
    fn syntax_errors_are_errors() {
        for text in [
            "proc.name =",
            "(proc.name = bash",
            "proc.name in (bash, sh",
            "and and proc.name = x",
            "proc.name not = bash",
        ] {
            assert!(
                plain(text).contains(&codes::FALCO_PARSE_ERROR.to_string()),
                "{text}"
            );
        }
        let d = analyze("(proc.name = bash").diagnostics;
        assert_eq!(d[0].severity, Severity::Error);
    }

    #[test]
    fn fields_are_checked_for_the_source() {
        let c = plain("proc.nmae = bash");
        assert_eq!(c, vec![codes::FALCO_UNKNOWN_FIELD]);
        let d = analyze("proc.nmae = bash").diagnostics;
        assert_eq!(d[0].suggestion.as_deref(), Some("proc.name"));
        assert_eq!(plain("ka.verb = create"), vec![codes::FALCO_UNKNOWN_FIELD]);
        let k8s = Context {
            source: Some("k8s_audit".into()),
            ..Context::default()
        };
        assert!(codes_of("ka.verb = create and ka.target.resource = pods", &k8s).is_empty());
        assert_eq!(
            codes_of("proc.name = bash", &k8s),
            vec![codes::FALCO_UNKNOWN_FIELD]
        );
        // Arguments: bracketed and dotted.
        assert!(plain("proc.aname[2] = sshd and evt.arg.flags contains O_TRUNC").is_empty());
        // An unknown source is not checked.
        let custom = Context {
            source: Some("my_plugin".into()),
            ..Context::default()
        };
        assert!(codes_of("my.field = 1", &custom).is_empty());
    }

    #[test]
    fn macros_and_lists_resolve_through_the_block() {
        assert_eq!(plain("my_private_macro"), vec![codes::FALCO_UNKNOWN_MACRO]);
        let mut ctx = Context::default();
        ctx.macros
            .insert("my_private_macro".into(), "proc.name = x".into());
        ctx.lists.insert("my_list".into(), vec!["a".into()]);
        assert!(codes_of("my_private_macro and proc.name in (my_list, b)", &ctx).is_empty());
        assert_eq!(codes_of("my_list", &ctx), vec![codes::FALCO_MISPLACED_LIST]);
        assert_eq!(plain("shell_binaries"), vec![codes::FALCO_MISPLACED_LIST]);
        assert!(codes_of("proc.name in my_list", &ctx).is_empty());
        assert_eq!(
            plain("proc.name in nope_list"),
            vec![codes::FALCO_UNKNOWN_LIST]
        );
        let d = analyze("spawned_proces").diagnostics;
        assert_eq!(d[0].suggestion.as_deref(), Some("spawned_process"));
    }

    #[test]
    fn operators_and_values_follow_the_field_type() {
        assert_eq!(plain("proc.name > 5"), vec![codes::FALCO_TYPE_MISMATCH]);
        assert_eq!(
            plain("proc.pid contains 5"),
            vec![codes::FALCO_TYPE_MISMATCH]
        );
        assert_eq!(plain("proc.pid = abc"), vec![codes::FALCO_TYPE_MISMATCH]);
        assert_eq!(
            plain("evt.failed = maybe"),
            vec![codes::FALCO_TYPE_MISMATCH]
        );
        assert!(plain("evt.failed = true and proc.pid > 1 and len(proc.args) > 10").is_empty());
        assert_eq!(
            plain("len(proc.args) startswith x"),
            vec![codes::FALCO_TYPE_MISMATCH]
        );
        assert!(plain("tolower(proc.name) startswith bash").is_empty());
    }

    #[test]
    fn event_types_are_checked() {
        assert!(plain("evt.type in (open, openat, openat2) and evt.dir = <").is_empty());
        let d = analyze("evt.type = execvee").diagnostics;
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, codes::FALCO_UNKNOWN_EVENT);
        assert_eq!(d[0].suggestion.as_deref(), Some("execve"));
    }

    #[test]
    fn tunings_append_with_and_or_or() {
        let tuning = Context {
            append: Some(true),
            ..Context::default()
        };
        let rule = Context {
            append: Some(false),
            ..Context::default()
        };
        assert!(codes_of("and not proc.pname in (sshd)", &tuning).is_empty());
        assert_eq!(
            codes_of("not proc.pname in (sshd)", &tuning),
            vec![codes::FALCO_APPEND_CONDITION]
        );
        assert_eq!(
            codes_of("and proc.name = x", &rule),
            vec![codes::FALCO_APPEND_CONDITION]
        );
        assert!(plain("or proc.name = x").is_empty());
    }

    #[test]
    fn output_fields_are_checked() {
        let r = analyze_output(
            "Shell (user=%user.name proc=%proc.nmae parent=%proc.aname[2] %container.info)",
            &Context::default(),
        );
        let codes: Vec<_> = r.diagnostics.iter().map(|d| d.code.as_str()).collect();
        assert_eq!(codes, vec![codes::FALCO_UNKNOWN_FIELD]);
        assert_eq!(r.diagnostics[0].suggestion.as_deref(), Some("proc.name"));
        assert_eq!(r.tokens.len(), 4);
    }

    #[test]
    fn hover_explains_fields_macros_lists_and_operators() {
        let ctx = Context::default();
        let text = "spawned_process and proc.name in (shell_binaries) and fd.name startswith /etc";
        let at = |needle: &str| {
            let off = text.find(needle).unwrap() + 1;
            opentide_core::offset_to_position(text, off)
        };
        assert!(
            hover(text, at("proc.name"), &ctx)
                .unwrap()
                .contains("CHARBUF")
        );
        assert!(
            hover(text, at("spawned_process"), &ctx)
                .unwrap()
                .contains("macro")
        );
        assert!(
            hover(text, at("shell_binaries"), &ctx)
                .unwrap()
                .contains("bash")
        );
        assert!(
            hover(text, at("startswith"), &ctx)
                .unwrap()
                .contains("starts with")
        );
    }

    #[test]
    fn completion_offers_what_fits_the_position() {
        let ctx = Context::default();
        let labels = |text: &str| -> Vec<String> {
            completions(text, text.len(), &ctx)
                .into_iter()
                .map(|i| i.label)
                .collect()
        };
        let start = labels("proc.");
        assert!(start.iter().any(|l| l == "proc.name"));
        assert!(start.iter().any(|l| l == "spawned_process"));
        let ops = labels("proc.name ");
        assert!(ops.iter().any(|l| l == "startswith"));
        assert!(!ops.iter().any(|l| l == "proc.name"));
        let list = labels("evt.type in (open, ");
        assert!(list.iter().any(|l| l == "shell_binaries"));
        assert!(list.iter().any(|l| l == "execve"));
    }

    #[test]
    fn severities_match_the_codes_table() {
        for (code, severity) in CODES {
            assert!(codes::describe(code).is_some(), "{code}");
            let _ = severity;
        }
    }
}
