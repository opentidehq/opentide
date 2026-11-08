//! I/O-free Falco rule condition engine: parse, compile-time checks, Falco's
//! rule-loader checks, highlighting, hover, and completion. Falco conditions
//! are what Sysdig Secure runs (`configurations.sysdig`, sysdig-1.0).
//!
//! The verdicts follow the sources Falco itself runs, not documentation:
//!
//! - [`parser`] is a port of libsinsp's filter parser, step for step; libs' own
//!   parser tests (`crates/testdata/conformance/libsinsp/parser.json`) all agree;
//! - [`compile`] is what libsinsp's filter compiler checks next: field
//!   resolution and arguments, operator and type, values, transformers,
//!   right-hand side fields, compile warnings; libs' compiler tests
//!   (`compiler.json`) agree;
//! - this module adds Falco's rule loader: lists are expanded as text before
//!   the parse (`resolve_list`), macros resolve by name, a tuning's condition
//!   is appended to the tuned rule's, deprecated fields and `<NA>` checks warn,
//!   and a syscall rule whose event types cannot be narrowed warns
//!   (`LOAD_NO_EVTTYPE`, as Sysdig's backend does).
//!
//! What depends on the agent (fields and macros the catalogue does not know)
//! is a warning; what Falco refuses to load is an error. See `docs/engine/FALCO.md`.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Range, Severity, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::parse as ts_parse;
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

pub mod catalog;
pub mod compile;
pub mod exceptions;
pub mod parser;

pub use catalog::{Catalog, DEFAULT_SOURCE, Field, Kind, Lookup};

/// The operators a modifier (`oneof`, `anyof`, `allof`) can follow: Falco's
/// `cmpop_supports_modifier`.
const MODIFIABLE: &[&str] = &[
    "=",
    "==",
    "!=",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
];

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
    /// A macro's condition (`macros[].condition`): Falco checks event types on
    /// rules only.
    pub macro_condition: bool,
    /// The rule a tuning extends (`append_to_rule`). When it is a Falco default
    /// rule, the tuning's event types are judged on the combined condition.
    pub tuned_rule: Option<String>,
    /// The block's list names in block order (Falco's load order for them).
    /// Empty: `lists` in name order.
    pub list_order: Vec<String>,
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

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_with(text: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    AnalyzeResult {
        diagnostics: condition_diagnostics(text, ctx),
        tokens: highlight(&spec, text, ctx),
    }
}

/// The placeholder for the tuned rule's condition a tuning is appended to.
const TUNED: &str = "tuned_rule_condition";

/// Text after Falco's list expansion, with every byte's offset in the text
/// before it (`map`) and the end of the source a byte stands for (`map_end`).
pub(crate) struct Expanded {
    pub(crate) text: String,
    map: Vec<usize>,
    map_end: Vec<usize>,
}

impl Expanded {
    fn new(text: &str) -> Self {
        Expanded {
            text: text.to_string(),
            map: (0..text.len()).collect(),
            map_end: (1..=text.len()).collect(),
        }
    }

    /// The span of the original text a span of this one stands for.
    fn original(&self, span: parser::Span) -> (usize, usize) {
        let len = self.text.len();
        let at = |i: usize| {
            if i < len {
                self.map[i]
            } else {
                self.map.last().map_or(0, |m| m + 1)
            }
        };
        let start = at(span.start.min(len));
        let end = if span.end > span.start && span.end <= len {
            self.map_end[span.end - 1]
        } else {
            start
        };
        (start, end.max(start))
    }
}

/// Falco's `quote_item`.
pub(crate) fn quote_item(item: &str) -> String {
    if item.contains(' ') && !item.starts_with('"') && !item.starts_with('\'') {
        format!("\"{item}\"")
    } else {
        item.to_string()
    }
}

/// Falco's `resolve_list` (`rule_loader_compiler.cpp`): every occurrence of
/// the list's name between delimiters becomes its items, quoted, comma-joined.
fn resolve_list(t: &mut Expanded, name: &str, items: &[String]) {
    const BLANKS: &[u8] = b" \t\n\r";
    const DELIMS: &[u8] = b" \t\n\r(),=";
    if name.is_empty() {
        return;
    }
    let mut start = t.text.find(name);
    while let Some(found) = start {
        let mut s = found;
        let mut e = s + name.len();
        let b = t.text.as_bytes();
        let mut next = found + 1;
        if (s == 0 || DELIMS.contains(&b[s - 1])) && (e >= b.len() || DELIMS.contains(&b[e])) {
            let origin = (t.map[s], t.map_end[e - 1]);
            while s > 0 && BLANKS.contains(&b[s - 1]) {
                s -= 1;
            }
            while e < b.len() && BLANKS.contains(&b[e]) {
                e += 1;
            }
            let sub = items
                .iter()
                .map(|i| quote_item(i))
                .collect::<Vec<_>>()
                .join(", ");
            if sub.is_empty() {
                if s > 0 && b[s - 1] == b',' {
                    s -= 1;
                } else if e < b.len() && b[e] == b',' {
                    e += 1;
                }
            }
            let mut text = String::new();
            let mut map = Vec::new();
            let mut map_end = Vec::new();
            text.push_str(&t.text[..s]);
            map.extend_from_slice(&t.map[..s]);
            map_end.extend_from_slice(&t.map_end[..s]);
            if s > 0 {
                text.push(' ');
                map.push(origin.0);
                map_end.push(origin.0);
            }
            let inserted = sub.len() + 1;
            text.push_str(&sub);
            text.push(' ');
            map.extend(std::iter::repeat_n(origin.0, inserted));
            map_end.extend(std::iter::repeat_n(origin.1, inserted));
            text.push_str(&t.text[e..]);
            map.extend_from_slice(&t.map[e..]);
            map_end.extend_from_slice(&t.map_end[e..]);
            t.text = text;
            t.map = map;
            t.map_end = map_end;
            // libs: `start += sub.length() + 1`, then searches from `start + 1`.
            next = s + sub.len() + 1 + 1;
        }
        start = t
            .text
            .get(next..)
            .and_then(|rest| rest.find(name))
            .map(|i| i + next);
    }
}

/// The lists Falco would expand, items expanded through other lists, the
/// block's after the default rules' (a later definition replaces).
fn lists_in_order(ctx: &Context) -> Vec<(String, Vec<String>)> {
    // Falco's rule loader (`compile_list_infos`, then `resolve_list` in load
    // order): the default lists in their load order, then the block's in block
    // order (a block list of a default's name replaces it in place). An item
    // names a list only when that list is loaded before it; otherwise it stays
    // a literal item, so a list naming itself or a later list keeps the name.
    let catalog = Catalog::cached();
    let block_order: Vec<String> = if ctx.list_order.is_empty() {
        ctx.lists.keys().cloned().collect()
    } else {
        ctx.list_order
            .iter()
            .filter(|n| ctx.lists.contains_key(*n))
            .cloned()
            .collect()
    };
    let mut order: Vec<String> = catalog.list_order.clone();
    for name in &block_order {
        if !order.contains(name) {
            order.push(name.clone());
        }
    }
    let raw = |name: &str| -> Vec<String> {
        ctx.lists
            .get(name)
            .cloned()
            .or_else(|| catalog.lists.get(name).map(|l| l.items.clone()))
            .unwrap_or_default()
    };
    let mut flat: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for name in order {
        let mut items = Vec::new();
        for item in raw(&name) {
            match flat.get(&item) {
                Some(earlier) => items.extend(earlier.iter().cloned()),
                None => items.push(item),
            }
        }
        flat.insert(name.clone(), items.clone());
        out.push((name, items));
    }
    out
}

pub(crate) fn expand_lists(text: &str, ctx: &Context) -> Expanded {
    let mut t = Expanded::new(text);
    for (name, items) in lists_in_order(ctx) {
        if t.text.contains(name.as_str()) {
            resolve_list(&mut t, &name, &items);
        }
    }
    t
}

/// Length of a leading `and` / `or` (after blanks) that a tuning starts with.
fn leading_bool_op(text: &str) -> Option<(usize, usize)> {
    let start = text.len() - text.trim_start().len();
    let rest = &text[start..];
    for kw in ["and", "or"] {
        if let Some(after) = rest.strip_prefix(kw)
            && after.starts_with([' ', '\t', '\n', '\r', '('])
        {
            return Some((start, start + kw.len()));
        }
    }
    None
}

fn condition_diagnostics(text: &str, ctx: &Context) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if text.trim().is_empty() {
        // Falco's rules schema: "Value must be non-empty".
        out.push(Diagnostic::error(
            codes::FALCO_PARSE_ERROR,
            "the condition is empty: Falco requires a non-empty condition (Value must be non-empty)",
            range(text, ByteSpan::new(0, text.len())),
        ));
        return out;
    }
    let lead = leading_bool_op(text);
    match (ctx.append, lead) {
        (Some(true), None) => out.push(Diagnostic::error(
            codes::FALCO_APPEND_CONDITION,
            "the condition of a tuning (`append_to_rule`) is appended to the tuned rule's condition: start it with `and` or `or`",
            range(text, ByteSpan::new(text.len() - text.trim_start().len(), text.trim_end().len())),
        )),
        (Some(false), Some((s, e))) => {
            out.push(Diagnostic::error(
                codes::FALCO_APPEND_CONDITION,
                "a condition that starts with `and` or `or` only extends another rule's: set `append_to_rule`, or remove the leading operator",
                range(text, ByteSpan::new(s, e)),
            ));
            return out;
        }
        _ => {}
    }
    // Falco appends a tuning's condition to the tuned rule's: `<rule> <text>`.
    let prefix = if lead.is_some() {
        format!("{TUNED} ")
    } else {
        String::new()
    };
    let full = format!("{prefix}{text}");
    let to_text = |(s, e): (usize, usize)| {
        let p = prefix.len();
        ByteSpan::new(
            s.saturating_sub(p).min(text.len()),
            e.saturating_sub(p).min(text.len()),
        )
    };

    if let Some(misplaced) = misplaced_lists(&full, ctx) {
        for (span, message) in misplaced {
            out.push(Diagnostic::error(
                codes::FALCO_MISPLACED_LIST,
                message,
                range(text, to_text((span.start, span.end))),
            ));
        }
        return out;
    }

    let expanded = expand_lists(&full, ctx);
    let ast = match parser::parse(&expanded.text) {
        Ok(ast) => ast,
        Err(e) => {
            let at = expanded.original(parser::Span {
                start: e.offset,
                end: e.offset + 1,
            });
            let span = to_text(at);
            let span = if span.start == span.end && span.start > 0 && span.start >= text.len() {
                ByteSpan::new(text.len().saturating_sub(1), text.len())
            } else {
                span
            };
            out.push(Diagnostic::error(
                codes::FALCO_PARSE_ERROR,
                format!("{} (libsinsp)", e.message),
                range(text, span),
            ));
            return out;
        }
    };

    let catalog = Catalog::cached();
    let mut compiler = compile::Compiler::new(catalog, ctx.source());
    compiler.condition(&ast);
    for f in compiler.findings {
        let mut d = match f.level {
            compile::Level::Error => Diagnostic::error(f.code, f.message, Range::point(0, 0)),
            compile::Level::Warning => Diagnostic::warning(f.code, f.message, Range::point(0, 0)),
        };
        d.range = range(text, to_text(expanded.original(f.span)));
        if let Some(s) = f.suggestion {
            d = d.with_suggestion(s);
        }
        out.push(d);
    }

    let mut identifiers = Vec::new();
    collect_identifiers(&ast, &mut identifiers);
    for (name, span) in identifiers {
        if name == TUNED && lead.is_some() {
            continue;
        }
        if !ctx.is_macro(&name) {
            let mut d = Diagnostic::warning(
                codes::FALCO_UNKNOWN_MACRO,
                format!(
                    "`{name}` is not a macro of this block or of the Falco default rules; the tenant must define it"
                ),
                range(text, to_text(expanded.original(span))),
            );
            let names = ctx
                .macros
                .keys()
                .map(String::as_str)
                .chain(catalog.macros.keys().map(String::as_str));
            if let Some(near) = near_miss(&name, names) {
                d = d.with_suggestion(near);
            }
            out.push(d);
        }
    }

    // Judged on the text before expansion: after it, a known list is gone.
    let mut list_values = Vec::new();
    if let Ok(original) = parser::parse(&full) {
        collect_list_identifiers(&original, &mut list_values);
    }
    for (name, span) in list_values {
        if ctx.is_list(&name) {
            continue;
        }
        out.push(Diagnostic::warning(
            codes::FALCO_UNKNOWN_LIST,
            format!(
                "`{name}` is not a list of this block or of the Falco default rules: it is compared as the single value '{name}'"
            ),
            range(text, to_text((span.start, span.end))),
        ));
    }

    let mut newer = Vec::new();
    compile::newer_syntax(&ast, &mut newer);
    for (span, message) in newer {
        out.push(Diagnostic::warning(
            codes::FALCO_NEWER_SYNTAX,
            message,
            range(text, to_text(expanded.original(span))),
        ));
    }

    let mut na = Vec::new();
    compile::unsafe_na_checks(&ast, &mut na);
    for span in na {
        out.push(Diagnostic::warning(
            codes::FALCO_UNSAFE_NA_CHECK,
            "comparing a `ka.` or `jevt.` field with `<NA>`: such a field may hold the string `<NA>`, so the check does not tell a missing value apart",
            range(text, to_text(expanded.original(span))),
        ));
    }

    // Falco judges a tuning's event types on the tuned rule's condition with
    // the tuning's text appended (`<rule condition> <text>`).
    let tuned = if lead.is_some() {
        ctx.tuned_rule
            .as_deref()
            .and_then(|name| catalog.rules.get(name))
            .filter(|rule| rule.source == ctx.source())
            .and_then(|rule| {
                let combined = format!("{} {text}", rule.condition);
                parser::parse(&expand_lists(&combined, ctx).text).ok()
            })
    } else {
        None
    };
    let judged = if lead.is_none() {
        Some(&ast)
    } else {
        tuned.as_ref()
    };
    if ctx.source() == "syscall"
        && !ctx.macro_condition
        && let Some(judged) = judged
        && !out.iter().any(|d| d.severity == Severity::Error)
    {
        let mut resolver = EventCodes::new(ctx);
        if let Some(codes_) = resolver.codes(judged, false, 0)
            && codes_.len() > 100
        {
            out.push(Diagnostic::warning(
                codes::FALCO_NO_EVTTYPE,
                format!(
                    "the rule matches {} event types: narrow it with `evt.type` (a macro such as `spawned_process` or `open_write`). Falco and Sysdig warn: this has a significant performance penalty",
                    codes_.len()
                ),
                range(text, ByteSpan::new(0, text.trim_end().len().min(text.len()))),
            ));
        }
    }
    out
}

/// Lists used where Falco's text expansion breaks the condition: as a macro,
/// as the value of a scalar operator, or after a list operator without
/// parentheses. `None` when the text does not parse unexpanded.
fn misplaced_lists(full: &str, ctx: &Context) -> Option<Vec<(parser::Span, String)>> {
    let ast = parser::parse(full).ok()?;
    let mut out = Vec::new();
    fn walk(e: &parser::Expr, ctx: &Context, out: &mut Vec<(parser::Span, String)>) {
        use parser::Expr;
        match e {
            Expr::And(c, _) | Expr::Or(c, _) => c.iter().for_each(|x| walk(x, ctx, out)),
            Expr::Not(c, _) => walk(c, ctx, out),
            Expr::Identifier(name, span) if ctx.is_list(name) && !ctx.is_macro(name) => out.push((
                *span,
                format!("`{name}` is a list, not a macro: use it in a value list, `in ({name})`"),
            )),
            Expr::Binary { right, .. } => {
                // A one-item list expands into a single value, which parses.
                if let Expr::Value(v, span) = &**right
                    && ctx.is_list(v)
                    && list_len(ctx, v) != 1
                {
                    out.push((
                        *span,
                        format!(
                            "`{v}` is a list: Falco expands it here into its comma-separated items, which a single value cannot hold; write `in ({v})`"
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    walk(&ast, ctx, &mut out);
    (!out.is_empty()).then_some(out)
}

fn list_len(ctx: &Context, name: &str) -> usize {
    lists_in_order(ctx)
        .into_iter()
        .find(|(n, _)| n == name)
        .map_or(0, |(_, items)| items.len())
}

/// The bare names in check positions of *text* (the macros it uses), after the
/// context's lists are expanded as Falco does. `None` when it does not parse.
pub fn check_position_names(text: &str, ctx: &Context) -> Option<Vec<String>> {
    let expanded = expand_lists(text, ctx);
    let ast = parser::parse(&expanded.text).ok()?;
    let mut out = Vec::new();
    collect_identifiers(&ast, &mut out);
    Some(out.into_iter().map(|(name, _)| name).collect())
}

/// Whether *name* occurs in *text* with a `resolve_list` delimiter (the text's
/// start or end, a blank, `(`, `)`, `,`, or `=`) on each side.
pub fn occurs_delimited(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let delim = |c: Option<char>| c.is_none_or(|c| " \t\n\r(),=".contains(c));
    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        if delim(text[..start].chars().next_back()) && delim(text[end..].chars().next()) {
            return true;
        }
        from = start + 1;
        while !text.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

fn collect_identifiers(e: &parser::Expr, out: &mut Vec<(String, parser::Span)>) {
    use parser::Expr;
    match e {
        Expr::And(c, _) | Expr::Or(c, _) => c.iter().for_each(|x| collect_identifiers(x, out)),
        Expr::Not(c, _) => collect_identifiers(c, out),
        Expr::Identifier(name, span) => out.push((name.clone(), *span)),
        _ => {}
    }
}

/// A list operator's right side that is a bare name (no parentheses): after
/// list expansion it is not a known list, so libsinsp compares the name itself.
fn collect_list_identifiers(e: &parser::Expr, out: &mut Vec<(String, parser::Span)>) {
    use parser::Expr;
    match e {
        Expr::And(c, _) | Expr::Or(c, _) => c.iter().for_each(|x| collect_list_identifiers(x, out)),
        Expr::Not(c, _) => collect_list_identifiers(c, out),
        Expr::Binary { op, right, .. } => {
            let list_op = parser::LIST_OPERATORS.contains(&op.as_str()) || op.contains(' ');
            if list_op && let Expr::Value(v, span) = &**right {
                out.push((v.clone(), *span));
            }
        }
        _ => {}
    }
}

/// libsinsp's `ppm_event_codes` (`filter/ppm_codes.cpp`) with Falco's macro
/// resolution: the event codes a condition can match. `None` when a macro the
/// engine does not know is on the way, so the set cannot be told.
struct EventCodes<'a> {
    ctx: &'a Context,
    all: BTreeSet<String>,
}

impl<'a> EventCodes<'a> {
    fn new(ctx: &'a Context) -> Self {
        EventCodes {
            ctx,
            all: Catalog::cached().all_codes.clone(),
        }
    }

    fn names_to_codes(&self, names: &[&str]) -> BTreeSet<String> {
        let catalog = Catalog::cached();
        let mut out = BTreeSet::new();
        for n in names {
            if let Some(codes) = catalog.event_codes(n) {
                out.extend(codes.iter().cloned());
            } else if catalog.syscalls.contains(*n)
                && let Some(generic) = catalog.event_codes("syscall")
            {
                out.extend(generic.iter().cloned());
            }
        }
        out
    }

    fn invert(&self, set: BTreeSet<String>) -> BTreeSet<String> {
        self.all.difference(&set).cloned().collect()
    }

    fn codes(&mut self, e: &parser::Expr, negated: bool, depth: usize) -> Option<BTreeSet<String>> {
        use parser::Expr;
        if depth > 32 {
            return None;
        }
        let all = || self.all.clone();
        Some(match e {
            Expr::And(children, _) | Expr::Or(children, _) => {
                let conjunction = matches!(e, Expr::And(..)) != negated;
                let mut acc: Option<BTreeSet<String>> = if conjunction {
                    Some(all())
                } else {
                    Some(BTreeSet::new())
                };
                for c in children {
                    let s = self.codes(c, negated, depth + 1)?;
                    acc = acc.map(|a| {
                        if conjunction {
                            a.intersection(&s).cloned().collect()
                        } else {
                            a.union(&s).cloned().collect()
                        }
                    });
                }
                acc.unwrap_or_default()
            }
            Expr::Not(child, _) => self.codes(child, !negated, depth + 1)?,
            Expr::Identifier(name, _) => {
                let condition = self.ctx.macros.get(name).cloned().or_else(|| {
                    Catalog::cached()
                        .macros
                        .get(name)
                        .map(|m| m.condition.clone())
                })?;
                let expanded = expand_lists(&condition, self.ctx);
                let ast = parser::parse(&expanded.text).ok()?;
                self.codes(&ast, negated, depth + 1)?
            }
            Expr::Binary {
                left, op, right, ..
            } => {
                let evttype = matches!(&**left, Expr::Field { name, arg: None, .. } if name == "evt.type" || name == "syscall.type");
                if evttype && matches!(op.as_str(), "==" | "=" | "!=" | "in") {
                    let names: Vec<&str> = match &**right {
                        Expr::Value(v, _) => vec![v.as_str()],
                        Expr::List(values, _) => values.iter().map(|(v, _)| v.as_str()).collect(),
                        _ => return Some(all()),
                    };
                    let mut set = self.names_to_codes(&names);
                    if op == "!=" {
                        set = self.invert(set);
                    }
                    if negated {
                        set = self.invert(set);
                    }
                    set
                } else if let Some(known) = evt_num_invariant(left, op, right) {
                    let set = if known { all() } else { BTreeSet::new() };
                    if negated { self.invert(set) } else { set }
                } else {
                    all()
                }
            }
            _ => all(),
        })
    }
}

/// `evaluate_field_invariant`: `evt.num` starts at 1. `Some(true)` for a
/// tautology, `Some(false)` for an unsatisfiable check.
fn evt_num_invariant(left: &parser::Expr, op: &str, right: &parser::Expr) -> Option<bool> {
    use parser::Expr;
    if !matches!(left, Expr::Field { name, arg: None, .. } if name == "evt.num") {
        return None;
    }
    let num = |v: &str| v.parse::<u64>().ok();
    if op == "in" {
        let Expr::List(values, _) = right else {
            return None;
        };
        return values
            .iter()
            .all(|(v, _)| num(v) == Some(0))
            .then_some(false);
    }
    let Expr::Value(v, _) = right else {
        return None;
    };
    let n = num(v)?;
    match op {
        "=" | "==" if n == 0 => Some(false),
        "!=" if n == 0 => Some(true),
        "<" if n <= 1 => Some(false),
        "<=" if n == 0 => Some(false),
        ">" if n == 0 => Some(true),
        ">=" if n <= 1 => Some(true),
        _ => None,
    }
}

/// A field the catalogue does not know for *source*, with a near miss.
pub(crate) fn unknown_field_finding(
    name: &str,
    source: &str,
    span: parser::Span,
) -> compile::Finding {
    let catalog = Catalog::cached();
    let message = match catalog.lookup(name, source) {
        Lookup::OtherSource(field) => format!(
            "`{name}` is a field of the {} source, not of `{source}`",
            field
                .sources
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => format!("`{name}` is not a Falco field of the `{source}` source"),
    };
    compile::Finding {
        code: codes::FALCO_UNKNOWN_FIELD,
        level: compile::Level::Error,
        message,
        span,
        suggestion: near_miss(name, catalog.field_names_for(source).into_iter()),
    }
}

/// The closest name within one edit (two for names of ten characters or more).
pub fn near_miss<'a>(name: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
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

/// Output-only placeholders Falco expands itself.
const OUTPUT_PLACEHOLDERS: &[&str] = &["container.info"];

/// Diagnostics for an output template (`output:`), as libsinsp's formatter
/// (`eventformatter.cpp`) reads it: an optional leading `*`; each `%` takes an
/// optional length, then the longest text that parses as a field or a
/// transformer and compiles (so `%proc.namex` is `proc.name` then `x`).
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_output(text: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let mut diagnostics = Vec::new();
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    let start = usize::from(text.starts_with('*'));
    let bytes = text.as_bytes();
    let mut j = start;
    while j < bytes.len() {
        if bytes[j] != b'%' {
            j += 1;
            continue;
        }
        let pct = j;
        if j == bytes.len() - 1 {
            diagnostics.push(Diagnostic::error(
                codes::FALCO_OUTPUT_SYNTAX,
                "invalid formatting syntax: formatting cannot end with a % (libsinsp)",
                range(text, ByteSpan::new(pct, pct + 1)),
            ));
            break;
        }
        let mut k = j + 1;
        while k < bytes.len() && bytes[k].is_ascii_digit() {
            k += 1;
        }
        if k == bytes.len() {
            diagnostics.push(Diagnostic::error(
                codes::FALCO_OUTPUT_SYNTAX,
                "invalid formatting syntax: formatting cannot end with a number (libsinsp)",
                range(text, ByteSpan::new(pct, k)),
            ));
            break;
        }
        let rest = &text[k..];
        if let Some(p) = OUTPUT_PLACEHOLDERS.iter().find(|p| rest.starts_with(**p)) {
            diagnostics.push(Diagnostic::warning(
                codes::FALCO_DEPRECATED_FIELD,
                "%container.info is deprecated and no more useful, and will be dropped by Falco 1.0.0: the container plugin adds the container fields to the output itself",
                range(text, ByteSpan::new(pct, k + p.len())),
            ));
            spans.push((ByteSpan::new(pct, k + p.len()), "property"));
            j = k + p.len();
            continue;
        }
        // Shrink from the end until a prefix parses and compiles.
        let mut chosen: Option<usize> = None;
        let mut first_failure: Option<(parser::Expr, Vec<compile::Finding>)> = None;
        for (expr, consumed) in compile::output_prefixes(rest) {
            let mut compiler = compile::Compiler::new(catalog, ctx.source());
            let ok = compiler.output_token(&expr);
            if ok {
                for f in compiler
                    .findings
                    .into_iter()
                    .filter(|f| f.level == compile::Level::Warning)
                {
                    diagnostics.push(Diagnostic::warning(
                        f.code,
                        f.message,
                        range(text, ByteSpan::new(k + f.span.start, k + f.span.end)),
                    ));
                }
                chosen = Some(consumed);
                break;
            }
            if first_failure.is_none() {
                first_failure = Some((expr, compiler.findings));
            }
        }
        match chosen {
            Some(consumed) => {
                spans.push((ByteSpan::new(pct, k + consumed), "property"));
                j = k + consumed;
            }
            None => {
                let (code, message, span, suggestion) = match first_failure {
                    Some((_, findings)) if !findings.is_empty() => {
                        let f = findings
                            .iter()
                            .find(|f| f.level == compile::Level::Error)
                            .unwrap_or(&findings[0])
                            .clone();
                        (
                            f.code,
                            f.message,
                            ByteSpan::new(k + f.span.start, k + f.span.end),
                            f.suggestion,
                        )
                    }
                    _ => (
                        codes::FALCO_OUTPUT_SYNTAX,
                        format!(
                            "unknown filter: `%{}` is not a field or a transformer (libsinsp)",
                            rest.split_whitespace().next().unwrap_or("")
                        ),
                        ByteSpan::new(
                            pct,
                            (k + rest.find(char::is_whitespace).unwrap_or(rest.len())).max(pct + 1),
                        ),
                        None,
                    ),
                };
                let mut d = if ctx.known_source() {
                    Diagnostic::error(code, message, range(text, span))
                } else {
                    Diagnostic::warning(code, message, range(text, span))
                };
                if let Some(s) = suggestion {
                    d = d.with_suggestion(s);
                }
                if ctx.known_source() || code == codes::FALCO_OUTPUT_SYNTAX {
                    diagnostics.push(d);
                }
                j = k + 1;
            }
        }
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
    (
        "len",
        "The length of the field's value, or the number of values of a list field.",
    ),
    (
        "join",
        "Joins a list into one string: `join(\",\", proc.aname)`. Needs libsinsp 0.24.0 or later.",
    ),
    (
        "concat",
        "Concatenates strings: `concat(proc.name, \"-\", proc.pname)`. Needs libsinsp 0.24.0 or later.",
    ),
    (
        "getopt",
        "Parses command-line options: `getopt(proc.args, \"nt:\")[t]` is the value of `-t`. Needs libsinsp 0.25.0 or later.",
    ),
    (
        "oneof",
        "Modifier: exactly one value of the list satisfies the operator: `proc.name = oneof (a, b)`. Needs libsinsp 0.25.0 or later.",
    ),
    (
        "anyof",
        "Modifier: at least one value of the list satisfies the operator: `fd.name startswith anyof (/etc, /usr)`. Needs libsinsp 0.25.0 or later.",
    ),
    (
        "allof",
        "Modifier: every value of the list satisfies the operator: `proc.cmdline contains allof (-e, -c)`. Needs libsinsp 0.25.0 or later.",
    ),
    (
        "val",
        "The value of another field, compared with this one: `proc.pname = val(proc.name)`.",
    ),
];

/// Hover at byte `offset` of `text` (a host converts the editor's UTF-16
/// position once, with `opentide_core::position_to_offset`).
pub fn hover(text: &str, offset: usize, ctx: &Context) -> Option<String> {
    let offset = offset.min(text.len());
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
                        "**`{word}`** (macro, Falco default rules)\n\n```falco\n{}\n```\n\nDefined in `{}`.{}",
                        m.condition,
                        m.origin,
                        also_defined(&m.also)
                    ));
                }
            }
            if let Some(l) = catalog.lists.get(word) {
                return Some(format!(
                    "**`{word}`** (list, Falco default rules)\n\n`{}`\n\nDefined in `{}`.{}",
                    l.items.join(", "),
                    l.origin,
                    also_defined(&l.also)
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

/// The differing definitions later default rules files give a name, for hover.
fn also_defined(also: &[String]) -> String {
    if also.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = also.iter().map(|a| format!("- `{a}`")).collect();
    format!(
        "\n\nDefined differently later (not loaded by default):\n{}",
        lines.join("\n")
    )
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

/// A token of the text before the word being completed.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Sym(String),
    Str,
    Open,
    Close,
    Comma,
}

/// What a `(` opened, for the paren stack.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Paren {
    /// A value list after `in`, `intersects`, `pmatch`, or a modifier; the
    /// index of the field token it compares.
    List(Option<usize>),
    /// A transformer or `val()` call.
    Call,
    Group,
}

fn lex_head(head: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let chars: Vec<char> = head.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' || c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str);
        } else if c == '(' {
            out.push(Tok::Open);
            i += 1;
        } else if c == ')' {
            out.push(Tok::Close);
            i += 1;
        } else if c == ',' {
            out.push(Tok::Comma);
            i += 1;
        } else if "=!<>".contains(c) {
            let mut s = c.to_string();
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                s.push('=');
                i += 1;
            }
            out.push(Tok::Sym(s));
            i += 1;
        } else {
            // A word, with a field argument `[...]` kept on it.
            let mut s = String::new();
            while i < chars.len() && !chars[i].is_whitespace() && !"()\"',=!<>".contains(chars[i]) {
                if chars[i] == '[' {
                    while i < chars.len() && chars[i] != ']' {
                        s.push(chars[i]);
                        i += 1;
                    }
                }
                if i < chars.len() {
                    s.push(chars[i]);
                    i += 1;
                }
            }
            out.push(Tok::Word(s));
        }
    }
    out
}

fn is_field_word(w: &str) -> bool {
    w.contains('.') && w.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

fn is_operator_word(w: &str) -> bool {
    parser::OPERATORS.contains(&w) && w.chars().all(|c| c.is_ascii_alphabetic())
}

/// The field a comparison at `op` (the operator token's index) is about.
fn field_before(toks: &[Tok], op: usize) -> Option<usize> {
    let mut i = op.checked_sub(1)?;
    if let Tok::Word(w) = &toks[i]
        && parser::MODIFIERS.contains(&w.as_str())
    {
        i = i.checked_sub(1)?;
        i = i.checked_sub(1)?;
    }
    match &toks[i] {
        Tok::Word(w) if is_field_word(w) => Some(i),
        _ => None,
    }
}

/// Where the cursor is, judged from the tokens before the word being typed.
#[derive(Debug, PartialEq)]
enum Spot {
    /// A check: fields, macros, `not`, transformers.
    Check,
    /// After a field (token index), or after a transformer call (`None`).
    Operator(Option<usize>),
    /// After a comparison operator: the field's enumerated values.
    Value(Option<usize>),
    /// Inside a value list: lists, and the field's enumerated values.
    List(Option<usize>),
    /// After a value or a complete check: `and`, `or`.
    Boolean,
    /// After a modifier: the value list's `(` comes next.
    Nothing,
}

fn spot(toks: &[Tok]) -> Spot {
    let mut stack: Vec<Paren> = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        match t {
            Tok::Open => {
                let kind = match i.checked_sub(1).map(|p| &toks[p]) {
                    Some(Tok::Word(w))
                        if parser::LIST_OPERATORS.contains(&w.as_str())
                            || parser::MODIFIERS.contains(&w.as_str()) =>
                    {
                        Paren::List(field_before(toks, i - 1))
                    }
                    Some(Tok::Word(w))
                        if parser::TRANSFORMERS.contains(&w.as_str()) || w == "val" =>
                    {
                        Paren::Call
                    }
                    _ => Paren::Group,
                };
                stack.push(kind);
            }
            Tok::Close => {
                stack.pop();
            }
            _ => {}
        }
    }
    if let Some(Paren::List(field)) = stack.last() {
        return Spot::List(*field);
    }
    let Some(last) = toks.last() else {
        return Spot::Check;
    };
    let n = toks.len() - 1;
    match last {
        Tok::Open | Tok::Comma => Spot::Check,
        Tok::Word(w) if matches!(w.as_str(), "and" | "or" | "not") => Spot::Check,
        Tok::Word(w) if parser::MODIFIERS.contains(&w.as_str()) => Spot::Nothing,
        Tok::Word(w) if w == "exists" => Spot::Boolean,
        Tok::Word(w) if is_operator_word(w) => Spot::Value(field_before(toks, n)),
        Tok::Sym(_) => Spot::Value(field_before(toks, n)),
        Tok::Word(w) if is_field_word(w) => {
            // A field after an operator is a value (`val(...)` aside).
            match n.checked_sub(1).map(|p| &toks[p]) {
                Some(Tok::Sym(_)) => Spot::Boolean,
                Some(Tok::Word(p)) if is_operator_word(p) => Spot::Boolean,
                _ => Spot::Operator(Some(n)),
            }
        }
        Tok::Close => {
            // `)` that closed a transformer call takes an operator; a group or
            // value list closes a check.
            let mut depth = 0usize;
            let mut open = None;
            for j in (0..n).rev() {
                match toks[j] {
                    Tok::Close => depth += 1,
                    Tok::Open if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    Tok::Open => depth -= 1,
                    _ => {}
                }
            }
            let callee = open.and_then(|o| o.checked_sub(1)).map(|p| &toks[p]);
            match callee {
                Some(Tok::Word(w)) if parser::TRANSFORMERS.contains(&w.as_str()) => {
                    // The call is a value when an operator came before it.
                    let before = open.and_then(|o| o.checked_sub(2)).map(|p| &toks[p]);
                    match before {
                        Some(Tok::Sym(_)) => Spot::Boolean,
                        Some(Tok::Word(p)) if is_operator_word(p) => Spot::Boolean,
                        _ => Spot::Operator(None),
                    }
                }
                _ => Spot::Boolean,
            }
        }
        _ => Spot::Boolean,
    }
}

fn field_item(field: &Field) -> CompletionItem {
    let mut item = CompletionItem::new(field.name.clone(), "property");
    item.detail = Some(field.field_type.clone());
    item.documentation = Some(field.description.clone());
    item
}

/// The comparison operators a field's type accepts, with their modified forms
/// (libsinsp's `flt_is_comparable`).
fn operator_items(field: Option<&Field>) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    let doc = |op: &str| {
        KEYWORDS
            .iter()
            .find(|(k, _)| *k == op)
            .map(|(_, d)| (*d).to_string())
    };
    for op in parser::OPERATORS {
        let ok = field.is_none_or(|f| compile::comparable(op, &f.field_type, f.list).is_ok());
        if !ok {
            continue;
        }
        let mut item = CompletionItem::new(*op, "operator");
        item.documentation = doc(op);
        items.push(item);
    }
    for op in parser::OPERATORS {
        for m in parser::MODIFIERS {
            let full = format!("{op} {m}");
            if !MODIFIABLE.contains(op) {
                continue;
            }
            if field.is_some_and(|f| compile::comparable(&full, &f.field_type, f.list).is_err()) {
                continue;
            }
            let mut item = CompletionItem::new(full, "operator");
            item.documentation = doc(m);
            items.push(item);
        }
    }
    items
}

/// The values a field takes, where it is enumerated: `evt.type` event names
/// (syscall source) and the fields libsinsp extracts a fixed set for.
fn value_items(field: Option<&Field>, ctx: &Context) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
    let Some(field) = field else {
        return Vec::new();
    };
    if field.name == "evt.type" && ctx.source() == "syscall" {
        return catalog
            .events()
            .map(|e| CompletionItem::new(e, "constant"))
            .collect();
    }
    field
        .values
        .iter()
        .map(|v| CompletionItem::new(v.clone(), "constant"))
        .collect()
}

fn resolve_field<'c>(toks: &[Tok], at: Option<usize>, ctx: &Context) -> Option<&'c Field> {
    let Tok::Word(w) = &toks[at?] else {
        return None;
    };
    let name = w.split('[').next().unwrap_or(w);
    match Catalog::cached().lookup(name, ctx.source()) {
        Lookup::Known(f) => Some(f),
        _ => None,
    }
}

/// Completion in a condition: what the cursor's position takes, filtered by the
/// word already typed (a dotted prefix, `proc.ex`, included).
pub fn completions(text: &str, offset: usize, ctx: &Context) -> Vec<CompletionItem> {
    let before = &text[..offset.min(text.len())];
    let prefix_start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_word_char(*c))
        .last()
        .map(|(i, _)| i)
        .unwrap_or(before.len());
    let prefix = &before[prefix_start..];
    let head = &before[..prefix_start];
    let catalog = Catalog::cached();
    let toks = lex_head(head);
    let mut items = Vec::new();
    match spot(&toks) {
        Spot::Check => {
            items.extend(catalog.fields_for(ctx.source()).map(field_item));
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
            for kw in ["not"].iter().chain(parser::TRANSFORMERS.iter()) {
                items.push(CompletionItem::new(*kw, "keyword"));
            }
        }
        Spot::Operator(at) => {
            let field = resolve_field(&toks, at, ctx);
            items.extend(operator_items(field));
        }
        Spot::Value(at) => {
            let field = resolve_field(&toks, at, ctx);
            items.extend(value_items(field, ctx));
        }
        Spot::List(at) => {
            for name in ctx.lists.keys() {
                let mut item = CompletionItem::new(name.clone(), "variable");
                item.detail = Some("list (this block)".into());
                items.push(item);
            }
            for (name, l) in &catalog.lists {
                if ctx.lists.contains_key(name) {
                    continue;
                }
                let mut item = CompletionItem::new(name.clone(), "variable");
                item.detail = Some("list (Falco default rules)".into());
                item.documentation = Some(l.items.join(", "));
                items.push(item);
            }
            let field = resolve_field(&toks, at, ctx);
            items.extend(value_items(field, ctx));
        }
        Spot::Boolean => {
            for kw in ["and", "or"] {
                items.push(CompletionItem::new(kw, "keyword"));
            }
        }
        Spot::Nothing => {}
    }
    items.retain(|i| i.label.starts_with(prefix));
    items
}

/// Completion in an output template: fields after `%` (or `%(`), filtered by
/// the word already typed; nothing elsewhere.
pub fn output_completions(text: &str, offset: usize, ctx: &Context) -> Vec<CompletionItem> {
    let before = &text[..offset.min(text.len())];
    let prefix_start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_word_char(*c))
        .last()
        .map(|(i, _)| i)
        .unwrap_or(before.len());
    let prefix = &before[prefix_start..];
    let head = &before[..prefix_start];
    if !(head.ends_with('%') || head.ends_with("%(")) {
        return Vec::new();
    }
    Catalog::cached()
        .fields_for(ctx.source())
        .filter(|f| !f.filter_only && f.name.starts_with(prefix))
        .map(field_item)
        .collect()
}

/// Severity of every code this engine emits, for documentation and tests.
pub const CODES: &[(&str, Severity)] = &[
    (codes::FALCO_PARSE_ERROR, Severity::Error),
    (codes::FALCO_UNKNOWN_FIELD, Severity::Error),
    (codes::FALCO_UNKNOWN_MACRO, Severity::Warning),
    (codes::FALCO_UNKNOWN_LIST, Severity::Warning),
    (codes::FALCO_MISPLACED_LIST, Severity::Error),
    (codes::FALCO_FIELD_ARGUMENT, Severity::Error),
    (codes::FALCO_OPERATOR_TYPE, Severity::Error),
    (codes::FALCO_VALUE_TYPE, Severity::Error),
    (codes::FALCO_TRANSFORMER, Severity::Error),
    (codes::FALCO_RHS_FIELD, Severity::Error),
    (codes::FALCO_INVALID_REGEX, Severity::Error),
    (codes::FALCO_UNKNOWN_EVENT, Severity::Error),
    (codes::FALCO_APPEND_CONDITION, Severity::Error),
    (codes::FALCO_UNKNOWN_RULE, Severity::Warning),
    (codes::FALCO_OUTPUT_SYNTAX, Severity::Error),
    (codes::FALCO_EXCEPTION, Severity::Error),
    (codes::FALCO_REGEX_SIMPLE, Severity::Warning),
    (codes::FALCO_FIELD_AS_VALUE, Severity::Warning),
    (codes::FALCO_TRANSFORMER_AS_VALUE, Severity::Warning),
    (codes::FALCO_DEPRECATED_FIELD, Severity::Warning),
    (codes::FALCO_UNSAFE_NA_CHECK, Severity::Warning),
    (codes::FALCO_NO_EVTTYPE, Severity::Warning),
    (codes::FALCO_NEWER_SYNTAX, Severity::Warning),
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

    /// A condition with no event-type check (as a macro's): most tests
    /// are about one check, not about narrowing a rule's event types.
    fn plain(text: &str) -> Vec<String> {
        codes_of(
            text,
            &Context {
                macro_condition: true,
                ..Context::default()
            },
        )
    }

    fn rule(text: &str) -> Vec<String> {
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
        let mut ctx = Context {
            macro_condition: true,
            ..Context::default()
        };
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
        // libsinsp compares strings with `<` and `>`; a number value is a string.
        assert!(plain("proc.name > 5").is_empty());
        assert_eq!(
            plain("proc.pid contains 5"),
            vec![codes::FALCO_OPERATOR_TYPE]
        );
        assert_eq!(plain("proc.pid = abc"), vec![codes::FALCO_VALUE_TYPE]);
        assert_eq!(plain("evt.failed = maybe"), vec![codes::FALCO_VALUE_TYPE]);
        assert!(plain("evt.failed = true and proc.pid > 1 and len(proc.args) > 10").is_empty());
        assert_eq!(
            plain("len(proc.args) startswith x"),
            vec![codes::FALCO_OPERATOR_TYPE]
        );
        assert!(plain("tolower(proc.name) startswith bash").is_empty());
        assert_eq!(plain("fd.sip = 10.0.0.300"), vec![codes::FALCO_VALUE_TYPE]);
        assert!(plain("fd.snet in (10.0.0.0/8, 192.168.0.0/16)").is_empty());
        assert_eq!(
            plain("evt.buffer bcontains 4865Z0"),
            vec![codes::FALCO_VALUE_TYPE]
        );
        assert_eq!(
            plain("proc.name regex '('"),
            vec![codes::FALCO_INVALID_REGEX]
        );
        assert_eq!(
            plain("proc.name = val(proc.pid)"),
            vec![codes::FALCO_RHS_FIELD]
        );
        assert_eq!(plain("proc.name[1] = x"), vec![codes::FALCO_FIELD_ARGUMENT]);
        assert_eq!(
            plain("evt.arg.nosuch = x"),
            vec![codes::FALCO_FIELD_ARGUMENT]
        );
    }

    #[test]
    fn libsinsp_syntax_beyond_the_basics() {
        for text in [
            "proc.name = anyof (bash, sh)",
            "proc.name startswith oneof (/usr, /bin)",
            "not(proc.name = x)",
            "proc.pid > 0x10 and proc.pid < 1e+9",
            "getopt(proc.args, \"nt:\")[t] = x",
            "concat(proc.name, \"-\", proc.pname) = a-b",
            "join(\",\", (proc.name, proc.pname)) = \"a,b\"",
            "fd.name exists and proc.name in ()",
        ] {
            let c = plain(text);
            assert!(
                !c.iter().any(|c| c == codes::FALCO_PARSE_ERROR),
                "{text}: {c:?}"
            );
        }
        assert_eq!(
            plain("proc.name = anyof (bash, sh)"),
            vec![codes::FALCO_NEWER_SYNTAX]
        );
        // libsinsp parses hex numbers, then refuses them as integer values.
        assert_eq!(plain("proc.pid = 0x10"), vec![codes::FALCO_VALUE_TYPE]);
        // A word operator needs a blank after it.
        assert_eq!(
            plain("proc.name contains(x)"),
            vec![codes::FALCO_PARSE_ERROR]
        );
    }

    #[test]
    fn falco_loader_warnings() {
        assert_eq!(
            plain("proc.name = bash and evt.dir = <"),
            vec![codes::FALCO_DEPRECATED_FIELD]
        );
        assert!(
            rule("open_read and evt.dir = <").contains(&codes::FALCO_DEPRECATED_FIELD.to_string())
        );
        let k8s = Context {
            source: Some("k8s_audit".into()),
            ..Context::default()
        };
        assert_eq!(
            codes_of("ka.user.name = <NA>", &k8s),
            vec![codes::FALCO_UNSAFE_NA_CHECK]
        );
        // No evt.type: every event (warned); a macro narrows it.
        assert_eq!(rule("proc.name = bash"), vec![codes::FALCO_NO_EVTTYPE]);
        assert!(rule("spawned_process and proc.name = bash").is_empty());
        assert!(rule("evt.type in (open, openat) and not proc.name = bash").is_empty());
        assert_eq!(rule("not evt.type = open"), vec![codes::FALCO_NO_EVTTYPE]);
        let macro_ctx = Context {
            macro_condition: true,
            ..Context::default()
        };
        assert!(codes_of("proc.name = bash", &macro_ctx).is_empty());
        assert_eq!(
            rule("proc.name regex bash"),
            vec![codes::FALCO_REGEX_SIMPLE, codes::FALCO_NO_EVTTYPE]
        );
    }

    #[test]
    fn lists_expand_as_falco_expands_them() {
        let mut ctx = Context::default();
        ctx.lists
            .insert("two".into(), vec!["a".into(), "b c".into()]);
        ctx.lists.insert("one".into(), vec!["a".into()]);
        assert!(codes_of("spawned_process and proc.name in (two, x)", &ctx).is_empty());
        assert!(codes_of("spawned_process and proc.name in one", &ctx).is_empty());
        assert_eq!(
            codes_of("spawned_process and proc.name = two", &ctx),
            vec![codes::FALCO_MISPLACED_LIST]
        );
        assert_eq!(
            codes_of("spawned_process and proc.name in two", &ctx),
            vec![codes::FALCO_MISPLACED_LIST]
        );
        // A value of an expanded list maps back to the list's name.
        ctx.lists
            .insert("pids".into(), vec!["1".into(), "x".into()]);
        let d = analyze_with("spawned_process and proc.pid in (pids)", &ctx).diagnostics;
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].code, codes::FALCO_VALUE_TYPE);
        assert_eq!(d[0].range.start.character, 33);
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
    fn an_empty_condition_is_refused() {
        // Falco's rules schema: "Value must be non-empty".
        assert_eq!(
            codes_of("   ", &Context::default()),
            vec![codes::FALCO_PARSE_ERROR]
        );
    }

    #[test]
    fn a_tuning_is_judged_on_the_tuned_rule_with_it_appended() {
        let tuning = |rule: &str| Context {
            append: Some(true),
            tuned_rule: Some(rule.into()),
            ..Context::default()
        };
        // Falco warns LOAD_NO_EVTTYPE: `<rule condition> or proc.name = sshd`.
        assert_eq!(
            codes_of(
                "or proc.name = sshd",
                &tuning("Terminal shell in container")
            ),
            vec![codes::FALCO_NO_EVTTYPE]
        );
        // An `and not` keeps the tuned rule's event types.
        assert!(
            codes_of(
                "and not proc.pname in (kubectl)",
                &tuning("Terminal shell in container")
            )
            .is_empty()
        );
        // A rule the defaults do not have: nothing to judge (Tide reports falco_unknown_rule).
        assert!(codes_of("or proc.name = sshd", &tuning("No such rule")).is_empty());
    }

    #[test]
    fn hover_names_differing_later_definitions() {
        let h = hover(
            "evt.type = connect and inbound_outbound",
            26,
            &Context::default(),
        )
        .unwrap();
        // First defined in the incubating file; the sandbox file differs.
        assert!(
            h.contains("Defined in `falcosecurity/rules/rules/falco-incubating_rules.yaml`"),
            "{h}"
        );
        assert!(
            h.contains("Defined differently later") && h.contains("falco-sandbox_rules.yaml"),
            "{h}"
        );
    }

    #[test]
    fn default_definitions_follow_the_stable_rules_file() {
        let catalog = Catalog::cached();
        assert!(
            catalog.macros["spawned_process"]
                .origin
                .ends_with("/falco_rules.yaml")
        );
        assert!(catalog.rules.contains_key("Terminal shell in container"));
    }

    #[test]
    fn output_fields_are_checked() {
        let r = analyze_output(
            "Shell (user=%user.name proc=%proc.nmae parent=%proc.aname[2] %container.info)",
            &Context::default(),
        );
        let codes: Vec<_> = r.diagnostics.iter().map(|d| d.code.as_str()).collect();
        assert_eq!(
            codes,
            vec![codes::FALCO_UNKNOWN_FIELD, codes::FALCO_DEPRECATED_FIELD]
        );
        assert_eq!(r.diagnostics[0].suggestion.as_deref(), Some("proc.name"));
        assert_eq!(r.tokens.len(), 3);
    }

    #[test]
    fn hover_explains_fields_macros_lists_and_operators() {
        let ctx = Context::default();
        let text = "spawned_process and proc.name in (shell_binaries) and fd.name startswith /etc";
        let at = |needle: &str| text.find(needle).unwrap() + 1;
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
        // Filtered by the dotted prefix already typed.
        let start = labels("proc.");
        assert!(start.iter().any(|l| l == "proc.name"));
        assert!(start.iter().all(|l| l.starts_with("proc.")));
        let check = labels("proc.name = bash and ");
        assert!(check.iter().any(|l| l == "spawned_process"));
        assert!(check.iter().any(|l| l == "proc.name"));
        // After an operator, a free string field takes no suggestion.
        assert!(labels("proc.name startswith ").is_empty());
        assert!(labels("fd.l4proto = ").iter().any(|l| l == "tcp"));
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
