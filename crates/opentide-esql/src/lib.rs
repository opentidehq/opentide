//! I/O-free ES|QL engine: parse, catalog diagnostics, highlighting, hover,
//! completion, and signature help for Elastic Security `esql` rules.
//!
//! The catalog is Elastic's generated function and command definitions
//! (`data/catalogs/esql/`). Names the catalog does not know are diagnostics, not
//! parse errors: Kibana 9.4 and 9.5 drop an unknown command from a
//! non-aggregating rule and run the rest, so the editor has to say so.
//!
//! # Stack versions
//!
//! [`analyze`] checks a query against every stack elastic-1.0 supports
//! (Kibana 8.19 and 9.x). [`analyze_for`] takes an optional [`StackTarget`]
//! (`"9.5"`, `"serverless"`: the tenant `version` key proposed in
//! opentidehq/specifications#59) and checks against that stack only.
//!
//! # Output columns
//!
//! [`output_columns`] returns the column names a query produces when they can
//! be known without the index mappings.
//!
//! # Indices
//!
//! [`analyze_for`] reads the indices `FROM` names ([`source_indices`]). Where
//! the workspace declares Elastic indices, an undeclared one is
//! `elastic_dataset_not_declared`. Where every one holds ECS documents
//! (`logs-*`), columns read straight from them are checked against ECS
//! ([`ecs_diagnostics`]) and the columns `visibility.toml` declares for them.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]
#![expect(
    clippy::too_many_lines,
    reason = "engine dispatchers match every node kind in one function"
)]
pub mod catalog;
mod columns;
mod ecs;
mod gates;
mod lexer;
mod parser;
mod syntax;
mod tree;

// What the generated typed AST names from the crate root (`use crate::{..}`).
#[doc(hidden)]
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

/// The typed AST `cargo xtask codegen` writes from `esql.ungram`.
#[doc(hidden)]
#[path = "generated/ast.rs"]
pub mod ast;
pub mod version;

pub use catalog::{Catalog, CommandRow, FunctionRow, Lifecycle, StackVersion, TypeRow};
pub use columns::output_columns;
pub use ecs::{ecs_diagnostics, source_indices};
pub use version::{Availability, RELEASES, StackTarget};

use gates::{
    SyntaxElement, children_of, element_span, first_token, is_named, nodes_after, parts, span_of,
    text_of,
};
use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, ParameterInformation, Range, Severity, SignatureHelp,
    SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use rowan::NodeOrToken;
use std::collections::HashMap;
use syntax::SyntaxKind as K;

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// `METADATA` fields an `esql` rule can request. Hover text only.
const METADATA_FIELDS: &[(&str, &str)] = &[
    (
        "_id",
        "Document id. Elastic Security de-duplicates alerts from non-aggregating rules on `_id`.",
    ),
    ("_index", "Index the row came from."),
    ("_version", "Document version."),
    ("_score", "Relevance score, when the query scores."),
    ("_source", "Original document source."),
    ("_ignored", "Fields ignored at index time."),
    ("_index_mode", "Index mode of the backing index."),
    ("_tsid", "Time series id, for time series indices."),
];

/// The production names of the ES|QL tree's named nodes (`from_command`), for
/// the corpus gate in `opentide-analysis`. Not API.
#[doc(hidden)]
pub fn production_names() -> Vec<&'static str> {
    tree::production_names()
}

/// Whether the ES|QL parser reports a problem in `source`, and the production
/// names of its tree's named nodes in preorder, for the corpus gate in
/// `opentide-analysis`. Not API.
#[doc(hidden)]
pub fn debug_kinds(source: &str) -> (bool, Vec<&'static str>) {
    tree::named_kinds(source)
}

/// For each syntax error of `source`, the production names of the nodes it was recorded in,
/// for the corpus gate in `opentide-analysis`. Not API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<&'static str>> {
    tree::error_kinds(source)
}

/// How many times this thread has parsed an ES|QL query: one per call of an
/// entry point (`tests/entry_points.rs`). Not API.
#[doc(hidden)]
pub fn parses() -> usize {
    tree::parses()
}

/// The lossless tree of `source`, for the typed AST's tests
/// (`tests/ast_accessors.rs`). Not API.
#[doc(hidden)]
pub fn syntax_tree(source: &str) -> SyntaxNode {
    SyntaxNode::new_root(parser::parse(source).green)
}

/// Analyze against every supported stack (8.19 and 9.x). Same as
/// `analyze_for(source, None)`.
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_for(source, None)
}

/// Analyze for one stack.
///
/// With `None`, a name or form that some supported stack lacks is
/// information (a warning when the newest stack lacks it too: a removed
/// form). With `Some(target)`, a name or form that target lacks is a warning;
/// what other stacks lack is not reported. Snapshot-only names are an error
/// either way.
pub fn analyze_for(source: &str, target: Option<StackTarget>) -> AnalyzeResult {
    with_lines(source, || analyze_with_lines(source, target))
}

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
fn analyze_with_lines(source: &str, target: Option<StackTarget>) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    let catalog = Catalog::cached();
    let mut suggestions = Suggestions::new(catalog);
    let Some(tree) = tree::parse_tree(source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::ESQL_PARSE_ERROR,
                "failed to initialize the ES|QL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let mut diagnostics = Vec::new();
    if let Some(d) = parse_problem(&tree, source) {
        diagnostics.push(d);
    }
    let to_range = |span: ByteSpan| range(source, span);
    for node in named_nodes(&tree.syntax) {
        for gate in gates::syntax_gates(&node, source) {
            diagnostics.extend(gate.diagnostic(target, to_range));
        }
        if let Some((spacing, span)) = gates::command_spacing(&node, source) {
            let word = gates::tree_children(&node)
                .next()
                .map(|k| element_text(&k, source))
                .unwrap_or_default();
            match gates::spacing_gate(word, spacing, span, to_range(span)) {
                Ok(gate) => diagnostics.extend(gate.diagnostic(target, to_range)),
                Err(d) => diagnostics.push(*d),
            }
        }
        let kind = node.kind();
        if kind == K::UNKNOWN_COMMAND {
            diagnostics.push(unknown_command(&node, source, &mut suggestions));
        } else if let Some(name) = command_name(&node, source) {
            if let Some(row) = catalog.command(&name)
                && let Some(d) = availability(
                    target,
                    &display_name(&name),
                    "command",
                    row.snapshot_only,
                    row.lifecycle(),
                    row.availability(),
                    keyword_span(&node),
                    &to_range,
                )
            {
                diagnostics.push(d);
            }
        } else if kind == K::FUNCTION_CALL {
            if let Some(d) = function_diagnostic(target, &node, source, catalog, &mut suggestions) {
                diagnostics.push(d);
            }
        } else if kind == K::INLINE_CAST {
            if let Some(d) = cast_diagnostic(target, &node, source, catalog, &mut suggestions) {
                diagnostics.push(d);
            }
        } else if kind == K::QUALIFIED_NAME {
            if let Some(d) = reserved_name(&node, source) {
                diagnostics.push(d);
            }
        } else if kind == K::STRING {
            if let Some(d) = string_escape(&node, source) {
                diagnostics.push(d);
            }
        } else if kind == K::LIKE_EXPRESSION {
            diagnostics.extend(pattern_problems(&node, source));
        } else if kind == K::SELECTOR {
            let name = text_of(&node, source);
            if !matches!(name.to_ascii_lowercase().as_str(), "data" | "failures") {
                diagnostics.push(Diagnostic::error(
                    codes::ESQL_PARSE_ERROR,
                    format!("unknown index selector `::{name}`; Elasticsearch knows `::data` and `::failures`"),
                    range(source, span_of(&node)),
                ));
            }
        } else if kind == K::QUALIFIED_INTERVAL {
            // The number; the unit after it.
            let value = node
                .children()
                .find(|v| v.kind() == K::NUMBER)
                .map(|v| text_of(&v, source));
            if value.is_some_and(|v| !v.bytes().all(|b| b.is_ascii_digit())) {
                diagnostics.push(Diagnostic::error(
                    codes::ESQL_PARSE_ERROR,
                    "a time span needs a whole number (`90 minutes`, not `1.5 hours`)",
                    range(source, span_of(&node)),
                ));
            }
        }
    }
    // Elasticsearch caps expression depth: 400 until 8.19.16, 9.0-9.2,
    // 9.3.4, and 9.4.2; 300 from 8.19.17, 9.3.5, 9.4.3, and 9.5.
    let (depth, deepest) = expression_depth(&tree.syntax);
    if depth > 300 {
        let span = deepest.unwrap_or_else(|| span_of(&tree.syntax));
        let (severity, message) = if depth > 400 {
            (
                Severity::Error,
                format!(
                    "expressions nest {depth} deep; every Elasticsearch release rejects more than 400 (300 on recent patches). Split the condition"
                ),
            )
        } else {
            (
                Severity::Warning,
                format!(
                    "expressions nest {depth} deep; Elasticsearch 8.19.17+, 9.3.5+, 9.4.3+, and 9.5 reject more than 300 (earlier releases allow 400)"
                ),
            )
        };
        let mut d = Diagnostic::error(codes::ESQL_EXPRESSION_DEPTH, message, range(source, span));
        d.severity = severity;
        diagnostics.push(d);
    }
    // Kibana 9.4 and later add `METADATA _id` themselves (elastic-1.0
    // Advisories), so a declared 9.4+ or Serverless target skips the advisory.
    if !target.is_some_and(|t| t.at_least(StackVersion::new(9, 4)))
        && let Some(d) = metadata_id_advisory(&tree.syntax, source)
    {
        diagnostics.push(d);
    }
    // The indices `FROM` reads: undeclared ones, and ECS field checks when
    // every one holds ECS documents.
    opentide_ecs::merge(&mut diagnostics, ecs::dataset_diagnostics(&tree, source));
    // The tree the checks read: a second parse doubled the cost of a long query.
    let tokens = highlight(spec, &tree, source, catalog);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// `root` and the nodes below it in document order, but not the insides of
/// a one-token node (`IndexName`'s string): what the checks see.
fn named_nodes(root: &SyntaxNode) -> impl Iterator<Item = SyntaxNode> {
    let mut stack = vec![root.clone()];
    std::iter::from_fn(move || {
        let node = stack.pop()?;
        if !tree::is_leaf(node.kind()) {
            let at = stack.len();
            stack.extend(node.children());
            stack[at..].reverse();
        }
        Some(node)
    })
}

/// Words the expression lexer always reads as keywords. A field with one of
/// these names needs backticks: `` `by` ``.
const EXPRESSION_KEYWORDS: &[&str] = &[
    "and", "asc", "by", "desc", "false", "first", "in", "is", "last", "like", "not", "null",
    "nulls", "on", "or", "rlike", "true", "where", "with",
];

fn reserved_name(node: &SyntaxNode, source: &str) -> Option<Diagnostic> {
    let part = node.children().find(|part| {
        matches!(part.kind(), K::IDENTIFIER | K::JOIN_QUALIFIER)
            && EXPRESSION_KEYWORDS.contains(&text_of(part, source).to_ascii_lowercase().as_str())
    })?;
    let word = text_of(&part, source);
    Some(
        Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            format!(
                "`{word}` is an ES|QL keyword here; quote a field with that name as `` `{word}` ``"
            ),
            range(source, span_of(&part)),
        )
        .with_suggestion(format!("`{word}`")),
    )
}

/// Double-quoted strings allow only `\t \n \r \" \\`; anything else, such as
/// `"C:\Windows"`, fails the lexer. Triple-quoted strings take no escapes.
fn string_escape(node: &SyntaxNode, source: &str) -> Option<Diagnostic> {
    let t = text_of(node, source);
    if t.starts_with("\"\"\"") {
        return None;
    }
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            if !matches!(bytes[i + 1], b't' | b'n' | b'r' | b'"' | b'\\') {
                let at = span_of(node).start + i;
                return Some(
                    Diagnostic::error(
                        codes::ESQL_PARSE_ERROR,
                        format!(
                            "ES|QL strings allow only the escapes \\t \\n \\r \\\" \\\\; `\\{}` fails. Use `\\\\` or a triple-quoted string",
                            bytes[i + 1] as char
                        ),
                        range(source, ByteSpan::new(at, at + 2)),
                    )
                    .with_suggestion(double_invalid_escapes(t)),
                );
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

/// `t` with each backslash that starts an invalid escape doubled, so
/// `"C:\Users\n\Bob"` becomes `"C:\\Users\n\\Bob"`: the valid escapes keep
/// their meaning and every other backslash becomes a literal one.
fn double_invalid_escapes(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 4);
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '\\' {
            continue;
        }
        match chars.peek() {
            Some('t' | 'n' | 'r' | '"' | '\\') => out.push(chars.next().unwrap_or_default()),
            _ => out.push('\\'),
        }
    }
    out
}

/// The value of an ES|QL string literal: `"…"` with `\t \n \r \" \\`, or a
/// raw `"""…"""`. `None` when an escape is invalid (reported elsewhere).
pub(crate) fn string_value(raw: &str) -> Option<String> {
    if let Some(body) = raw.strip_prefix("\"\"\"") {
        return body.strip_suffix("\"\"\"").map(str::to_string);
    }
    let body = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            '"' => '"',
            '\\' => '\\',
            _ => return None,
        });
    }
    Some(out)
}

/// `LIKE` and `RLIKE` patterns Elasticsearch fails to compile, on every
/// release (crates/testdata/oracles/elasticsearch/esql-functions): a `LIKE` escape
/// that is not `\*`, `\?`, or `\\`, and an `RLIKE` body Lucene's `RegExp`
/// rejects or cannot determinize.
fn pattern_problems(node: &SyntaxNode, source: &str) -> Vec<Diagnostic> {
    // The patterns follow the operator; the parser reads the operand before
    // it (`expressions.rs`, `Infix::Like`).
    let own = parts(node);
    let op = first_token(&own, &[K::LIKE_KW, K::RLIKE_KW]);
    let rlike = op.is_some_and(|at| own[at].kind() == K::RLIKE_KW);
    let mut out = Vec::new();
    for pattern in op.map(|at| nodes_after(&own, at)).into_iter().flatten() {
        if pattern.kind() != K::STRING {
            continue;
        }
        let Some(value) = string_value(text_of(pattern, source)) else {
            continue;
        };
        let at = range(source, span_of(pattern));
        if rlike {
            for problem in opentide_lucene::regexp::elasticsearch_problems(&value) {
                let mut d = Diagnostic::error(
                    codes::ESQL_PATTERN,
                    format!("RLIKE: {}", problem.message),
                    at,
                );
                d.severity = problem.severity;
                out.push(d);
            }
            continue;
        }
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                continue;
            }
            match chars.next() {
                Some('*' | '?' | '\\') => {}
                other => {
                    let what =
                        other.map_or("the end of the pattern".to_string(), |c| format!("`{c}`"));
                    out.push(Diagnostic::error(
                        codes::ESQL_PATTERN,
                        format!(
                            "LIKE escapes only `*`, `?`, and `\\`; a backslash before {what} fails. Write `\\\\` for a literal backslash"
                        ),
                        at,
                    ));
                    break;
                }
            }
        }
    }
    out
}

/// Nesting depth of expressions, counted the way Elasticsearch's parser
/// limit sees a chain of `AND`/`OR` terms: each logical, comparison,
/// arithmetic, predicate, cast, call, or parenthesized node adds one. A flat
/// chain of `k` terms nests `k - 1` levels (the first two terms the deepest,
/// as in a left-leaning tree); the span reported is the innermost pair.
fn expression_depth(root: &SyntaxNode) -> (usize, Option<ByteSpan>) {
    const NESTING: &[K] = &[
        K::NOT_EXPRESSION,
        K::AND_EXPRESSION,
        K::OR_EXPRESSION,
        K::IN_EXPRESSION,
        K::IS_NULL_EXPRESSION,
        K::LIKE_EXPRESSION,
        K::MATCH_EXPRESSION,
        K::COMPARISON,
        K::UNARY_EXPRESSION,
        K::BINARY_EXPRESSION,
        K::PARENTHESIZED_EXPRESSION,
        K::INLINE_CAST,
        K::FUNCTION_CALL,
    ];
    // Iterative: a 10 000-term chain must not overflow the stack.
    let mut stack = vec![(root.clone(), 0usize)];
    let (mut max, mut deepest) = (0usize, None);
    while let Some((node, base)) = stack.pop() {
        let kids: Vec<SyntaxNode> = children_of(&node)
            .into_iter()
            .filter_map(NodeOrToken::into_node)
            .collect();
        let flat = matches!(
            node.kind(),
            K::AND_EXPRESSION | K::OR_EXPRESSION | K::BINARY_EXPRESSION
        ) && kids.len() > 1;
        let mut depths = vec![base; kids.len()];
        if NESTING.contains(&node.kind()) {
            let levels = if flat { kids.len() - 1 } else { 1 };
            if base + levels > max {
                max = base + levels;
                deepest = Some(if flat {
                    ByteSpan::new(span_of(&node).start, span_of(&kids[1]).end)
                } else {
                    span_of(&node)
                });
            }
            for (i, d) in depths.iter_mut().enumerate() {
                *d = base
                    + if !flat {
                        1
                    } else if i == 0 {
                        levels
                    } else {
                        kids.len() - i
                    };
            }
        }
        for (kid, depth) in kids.into_iter().zip(depths).rev() {
            stack.push((kid, depth));
        }
    }
    (max, deepest)
}

/// The first syntax problem as a diagnostic: where it is, the word it sits
/// on, and what the parser expected there (its message names it).
fn parse_problem(tree: &tree::Tree, source: &str) -> Option<Diagnostic> {
    let problem = tree.problems.first()?;
    let at = problem.at.min(source.len());
    let rest = if problem.at_end {
        ""
    } else {
        source.get(at..).unwrap_or("")
    };
    // A bracket, pipe or operator is quoted alone; a word with its dots
    // (`host.name`) up to the next one: a whitespace-delimited chunk ran on
    // over `("a",`, or to the end of a query written without spaces.
    let chunk_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let stop = |c: char| "()[]{},|;=<>!+%".contains(c);
    let word_len = match rest.chars().next() {
        Some(c) if stop(c) => c.len_utf8(),
        _ => rest[..chunk_len].find(stop).unwrap_or(chunk_len),
    };
    let word = &rest[..word_len];
    let near = if word.is_empty() {
        "ES|QL syntax error at the end of the query".to_string()
    } else {
        format!("ES|QL syntax error near `{word}`")
    };
    let message = format!("{near}: {}", problem.message);
    Some(Diagnostic::error(
        codes::ESQL_PARSE_ERROR,
        message,
        range(source, ByteSpan::new(at, at + word_len)),
    ))
}

/// The line and UTF-16 column of `span` in `source`: from the line table of
/// [`with_lines`] when one is installed for this very `source`, else by
/// [`span_to_range`]'s scan from the start (one scan per finding made a
/// query with many findings quadratic).
fn range(source: &str, span: ByteSpan) -> Range {
    LINES.with(|lines| match &*lines.borrow() {
        Some(table) if table.source == (source.as_ptr() as usize, source.len()) => Range {
            start: table.position(source, span.start),
            end: table.position(source, span.end),
        },
        _ => span_to_range(source, span),
    })
}

/// The line starts of the source an entry point is analyzing.
struct Lines {
    /// The source's address and length: the table is used for it only.
    source: (usize, usize),
    starts: Vec<usize>,
    /// Lines that are pure ASCII, where a column is a byte distance.
    ascii: Vec<bool>,
}

impl Lines {
    fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        let ascii = starts
            .iter()
            .enumerate()
            .map(|(i, &start)| {
                let end = starts.get(i + 1).copied().unwrap_or(source.len());
                source.as_bytes()[start..end].is_ascii()
            })
            .collect();
        Lines {
            source: (source.as_ptr() as usize, source.len()),
            starts,
            ascii,
        }
    }

    /// What [`opentide_core::offset_to_position`] answers, by a binary search.
    fn position(&self, source: &str, offset: usize) -> opentide_core::Position {
        let offset = source.floor_char_boundary(offset);
        let line = self
            .starts
            .partition_point(|&s| s <= offset)
            .saturating_sub(1);
        let start = self.starts.get(line).copied().unwrap_or(0);
        let character = if self.ascii.get(line).copied().unwrap_or(false) {
            offset - start
        } else {
            source[start..offset].chars().map(char::len_utf16).sum()
        };
        opentide_core::Position {
            line: u32::try_from(line).unwrap_or(u32::MAX),
            character: u32::try_from(character).unwrap_or(u32::MAX),
        }
    }
}

thread_local! {
    static LINES: std::cell::RefCell<Option<Lines>> = const { std::cell::RefCell::new(None) };
}

/// Runs `run` with the line table of `source` installed for [`range`], and
/// puts back whatever was installed before, even on a panic.
fn with_lines<T>(source: &str, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Lines>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            LINES.with(|lines| *lines.borrow_mut() = previous);
        }
    }
    let previous = LINES.with(|lines| lines.replace(Some(Lines::new(source))));
    let _restore = Restore(previous);
    run()
}

/// The text of a node or token.
fn element_text<'s>(element: &SyntaxElement, source: &'s str) -> &'s str {
    let span = element_span(element);
    source.get(span.start..span.end).unwrap_or("")
}

/// A join's kind (`LOOKUP`, `LEFT`): its first child when that is a token.
fn join_kind(node: &SyntaxNode) -> Option<SyntaxElement> {
    gates::tree_children(node)
        .next()
        .filter(|first| !is_named(first))
}

/// Catalog name of a command node: `stats`, `inline stats`, `lookup join`.
pub(crate) fn command_name(node: &SyntaxNode, source: &str) -> Option<String> {
    if !gates::is_command(node.kind()) {
        return None;
    }
    let base = tree::node_name(node.kind()).strip_suffix("_command")?;
    Some(match base {
        "unknown" => return None,
        "inline_stats" => {
            let first = gates::tree_children(node)
                .next()
                .map(|c| element_text(&c, source).to_ascii_lowercase());
            if first.as_deref() == Some("inlinestats") {
                "inlinestats".into()
            } else {
                "inline stats".into()
            }
        }
        "join" => {
            let join_kind = join_kind(node)
                .map(|k| element_text(&k, source).to_ascii_lowercase())
                .unwrap_or_else(|| "lookup".into());
            format!("{join_kind} join")
        }
        "fill_null" => "fillnull".into(),
        other => other.to_string(),
    })
}

fn display_name(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// The command's keyword (`LIMIT`), for the version gates: [`keyword_span`]
/// of a one-keyword command.
pub(crate) fn keyword_span_of(node: &SyntaxNode) -> ByteSpan {
    let start = usize::from(node.text_range().start());
    let end = node
        .children_with_tokens()
        .next()
        .filter(|first| first.as_token().is_some())
        .map_or(start, |first| usize::from(first.text_range().end()));
    ByteSpan::new(start, end.max(start + 1))
}

/// The command's leading keywords (`LOOKUP JOIN`, `INLINE STATS`).
pub(crate) fn keyword_span(node: &SyntaxNode) -> ByteSpan {
    let start = span_of(node).start;
    let mut end = start;
    let several = matches!(node.kind(), K::INLINE_STATS_COMMAND | K::JOIN_COMMAND);
    // Lazy: a command of 100,000 names is read up to its first name.
    for child in gates::tree_children(node) {
        if is_named(&child) || matches!(child.kind(), K::PIPE | K::L_PAREN) {
            break;
        }
        end = element_span(&child).end;
        if !several {
            break;
        }
    }
    // The join's kind and the child after it (`JOIN`).
    if node.kind() == K::JOIN_COMMAND && join_kind(node).is_some() {
        for kid in gates::tree_children(node).take(2) {
            end = end.max(element_span(&kid).end);
        }
    }
    ByteSpan::new(start, end.max(start + 1))
}

/// The catalog's "did you mean" answers within one analysis, by name. Each
/// is a scan of the whole catalog, and a query can repeat one unknown name
/// thousands of times (`EVAL f(x), f(x), …`): asking once per name keeps a
/// query with many findings linear with a small constant.
struct Suggestions {
    catalog: &'static Catalog,
    commands: HashMap<String, Option<String>>,
    functions: HashMap<String, Option<String>>,
    types: HashMap<String, Option<String>>,
}

impl Suggestions {
    fn new(catalog: &'static Catalog) -> Self {
        Suggestions {
            catalog,
            commands: HashMap::new(),
            functions: HashMap::new(),
            types: HashMap::new(),
        }
    }

    fn command(&mut self, name: &str) -> Option<String> {
        let catalog = self.catalog;
        Self::memo(&mut self.commands, name, |n| catalog.suggest_command(n))
    }

    fn function(&mut self, name: &str) -> Option<String> {
        let catalog = self.catalog;
        Self::memo(&mut self.functions, name, |n| catalog.suggest_function(n))
    }

    fn cast_type(&mut self, name: &str) -> Option<String> {
        let catalog = self.catalog;
        Self::memo(&mut self.types, name, |n| catalog.suggest_type(n))
    }

    fn memo(
        seen: &mut HashMap<String, Option<String>>,
        name: &str,
        suggest: impl FnOnce(&str) -> Option<String>,
    ) -> Option<String> {
        if let Some(known) = seen.get(name) {
            return known.clone();
        }
        SUGGESTION_SCANS.set(SUGGESTION_SCANS.get() + 1);
        let answer = suggest(name);
        seen.insert(name.to_string(), answer.clone());
        answer
    }
}

thread_local! {
    /// The catalog scans for a "did you mean" on this thread: [`suggestion_scans`].
    static SUGGESTION_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many times this thread has scanned the catalog for a "did you mean"
/// (an unknown command, function or type). For the tests that hold it to one
/// scan per distinct name in a query (`tests/entry_points.rs`). Not API.
#[doc(hidden)]
pub fn suggestion_scans() -> usize {
    SUGGESTION_SCANS.get()
}

fn unknown_command(node: &SyntaxNode, source: &str, suggestions: &mut Suggestions) -> Diagnostic {
    // The name: the command's first node.
    let name_node = node.children().next().unwrap_or_else(|| node.clone());
    let name = text_of(&name_node, source);
    let mut d = Diagnostic::error(
        codes::ESQL_UNKNOWN_COMMAND,
        format!(
            "unknown ES|QL command `{name}`; Elasticsearch rejects it, and Kibana 9.4 and 9.5 run a non-aggregating rule without it"
        ),
        range(source, span_of(&name_node)),
    );
    if let Some(s) = suggestions.command(name) {
        d = d.with_suggestion(display_name(&s));
    }
    d
}

fn function_diagnostic(
    target: Option<StackTarget>,
    node: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    suggestions: &mut Suggestions,
) -> Option<Diagnostic> {
    // The name: the call's first node.
    let name_node = node.children().next()?;
    if name_node.kind() == K::PARAMETER {
        return None;
    }
    let name = text_of(&name_node, source);
    let span = span_of(&name_node);
    let lower = name.to_ascii_lowercase();
    if lower != "first" && lower != "last" && EXPRESSION_KEYWORDS.contains(&lower.as_str()) {
        // `in(x)`: the expression lexer reads the name as a keyword.
        return Some(Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            format!("`{name}` is an ES|QL keyword and cannot name a function"),
            range(source, span),
        ));
    }
    match catalog.function(name) {
        Some(row) => availability(
            target,
            &format!("{}()", name.to_ascii_uppercase()),
            "function",
            row.snapshot_only,
            row.lifecycle(),
            row.availability(),
            span,
            &|s| range(source, s),
        ),
        None => {
            let mut d = Diagnostic::error(
                codes::ESQL_UNKNOWN_FUNCTION,
                format!("unknown ES|QL function `{name}`"),
                range(source, span),
            );
            if let Some(s) = suggestions.function(name) {
                d = d.with_suggestion(s.to_ascii_uppercase());
            }
            Some(d)
        }
    }
}

/// `::type`: a name no release can cast to is an error (Elasticsearch fails
/// to parse it: "Unknown data type" or "Unsupported conversion"); a name only
/// some releases know is a version gate.
fn cast_diagnostic(
    target: Option<StackTarget>,
    node: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    suggestions: &mut Suggestions,
) -> Option<Diagnostic> {
    let type_node = node.children().find(|c| c.kind() == K::TYPE_NAME)?;
    let name = text_of(&type_node, source);
    if name.starts_with('?') || name.starts_with('`') {
        return None;
    }
    let span = span_of(&type_node);
    match catalog.cast_type(name) {
        Some(row) => {
            let mut gate = gates_for_type(row, span);
            if !row.function.is_empty() {
                gate.note = Some(format!(
                    "the cast calls `{}()`",
                    row.function.to_ascii_uppercase()
                ));
            }
            gate.diagnostic(target, |s| range(source, s))
        }
        None => {
            let mut d = Diagnostic::error(
                codes::ESQL_UNKNOWN_TYPE,
                format!(
                    "`{name}` is not an ES|QL type Elasticsearch can cast to; use a type such as `keyword`, `long`, `double`, `ip`, or `datetime`"
                ),
                range(source, span),
            );
            if let Some(s) = suggestions.cast_type(name) {
                d = d.with_suggestion(s);
            }
            Some(d)
        }
    }
}

fn gates_for_type(row: &TypeRow, span: ByteSpan) -> gates::Gate {
    gates::Gate {
        subject: format!("cast type `::{}`", row.name),
        available: row.availability(),
        note: None,
        suggestion: None,
        floor_severity: None,
        span,
    }
}

/// Snapshot-only names fail on every release. Otherwise the catalog's
/// release lines decide (see [`gates::Gate::diagnostic`]); a row without
/// them falls back to the docs lifecycle: a declared target older than the
/// first documented release is a warning, and with no target, first
/// documented at 9.2 or later is information (missing on 8.19). Preview
/// names may change.
#[expect(
    clippy::too_many_arguments,
    reason = "a private helper, called with each fact of one name"
)]
fn availability(
    target: Option<StackTarget>,
    name: &str,
    what: &str,
    snapshot_only: bool,
    lifecycle: &Lifecycle,
    available: Option<Availability>,
    span: ByteSpan,
    to_range: &dyn Fn(ByteSpan) -> Range,
) -> Option<Diagnostic> {
    // The line and column are found only for a finding: a scan from the start
    // of the source per command made a long pipeline quadratic.
    let range = || to_range(span);
    if snapshot_only {
        return Some(Diagnostic::error(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` exists only in Elasticsearch snapshot builds; release clusters reject it"
            ),
            range(),
        ));
    }
    if let Some(available) = available {
        // The gate's text is built only when it fires: most names are
        // available everywhere (ADR 0014 §4).
        if gates::Gate::fires(available, target) {
            let described = lifecycle.describe();
            let gate = gates::Gate {
                subject: format!("{what} `{name}`"),
                available,
                note: (!described.is_empty()).then_some(described),
                suggestion: None,
                floor_severity: None,
                span,
            };
            if let Some(d) = gate.diagnostic(target, to_range) {
                return Some(d);
            }
        }
        let ga_on_target = match (target, lifecycle.ga) {
            (Some(StackTarget::Serverless), _) => true,
            (Some(StackTarget::Version(v)), Some(ga)) => v >= ga,
            _ => false,
        };
        if ga_on_target {
            return None;
        }
    } else if let Some(target) = target {
        // A declared target older than the first documented release lacks it.
        if let Some(first) = lifecycle.first().filter(|v| !target.at_least(*v)) {
            return Some(Diagnostic::warning(
                codes::ESQL_UNAVAILABLE,
                format!(
                    "{what} `{name}` needs Elasticsearch {first} or later ({}); the declared stack {target} lacks it",
                    lifecycle.describe()
                ),
                range(),
            ));
        }
    } else if let Some(first) = lifecycle.after_floor() {
        let mut d = Diagnostic::warning(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` needs Elasticsearch {first} or later ({}); an 8.19 cluster rejects it",
                lifecycle.describe()
            ),
            range(),
        );
        d.severity = Severity::Information;
        return Some(d);
    }
    if !lifecycle.is_ga() && (lifecycle.preview.is_some() || lifecycle.preview_unversioned) {
        let mut d = Diagnostic::warning(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` is in technical preview ({}); Elastic may change or remove it",
                lifecycle.describe()
            ),
            range(),
        );
        d.severity = Severity::Information;
        return Some(d);
    }
    None
}

/// Non-aggregating `FROM` queries need `METADATA _id` so Elastic Security can
/// de-duplicate alerts ([elastic-1.0] Advisories).
fn metadata_id_advisory(root: &SyntaxNode, source: &str) -> Option<Diagnostic> {
    let query = root.children().find(|c| c.kind() == K::QUERY)?;
    let mut commands = parts(&query).into_iter().filter_map(NodeOrToken::into_node);
    let source_cmd = commands.next()?;
    if source_cmd.kind() != K::FROM_COMMAND {
        return None;
    }
    if commands.any(|c| c.kind() == K::STATS_COMMAND) {
        return None;
    }
    let metadata = source_cmd.children().find(|c| c.kind() == K::METADATA);
    let has_id = metadata.as_ref().is_some_and(|m| {
        m.children()
            .any(|f| f.kind() == K::METADATA_FIELD && text_of(&f, source) == "_id")
    });
    if has_id {
        return None;
    }
    let span = metadata
        .as_ref()
        .map_or_else(|| keyword_span(&source_cmd), span_of);
    Some(
        Diagnostic::warning(
            codes::ESQL_METADATA_ID,
            "non-aggregating ES|QL query lacks `METADATA _id`; before 9.4 Elastic Security cannot de-duplicate its alerts (9.4 and later add it)",
            range(source, span),
        )
        .with_suggestion("METADATA _id, _version, _index"),
    )
}

pub(crate) fn highlight(
    spec: &HighlightSpec,
    tree: &tree::Tree,
    source: &str,
    catalog: &Catalog,
) -> Vec<HighlightToken> {
    let mut spans: Vec<(ByteSpan, String)> = Vec::new();
    // The tree-sitter tree's leaves in document order: tokens, comments,
    // one-token nodes.
    let mut stack = vec![NodeOrToken::Node(tree.syntax.clone())];
    while let Some(element) = stack.pop() {
        if let NodeOrToken::Node(node) = &element {
            let kids = children_of(node);
            if !kids.is_empty() {
                stack.extend(kids.into_iter().rev());
                continue;
            }
        }
        let span = element_span(&element);
        if span.end <= span.start {
            continue;
        }
        let Some(capture) = tree::capture(&element) else {
            continue;
        };
        let capture = if capture == "function"
            && catalog
                .function(source.get(span.start..span.end).unwrap_or(""))
                .is_some()
        {
            "function.builtin"
        } else {
            capture
        };
        spans.push((span, capture.to_string()));
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

// ---- Hover ----------------------------------------------------------------

/// The smallest element of the tree-sitter tree (a node, a token, a comment)
/// that holds `offset`, with half-open spans, as tree-sitter finds it: the
/// token there (found by rowan's search, not a scan of each level's
/// children), whitespace standing for the node it is in, and the outermost
/// one-token node around it standing for its insides. At the end of the
/// query, the root.
fn element_at(root: &SyntaxNode, offset: usize) -> SyntaxElement {
    let Ok(at) = u32::try_from(offset).map(rowan::TextSize::from) else {
        return NodeOrToken::Node(root.clone());
    };
    if at >= root.text_range().end() {
        return NodeOrToken::Node(root.clone());
    }
    // Between two tokens, the one that starts here.
    let Some(token) = root.token_at_offset(at).right_biased() else {
        return NodeOrToken::Node(root.clone());
    };
    let mut element = if token.kind() == K::WHITESPACE {
        match tree::parent_of(&NodeOrToken::Token(token)) {
            Some(parent) => NodeOrToken::Node(parent),
            None => return NodeOrToken::Node(root.clone()),
        }
    } else {
        NodeOrToken::Token(token)
    };
    let start = match &element {
        NodeOrToken::Node(n) => n.parent(),
        NodeOrToken::Token(t) => t.parent(),
    };
    for ancestor in std::iter::successors(start, rowan::SyntaxNode::parent) {
        if tree::is_leaf(ancestor.kind()) {
            element = NodeOrToken::Node(ancestor);
        }
    }
    element
}

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset) {
        return None;
    }
    let tree = tree::parse_tree(source)?;
    let catalog = Catalog::cached();
    let element = element_at(&tree.syntax, offset);
    let text = element_text(&element, source);
    let node = element.as_node();
    // Function name.
    if let Some(parent) = tree::parent_of(&element) {
        if parent.kind() == K::FUNCTION_CALL
            && node.is_some()
            && parent.children().next().as_ref() == node
        {
            return catalog.function(text).map(function_hover);
        }
        if parent.kind() == K::METADATA_FIELD || element.kind() == K::METADATA_FIELD {
            return METADATA_FIELDS
                .iter()
                .find(|(n, _)| *n == text)
                .map(|(n, d)| format!("**`{n}`** (METADATA field)\n\n{d}"));
        }
    }
    // Command keyword.
    let mut cur = match &element {
        NodeOrToken::Node(n) => Some(n.clone()),
        NodeOrToken::Token(_) => tree::parent_of(&element),
    };
    while let Some(n) = cur {
        if gates::is_command(n.kind()) {
            let span = keyword_span(&n);
            if offset >= span.start && offset < span.end {
                if n.kind() == K::UNKNOWN_COMMAND {
                    return None;
                }
                let name = command_name(&n, source)?;
                return catalog.command(&name).map(command_hover);
            }
            break;
        }
        cur = tree::parent_of(&NodeOrToken::Node(n));
    }
    // Operator.
    if !is_named(&element)
        && let Some(op) = catalog.operator(text)
    {
        return Some(operator_hover(op));
    }
    None
}

fn command_hover(row: &CommandRow) -> String {
    let mut md = format!("**{}** ({} command)", display_name(&row.name), row.kind);
    if !row.syntax.is_empty() {
        md.push_str(&format!("\n\n```esql\n{}\n```", row.syntax));
    }
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    md.push_str(&lifecycle_line(row.snapshot_only, &row.stack));
    md.push_str(&releases_line(row.snapshot_only, row.availability()));
    if let Some(alias) = &row.alias_of {
        md.push_str(&format!("\n\nSame as `{}`.", display_name(alias)));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn function_hover(row: &FunctionRow) -> String {
    let mut md = format!(
        "**{}** ({} function)\n\n```esql\n{}\n```",
        row.name.to_ascii_uppercase(),
        row.kind,
        row.signature
    );
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    if !row.parameters.is_empty() {
        md.push_str("\n\n**Parameters**\n");
        for p in &row.parameters {
            let optional = if p.required { "" } else { " (optional)" };
            md.push_str(&format!(
                "\n- `{}`{optional} _{}_",
                p.name,
                p.types.join(" | ")
            ));
        }
    }
    if !row.returns.is_empty() {
        md.push_str(&format!("\n\n**Returns** _{}_", row.returns.join(" | ")));
    }
    md.push_str(&lifecycle_line(row.snapshot_only, &row.stack));
    md.push_str(&releases_line(row.snapshot_only, row.availability()));
    if let Some(license) = &row.license {
        md.push_str(&format!("\n\nLicence: {license}."));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn operator_hover(row: &catalog::OperatorRow) -> String {
    let mut md = format!("**`{}`** (operator)\n\n{}", row.operator, row.docs);
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

fn lifecycle_line(snapshot_only: bool, stack: &str) -> String {
    if snapshot_only {
        return "\n\nAvailability: snapshot builds only.".into();
    }
    let lifecycle = Lifecycle::parse(stack);
    let described = lifecycle.describe();
    if described.is_empty() {
        String::new()
    } else {
        format!("\n\nAvailability: {described}.")
    }
}

/// "Releases: 8.19 and 9.1 to 9.6." when some supported line lacks the name.
fn releases_line(snapshot_only: bool, available: Option<Availability>) -> String {
    match available {
        Some(a) if !snapshot_only && !a.is_all() && !a.is_empty() => {
            format!("\n\nReleases: {}.", version::join_versions(&a.versions()))
        }
        _ => String::new(),
    }
}

// ---- Completion -----------------------------------------------------------

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    let segment_start = last_pipe(before).map(|i| i + 1);
    let segment = &before[segment_start.unwrap_or(0)..];
    let trimmed = segment.trim_start();
    let typing_first_word = !trimmed.contains(char::is_whitespace);
    if typing_first_word {
        let source_position = segment_start.is_none();
        return catalog
            .commands
            .iter()
            .filter(|c| !c.snapshot_only && c.alias_of.is_none())
            .filter(|c| {
                if source_position {
                    c.kind == "source" || c.kind == "directive"
                } else {
                    c.kind == "processing"
                }
            })
            .map(|c| {
                CompletionItem::new(display_name(&c.name), "command")
                    .with_detail(c.syntax.lines().next().unwrap_or("").to_string())
                    .with_docs(command_hover(c))
            })
            .collect();
    }
    let command = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(command.as_str(), "from" | "ts") {
        if lower.split_whitespace().any(|w| w == "metadata") {
            return METADATA_FIELDS
                .iter()
                .map(|(n, d)| CompletionItem::new(*n, "property").with_docs(*d))
                .collect();
        }
        return vec![CompletionItem::new("METADATA", "keyword").with_docs(
            "Request metadata fields. Non-aggregating Elastic Security rules need `METADATA _id`.",
        )];
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .filter(|f| !f.snapshot_only)
        .filter(|f| {
            // Aggregations belong to STATS and INLINE STATS.
            f.kind != "agg" && f.kind != "time_series_agg"
                || matches!(command.as_str(), "stats" | "inline" | "inlinestats")
        })
        .map(|f| {
            CompletionItem::new(f.name.to_ascii_uppercase(), "function")
                .with_detail(f.signature.clone())
                .with_docs(function_hover(f))
        })
        .collect();
    for kw in clause_keywords(&command) {
        items.push(CompletionItem::new(*kw, "keyword"));
    }
    for name in columns_in(source) {
        items.push(CompletionItem::new(name, "property"));
    }
    items
}

fn clause_keywords(command: &str) -> &'static [&'static str] {
    match command {
        "where" | "eval" | "row" => &[
            "AND",
            "OR",
            "NOT",
            "IN",
            "LIKE",
            "RLIKE",
            "IS NULL",
            "IS NOT NULL",
        ],
        "stats" | "inline" | "inlinestats" => &["BY", "WHERE"],
        "sort" => &["ASC", "DESC", "NULLS FIRST", "NULLS LAST"],
        "enrich" => &["ON", "WITH"],
        "rename" => &["AS"],
        "lookup" => &["JOIN", "ON"],
        _ => &[],
    }
}

/// Column names the query already references or creates.
fn columns_in(source: &str) -> Vec<String> {
    let Some(tree) = tree::parse_tree(source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    for node in named_nodes(&tree.syntax) {
        if matches!(node.kind(), K::QUALIFIED_NAME | K::NAME_PATTERN)
            && !tree.problem_in(span_of(&node))
        {
            let name = text_of(&node, source);
            if !name.contains('*') && !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }
    names.into_iter().collect()
}

fn last_pipe(before: &str) -> Option<usize> {
    let mut in_string = false;
    let mut last = None;
    let bytes = before.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'|' if !in_string => last = Some(i),
            _ => {}
        }
        i += 1;
    }
    last
}

// ---- Signature help -------------------------------------------------------

#[expect(
    clippy::cast_possible_truncation,
    reason = "a signature has a handful of parameters, far below u32::MAX"
)]
pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    // An offset inside a character (a decoded escape) has nothing to show.
    let before = source.get(..offset.min(source.len()))?;
    let (name, active) = innermost_call(before)?;
    let row = Catalog::cached().function(&name)?;
    let parameters: Vec<ParameterInformation> = row
        .parameters
        .iter()
        .map(|p| ParameterInformation {
            label: p.name.clone(),
            documentation: Some(format!("_{}_", p.types.join(" | "))),
        })
        .collect();
    let active = active.min(parameters.len().saturating_sub(1) as u32);
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: row.signature.clone(),
            documentation: row.citation.clone().map(|c| format!("[Elastic docs]({c})")),
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    })
}

/// Innermost unclosed `name(` before the cursor and the comma count inside it.
fn innermost_call(before: &str) -> Option<(String, u32)> {
    let bytes = before.as_bytes();
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'(' => stack.push((i, 0)),
                b')' => {
                    stack.pop();
                }
                b',' => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    let (open, commas) = *stack.last()?;
    let name_start =
        opentide_core::word_start(&before[..open], |c| c.is_ascii_alphanumeric() || c == '_');
    let name = before[name_start..open].to_string();
    (!name.is_empty()).then_some((name, commas))
}

#[cfg(test)]
mod tests {
    #[test]
    fn lifecycle_fallback_checks_a_declared_target() {
        let ga = Lifecycle::parse("ga 9.3");
        let to_range = |span: ByteSpan| span_to_range("x", span);
        let check = |target| {
            availability(
                target,
                "f",
                "function",
                false,
                &ga,
                None,
                ByteSpan::new(0, 1),
                &to_range,
            )
            .map(|d| d.severity)
        };
        assert_eq!(check(StackTarget::parse("8.19")), Some(Severity::Warning));
        assert_eq!(check(StackTarget::parse("9.2")), Some(Severity::Warning));
        assert_eq!(check(StackTarget::parse("9.3")), None);
        assert_eq!(check(StackTarget::parse("serverless")), None);
        assert_eq!(check(None), Some(Severity::Information));
    }

    #[test]
    fn escape_fix_keeps_valid_escapes() {
        assert_eq!(
            double_invalid_escapes(r#""C:\Users\n\Bob""#),
            r#""C:\\Users\n\\Bob""#
        );
        assert_eq!(double_invalid_escapes(r#""a\\b\*\"q""#), r#""a\\b\\*\"q""#);
    }

    use super::*;

    #[test]
    fn declared_targets_order_and_skip_the_metadata_advisory() {
        let t = |s: &str| StackTarget::parse(s).unwrap();
        assert_eq!(
            StackTarget::lowest([t("9.5"), t("8.19"), t("serverless")]),
            Some(t("8.19"))
        );
        assert!(t("serverless").at_least(StackVersion::new(9, 4)));
        assert!(!t("9.3").at_least(StackVersion::new(9, 4)));
        let src = "FROM logs-* | WHERE a == 1";
        let codes = |target| -> Vec<String> {
            analyze_for(src, target)
                .diagnostics
                .into_iter()
                .map(|d| d.code)
                .collect()
        };
        assert!(codes(None).contains(&codes::ESQL_METADATA_ID.to_string()));
        assert!(codes(Some(t("9.3"))).contains(&codes::ESQL_METADATA_ID.to_string()));
        assert!(!codes(Some(t("9.4"))).contains(&codes::ESQL_METADATA_ID.to_string()));
        assert!(!codes(Some(t("serverless"))).contains(&codes::ESQL_METADATA_ID.to_string()));
    }

    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn clean_rule_has_no_diagnostics() {
        let src = "FROM logs-endpoint.events.process-* METADATA _id, _version, _index\n| WHERE process.name == \"cmd.exe\" AND host.os.type == \"windows\"\n| KEEP @timestamp, host.name, process.*\n| LIMIT 100";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
        assert!(r.tokens.iter().any(|t| t.capture == "type"));
    }

    #[test]
    fn unknown_command_is_named_with_a_suggestion() {
        let r = analyze("FROM logs-* METADATA _id | WEHRE x == 1");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::ESQL_UNKNOWN_COMMAND)
            .expect("unknown command");
        assert_eq!(d.suggestion.as_deref(), Some("WHERE"));
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_PARSE_ERROR)
        );
    }

    #[test]
    fn unknown_function_is_diagnosed() {
        let c = codes_of("FROM logs-* METADATA _id | EVAL x = STARTSWITH(a, \"b\")");
        assert!(
            c.contains(&codes::ESQL_UNKNOWN_FUNCTION.to_string()),
            "{c:?}"
        );
    }

    #[test]
    fn metadata_id_advisory_only_for_non_aggregating_from() {
        assert!(
            codes_of("FROM logs-* | WHERE a == 1").contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(
            !codes_of("FROM logs-* | STATS c = COUNT(*) BY host.name")
                .contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(
            !codes_of("FROM logs-* METADATA _id | WHERE a == 1")
                .contains(&codes::ESQL_METADATA_ID.to_string())
        );
        assert!(!codes_of("ROW a = 1").contains(&codes::ESQL_METADATA_ID.to_string()));
    }

    /// A catalog row's `versions` list is read once, not on each lookup
    /// (ADR 0014 §2, §7): every lookup formatted the eight release lines.
    #[test]
    fn a_rows_versions_are_read_once_not_per_lookup() {
        let queries = [
            "FROM logs-* | EVAL x = TO_LOWER(a::keyword) | STATS c = COUNT(*) BY x | LIMIT 10",
            "FROM logs-* | EVAL y = TO_UPPER(b::keyword) | STATS d = COUNT(*) BY y | LIMIT 11",
        ];
        for q in queries {
            analyze(q);
        }
        let before = version::version_lists_read();
        for _ in 0..3 {
            for q in queries {
                analyze(q);
            }
        }
        assert_eq!(version::version_lists_read() - before, 0);
    }

    #[test]
    fn newer_commands_report_availability() {
        let r = analyze("FROM logs-* METADATA _id | INLINE STATS c = COUNT(*) BY host.name");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::ESQL_UNAVAILABLE)
            .expect("availability");
        assert_eq!(d.severity, Severity::Information);
        assert!(d.message.contains("9.2"), "{}", d.message);
    }

    #[test]
    fn lexer_rules_from_elasticsearch() {
        let c = codes_of("FROM logs-* METADATA _id | WHERE file.path == \"C:\\Windows\"");
        assert!(c.contains(&codes::ESQL_PARSE_ERROR.to_string()), "{c:?}");
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE file.path == \"\"\"C:\\Windows\"\"\"")
                .is_empty()
        );
        assert!(codes_of("FROM logs-* METADATA _id | WHERE a == \"x\\ty\"").is_empty());
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE @timestamp > NOW() - 1.5 hours")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("FROM logs-* METADATA _id | EVAL s = TO_STR(x)").is_empty(),
            "registered alias"
        );
        assert!(
            codes_of("FROM logs-* METADATA _id | WHERE a =~ \"x\"")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn expression_keywords_are_reserved() {
        let c = codes_of("FROM logs-* METADATA _id | INLINE STATS BY");
        assert!(c.contains(&codes::ESQL_PARSE_ERROR.to_string()), "{c:?}");
        assert!(codes_of("FROM logs-* METADATA _id | WHERE `by` == 1").is_empty());
        assert!(
            codes_of("FROM logs-* | STATS f = FIRST(x, @timestamp) BY host.name")
                .iter()
                .all(|c| c != codes::ESQL_PARSE_ERROR)
        );
        assert!(codes_of("FROM logs-* METADATA _id | WHERE source.as.number == 1").is_empty());
    }

    #[test]
    fn parse_error_has_a_range() {
        let r = analyze("FROM logs-* | WHERE (a == ");
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_PARSE_ERROR)
        );
    }

    #[test]
    fn hover_names_commands_and_functions() {
        let src = "FROM logs-* | WHERE STARTS_WITH(process.name, \"x\")";
        let h = hover(src, 15).expect("command hover");
        assert!(h.contains("WHERE"), "{h}");
        let h = hover(src, 22).expect("function hover");
        assert!(h.contains("STARTS_WITH"), "{h}");
        assert!(h.contains("elastic.co"), "{h}");
    }

    #[test]
    fn completion_by_position() {
        let items = completions("FROM logs-* | ", 14);
        assert!(items.iter().any(|i| i.label == "WHERE"));
        assert!(!items.iter().any(|i| i.label == "FROM"));
        let items = completions("FR", 2);
        assert!(items.iter().any(|i| i.label == "FROM"));
        let items = completions("FROM logs-* METADATA ", 21);
        assert!(items.iter().any(|i| i.label == "_id"));
        let src = "FROM logs-* | WHERE ";
        let items = completions(src, src.len());
        assert!(items.iter().any(|i| i.label == "STARTS_WITH"));
        assert!(
            !items.iter().any(|i| i.label == "COUNT"),
            "aggregations only in STATS"
        );
    }

    fn find<'a>(diags: &'a [Diagnostic], code: &str, needle: &str) -> Option<&'a Diagnostic> {
        diags
            .iter()
            .find(|d| d.code == code && d.message.contains(needle))
    }

    fn at(version: &str) -> Option<StackTarget> {
        StackTarget::parse(version)
    }

    #[test]
    fn presence_matrix_drives_name_availability() {
        let r = analyze("FROM logs-* METADATA _id | FORK (WHERE a == 1) (WHERE b == 2)");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "FORK").expect("fork");
        assert_eq!(d.severity, Severity::Information);
        assert!(
            d.message.contains("8.19 and 9.0 reject it"),
            "{}",
            d.message
        );
        let r = analyze("ROW a = COPY_SIGN(1, -2)");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "COPY_SIGN").expect("copy_sign");
        assert_eq!(d.severity, Severity::Information);
        // Removed after 9.3: a warning, never an unknown-function error.
        let r = analyze("FROM a METADATA _id | WHERE MULTI_MATCH(\"x\", b, c)");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "MULTI_MATCH").expect("multi_match");
        assert_eq!(d.severity, Severity::Warning);
        assert!(d.message.contains("9.1 to 9.3"), "{}", d.message);
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_UNKNOWN_FUNCTION)
        );
        assert!(
            codes_of("ROW a = ABS(-1)").is_empty(),
            "abs is in the math module"
        );
    }

    #[test]
    fn declared_target_reports_only_that_stack() {
        let q = "FROM logs-* METADATA _id | INLINE STATS c = COUNT(*) BY host.name";
        let on = |v: &str| analyze_for(q, at(v)).diagnostics;
        let d = on("8.19");
        let d = find(&d, codes::ESQL_UNAVAILABLE, "INLINE STATS").expect("8.19 lacks it");
        assert_eq!(d.severity, Severity::Warning);
        assert!(
            d.message.contains("Elasticsearch 8.19 rejects it"),
            "{}",
            d.message
        );
        assert!(on("9.3").is_empty(), "{:?}", on("9.3"));
        assert!(on("9.12").is_empty());
        assert!(on("serverless").is_empty());
        // 9.0 is the only line without `RENAME new = old`.
        let q = "ROW a = 1 | RENAME b = a";
        assert!(analyze_for(q, at("8.19")).diagnostics.is_empty());
        let d = analyze_for(q, at("9.0")).diagnostics;
        assert!(find(&d, codes::ESQL_UNAVAILABLE, "RENAME new = old").is_some());
        // Snapshot-only stays an error for every target.
        let d = analyze_for("FROM a METADATA _id | FILLNULL 0 ON b", at("9.6")).diagnostics;
        assert!(d.iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn syntax_gates_name_the_versions() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "ROW a = 1 | RENAME b = a",
                "RENAME new = old",
                "9.0 rejects it",
            ),
            (
                "ROW a = \"x\" | WHERE a LIKE (\"x\", \"y\")",
                "LIKE (…)",
                "9.0 rejects it",
            ),
            (
                "ROW a = \"x\" | WHERE a RLIKE (\"x\", \"y\")",
                "RLIKE (…)",
                "needs Elasticsearch 9.2",
            ),
            (
                "FROM logs-*::failures METADATA _id",
                "::failures",
                "9.0 rejects it",
            ),
            (
                "FROM c:logs-*::data METADATA _id",
                "cluster:index::selector",
                "needs Elasticsearch 9.4",
            ),
            ("ROW a = 1 | WHERE a == ??b", "??", "9.0 rejects it"),
            (
                "ROW a = NOW() - 5 m",
                "minute unit `m`",
                "needs Elasticsearch 9.3",
            ),
            (
                "ROW a = NOW() - 5M",
                "minute unit `m`",
                "needs Elasticsearch 9.3",
            ),
            (
                "FROM a, (FROM b) METADATA _id",
                "subquery in `FROM`",
                "needs Elasticsearch 9.4",
            ),
            (
                "FROM a METADATA _id | WHERE b IN (FROM c | KEEP d)",
                "IN (subquery)",
                "needs Elasticsearch 9.5",
            ),
            (
                "FROM a | STATS c = COUNT(*) WHERE b IN (FROM c | KEEP d)",
                "aggregate filter",
                "needs Elasticsearch 9.6",
            ),
            (
                "FROM a METADATA _id | WHERE (b, e) IN (FROM c | KEEP d, f)",
                "tuple",
                "needs Elasticsearch 9.6",
            ),
            (
                "ROW a = 1 | LIMIT 1 BY a",
                "LIMIT … BY",
                "needs Elasticsearch 9.4",
            ),
            (
                "ROW a = \"x\" | GROK a \"%{WORD:b}\", \"%{WORD:c}\"",
                "several patterns",
                "needs Elasticsearch 9.3",
            ),
        ];
        for (q, subject, versions) in cases {
            let r = analyze(q);
            let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, subject)
                .unwrap_or_else(|| panic!("{q}: {:?}", r.diagnostics));
            assert!(d.message.contains(versions), "{q}: {}", d.message);
            assert_eq!(d.severity, Severity::Information, "{q}");
        }
        let r = analyze("ROW a = NOW() - 5 min");
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    }

    #[test]
    fn old_forms_warn_with_the_versions() {
        let r = analyze("FROM logs-* [METADATA _id] | LIMIT 1");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "[METADATA").expect("brackets");
        assert_eq!(d.severity, Severity::Warning);
        assert!(
            d.message.contains("only Elasticsearch 8.19 accepts it"),
            "{}",
            d.message
        );
        assert_eq!(d.suggestion.as_deref(), Some("METADATA _id"));
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_PARSE_ERROR)
        );
        let r = analyze("FROM a METADATA _id | COMPLETION c = p WITH my_endpoint");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "WITH endpoint").expect("with id");
        assert_eq!(d.severity, Severity::Warning);
        assert!(d.message.contains("8.19 and 9.1"), "{}", d.message);
        assert!(
            d.message.contains("\"inference_id\": \"my_endpoint\""),
            "{}",
            d.message
        );
        assert!(
            analyze_for(
                "FROM a METADATA _id | COMPLETION c = p WITH {\"inference_id\": \"e\"}",
                at("9.3")
            )
            .diagnostics
            .is_empty()
        );
    }

    #[test]
    fn command_name_spacing_follows_the_lexer() {
        let r = analyze("FROM a METADATA _id | where(b == 1)");
        let d = find(&r.diagnostics, codes::ESQL_UNAVAILABLE, "`where(`").expect("where(");
        assert_eq!(d.severity, Severity::Warning);
        assert!(
            d.message.contains("needs Elasticsearch 9.6"),
            "{}",
            d.message
        );
        assert_eq!(d.suggestion.as_deref(), Some("where ("));
        assert!(
            analyze_for("FROM a METADATA _id | where(b == 1)", at("9.6"))
                .diagnostics
                .is_empty()
        );
        assert!(
            analyze_for("FROM a METADATA _id | EVAL(x = 1)", at("9.5"))
                .diagnostics
                .iter()
                .any(|d| d.message.contains("`EVAL(`"))
        );
        assert!(codes_of("FROM a METADATA _id | where (b == 1)").is_empty());
        let r = analyze("FROM a METADATA _id | KEEP\"b\"");
        assert!(r.diagnostics.iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn cast_types_are_checked() {
        let r = analyze("ROW a = 1 | EVAL b = a::strng");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::ESQL_UNKNOWN_TYPE)
            .expect("unknown type");
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(d.suggestion.as_deref(), Some("string"));
        assert!(
            codes_of("ROW a = 1 | EVAL b = a::STRING, c = a::long, d = a::datetime").is_empty()
        );
        let r = analyze("ROW a = 1 | EVAL b = a::text");
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::ESQL_UNKNOWN_TYPE)
        );
        let r = analyze("ROW a = 1 | EVAL b = a::aggregate_metric_double");
        let d = find(
            &r.diagnostics,
            codes::ESQL_UNAVAILABLE,
            "aggregate_metric_double",
        )
        .expect("gate");
        assert_eq!(d.severity, Severity::Information);
    }

    #[test]
    fn nested_block_comments_follow_elasticsearch() {
        assert!(codes_of("FROM a /* x /* y */ z */ METADATA _id | LIMIT 1").is_empty());
        assert!(codes_of("FROM a METADATA _id /* x /* y */ | LIMIT 1").is_empty());
        assert!(
            codes_of("FROM a METADATA _id /* x */ */ | LIMIT 1")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("FROM a METADATA _id /* x /* y | LIMIT 1")
                .contains(&codes::ESQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("ROW a = 4 /* c */ / 2, b = 4/2 // end").is_empty());
    }

    #[test]
    fn keywords_cannot_name_functions() {
        let c = codes_of("ROW a = 1 | EVAL b = in(a)");
        assert!(c.contains(&codes::ESQL_PARSE_ERROR.to_string()), "{c:?}");
    }

    #[test]
    fn hover_shows_the_catalog_summary() {
        let src = "ROW a = TO_LOWER(\"X\")";
        let h = hover(src, 10).expect("function hover");
        assert!(h.contains("Lower-cases a string."), "{h}");
        let h = hover("ROW a = COPY_SIGN(1, 2)", 10).expect("hover");
        assert!(h.contains("Releases: 9.1 to 9.6."), "{h}");
    }

    #[test]
    fn signature_help_tracks_the_active_parameter() {
        let src = "FROM logs-* | EVAL x = STARTS_WITH(process.name, ";
        let help = signature_help(src, src.len()).expect("signature");
        assert_eq!(help.active_parameter, 1);
        assert!(help.signatures[0].label.starts_with("STARTS_WITH("));
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "FROM logs | WHERE user == \"\u{e9}\"";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside).is_empty());
        assert_eq!(hover(src, inside), None);
        assert!(signature_help(src, inside).is_none());
    }

    #[test]
    fn a_map_recovery_makes_up_has_no_gate() {
        let maps = |src: &str| {
            analyze(src)
                .diagnostics
                .into_iter()
                .filter(|d| d.message.contains("an empty or nested map"))
                .count()
        };
        // `{` missing: the parse error only, no hint on a map nobody wrote.
        assert_eq!(maps("FROM docs | DENSE_VECTOR embedding = WITH"), 0);
        // A written empty map keeps its gate.
        assert_eq!(maps("FROM docs | DENSE_VECTOR embedding = WITH {}"), 1);
    }

    #[test]
    fn a_name_before_a_stray_token_is_still_a_column() {
        // The problem is at `)`, after the name: `foo)` reads as `foo )` does.
        for src in [
            "FROM a | WHERE foo)",
            "FROM a | WHERE foo )",
            "FROM a | KEEP foo)",
        ] {
            let labels: Vec<String> = completions(src, src.len())
                .into_iter()
                .map(|c| c.label)
                .collect();
            assert!(labels.iter().any(|l| l == "foo"), "{src}: {labels:?}");
        }
    }

    #[test]
    fn the_line_table_answers_as_the_scan_does() {
        for source in [
            "",
            "FROM a",
            "FROM a\n| WHERE b == \"\u{e9}\u{1f600}x\"\r\n| KEEP c\n",
            "\u{e9}\n\n\u{1f600}\u{1f600}\na",
        ] {
            let lines = Lines::new(source);
            for offset in 0..=source.len() + 2 {
                let span = ByteSpan::new(offset.min(source.len()), offset);
                let expected = span_to_range(source, span);
                assert_eq!(
                    (
                        lines.position(source, span.start),
                        lines.position(source, span.end)
                    ),
                    (expected.start, expected.end),
                    "{source:?} at {offset}"
                );
            }
        }
    }

    #[test]
    fn a_syntax_error_quotes_the_token_not_the_chunk() {
        let message = |src: &str| {
            analyze(src)
                .diagnostics
                .into_iter()
                .find(|d| d.code == codes::ESQL_PARSE_ERROR)
                .map(|d| d.message)
                .unwrap_or_default()
        };
        let m = message("FROM a | WHERE x == 1)| KEEP a,b,c,d");
        assert!(m.contains("near `)`"), "{m}");
        let m = message("FROM a | WHERE (\"a\", \"b\") IN (1)");
        assert!(!m.contains("`(\"a\",`"), "{m}");
    }

    #[test]
    fn an_error_at_the_end_is_an_empty_span_after_the_last_token() {
        let d = analyze("FROM logs-* | WHERE (\n")
            .diagnostics
            .into_iter()
            .find(|d| d.code == codes::ESQL_PARSE_ERROR)
            .expect("a parse error");
        assert!(
            d.message.contains("at the end of the query"),
            "{}",
            d.message
        );
        // Right after the last token, `(`, not past the final newline: as
        // every engine reports the end of a query (#1431 follow-up).
        assert_eq!((d.range.start.line, d.range.start.character), (0, 21));
        assert_eq!((d.range.end.line, d.range.end.character), (0, 21));
    }

    /// What the analysis walk reads from each node: a join's two words, an
    /// escape's place, a command's spelling, the innermost pair of a long
    /// chain; and not the inside of a one-token node (an index name's
    /// string is no string literal).
    #[test]
    fn the_walk_reads_each_node_s_parts() {
        let found = |q: &str, code: &str| -> Vec<(u32, u32, String)> {
            analyze_for(q, at("8.19"))
                .diagnostics
                .into_iter()
                .filter(|d| d.code == code)
                .map(|d| (d.range.start.character, d.range.end.character, d.message))
                .collect()
        };
        let join = found(
            "FROM a METADATA _id | LEFT JOIN t ON x",
            codes::ESQL_UNAVAILABLE,
        );
        assert_eq!((join[0].0, join[0].1), (22, 31), "{join:?}");
        // A comment after the join's kind ends the keywords there.
        let join = found(
            "FROM a METADATA _id | LEFT /* c */ JOIN t ON x",
            codes::ESQL_UNAVAILABLE,
        );
        assert_eq!((join[0].0, join[0].1), (22, 34), "{join:?}");
        let escape = found("ROW a = \"C:\\Windows\"", codes::ESQL_PARSE_ERROR);
        assert_eq!((escape[0].0, escape[0].1), (11, 13), "{escape:?}");
        assert!(
            found("FROM \"a\\qb\" METADATA _id", codes::ESQL_PARSE_ERROR).is_empty(),
            "an index name's string is not checked as a literal"
        );
        let inline = found(
            "ROW a = 1 | INLINESTATS c = COUNT(*)",
            codes::ESQL_UNAVAILABLE,
        );
        assert!(inline[0].2.contains("`INLINESTATS`"), "{inline:?}");
        let inline = found(
            "ROW a = 1 | INLINE STATS c = COUNT(*)",
            codes::ESQL_UNAVAILABLE,
        );
        assert!(inline[0].2.contains("`INLINE STATS`"), "{inline:?}");
        assert_eq!((inline[0].0, inline[0].1), (12, 24), "both words");
        // The advisory reads the query, not what recovery left after it,
        // and INLINE STATS does not aggregate the rows away.
        for q in ["FROM a | KEEP b )", "FROM a | INLINE STATS c = COUNT(*)"] {
            assert_eq!(found(q, codes::ESQL_METADATA_ID).len(), 1, "{q}");
        }
        // A parameter names no function.
        assert!(analyze("ROW a = 1 | EVAL x = ?p(a)").diagnostics.is_empty());
        // A chain of names: the innermost pair, `a AND a`.
        let chain = format!(
            "FROM a METADATA _id | WHERE {}",
            vec!["a"; 302].join(" AND ")
        );
        let deep = found(&chain, codes::ESQL_EXPRESSION_DEPTH);
        assert_eq!((deep[0].0, deep[0].1), (28, 35), "{deep:?}");
    }

    /// Highlight, hover and the debug kinds read the tree as tree-sitter did:
    /// only a call's first node is its name, an element ends before the
    /// offset at its end, and a comment is a named node.
    #[test]
    fn highlight_hover_and_kinds_read_the_tree() {
        let tokens = analyze("ROW x = f(?p)").tokens;
        let at = |start: usize| {
            tokens
                .iter()
                .find(|t| t.span.start == start)
                .map(|t| t.capture.as_str())
        };
        assert_eq!((at(8), at(10)), (Some("function"), Some("constant")));
        assert!(debug_kinds("ROW a = 1 // c").1.contains(&"comment"));
        let q = "ROW a = 1 | WHERE a == 1";
        let eq = q.find("==").unwrap_or_default();
        assert!(hover(q, eq + 1).is_some_and(|h| h.contains("`==`")));
        assert_eq!(hover(q, eq + 2), None, "the space after `==`");
        let comment = analyze("ROW a = 1 // c").tokens;
        assert!(
            comment
                .iter()
                .any(|t| t.span.start == 10 && t.capture == "comment")
        );
        // A problem inside the query, not only at its end, hides its indices.
        assert_eq!(source_indices("FROM a | KEEP , b"), None);
        // Completions offer the names that parse, not one with a problem.
        let q = "FROM docs\n| RERANK ON title | WHERE a.b == 1 | EVAL x = ";
        let columns: Vec<String> = completions(q, q.len())
            .into_iter()
            .filter(|c| c.kind == "property")
            .map(|c| c.label)
            .collect();
        assert_eq!(columns, ["a.b", "x"]);
    }
}
