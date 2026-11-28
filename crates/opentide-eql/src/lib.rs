//! I/O-free EQL engine for Elastic Security `eql` rules: parse, the checks
//! Elasticsearch's EQL builder makes after the grammar, the function
//! catalog, highlighting, hover, completion, and signature help.
//!
//! Builder checks follow `x-pack/plugin/eql/.../parser/LogicalPlanBuilder.java`
//! and `AbstractBuilder.java`: `maxspan` units, `runs`, sequence and sample
//! sizes, missing events, pipes, and Endgame syntax Elasticsearch rejects.
//! `semantics` adds the Verifier's literal type checks and the planner's
//! field-versus-field rule; `lexical` follows the lexer where the grammar
//! cannot (nested block comments, the expression-depth pre-scan).
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
// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads user queries: every slice is checked or says why it is safe (#1946;
// the lint moves to `[workspace.lints]` once every crate is clean).
#![warn(clippy::string_slice)]
/// The typed AST `cargo xtask codegen` writes from `eql.ungram`. Public but hidden, as SPL's
/// and KQL's, so that the accessors no check reads yet are not dead code.
#[doc(hidden)]
#[path = "generated/ast.rs"]
pub mod ast;
mod ast_ext;
mod builder;
mod ecs;
mod highlight;
// The lexer, the comment pre-scan, the parser and the kinds: public but hidden, as the typed
// AST, for the crate's corpus, tree and conformance tests (`tests/`). Not an API.
#[doc(hidden)]
pub mod lexer;
#[doc(hidden)]
pub mod lexical;
mod nav;
mod parsed;
#[doc(hidden)]
pub mod parser;
mod regex;
mod semantics;
#[doc(hidden)]
pub mod syntax;

pub use ecs::ecs_diagnostics;

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, ParameterInformation, Range, SignatureHelp,
    SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_parse::ast::AstNode;
use serde::Deserialize;
use std::sync::OnceLock;
use syntax::SyntaxKind as K;

/// `text[start..end]`, a range this crate computes: a token's bounds, a
/// character's, or an ASCII byte's, so its ends are char boundaries. A range
/// that is not fails a debug assertion and reads as empty.
pub(crate) fn cut(text: &str, start: usize, end: usize) -> &str {
    let piece = text.get(start..end);
    debug_assert!(piece.is_some(), "{start}..{end} in {} bytes", text.len());
    piece.unwrap_or_default()
}
#[doc(hidden)]
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

fn functions_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/eql/functions.toml")
}
fn pipes_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/eql/pipes.toml")
}

const SYNTAX_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax";

/// Units `LogicalPlanBuilder.visitSequenceParams` accepts.
const MAXSPAN_UNITS: &[(&str, u64)] = &[
    ("ms", 1),
    ("s", 1_000),
    ("m", 60_000),
    ("h", 3_600_000),
    ("d", 86_400_000),
];

const MAX_RUNS: u64 = 100;
/// A sequence expands to at most this many queries after `runs`.
const MAX_SEQUENCE_QUERIES: u64 = 256;
const KEYWORD_WORDS: &[&str] = &[
    "and", "any", "by", "false", "in", "join", "like", "maxspan", "not", "null", "of", "or",
    "regex", "sample", "sequence", "true", "until", "where", "with",
];
const MAX_SAMPLE_QUERIES: usize = 5;

#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize), serde(deny_unknown_fields))]
struct FunctionsFile {
    functions: Vec<FunctionRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub returns: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    /// Argument counts the function registry accepts; `max_args` absent is unbounded.
    #[serde(default)]
    pub min_args: usize,
    #[serde(default)]
    pub max_args: Option<usize>,
    #[serde(default)]
    pub citation: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParamRow {
    pub name: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize), serde(deny_unknown_fields))]
struct PipesFile {
    pipes: Vec<PipeRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipeRow {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub citation: Option<String>,
}

#[derive(Debug)]
pub struct Catalog {
    pub functions: Vec<FunctionRow>,
    pub pipes: Vec<PipeRow>,
}

/// Reads the compiled-in files item by item ([`opentide_core::catalog`]).
fn files() -> (FunctionsFile, PipesFile) {
    use opentide_core::catalog::{array_items, compiled_in};
    let functions = FunctionsFile {
        functions: compiled_in(
            "data/catalogs/eql/functions.toml",
            array_items(functions_toml(), "functions"),
        ),
    };
    let pipes = PipesFile {
        pipes: compiled_in(
            "data/catalogs/eql/pipes.toml",
            array_items(pipes_toml(), "pipes"),
        ),
    };
    (functions, pipes)
}

impl Catalog {
    pub fn cached() -> &'static Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| {
            let (functions, pipes) = files();
            Catalog {
                functions: functions.functions,
                pipes: pipes.pipes,
            }
        })
    }

    /// The registry resolves function names case-insensitively: Elastic's own
    /// rules write `cidrmatch`. Matching *behaviour* is case-sensitive unless
    /// the call uses `~`.
    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        self.functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    pub fn pipe(&self, name: &str) -> Option<&PipeRow> {
        self.pipes.iter().find(|p| p.name == name)
    }
}

/// Keywords and operators with a syntax-reference anchor, for hover.
const KEYWORDS: &[(&str, &str, &str)] = &[
    (
        "sequence",
        "Matches an ordered series of events.",
        "eql-sequences",
    ),
    (
        "sample",
        "Matches events that share join keys, in any order.",
        "eql-samples",
    ),
    (
        "by",
        "Join keys: events must share these field values.",
        "eql-by-keyword",
    ),
    (
        "maxspan",
        "Time span a sequence must fit in. Units: `ms`, `s`, `m`, `h`, `d`.",
        "eql-with-maxspan-keywords",
    ),
    (
        "until",
        "Expiration event: a sequence that has not completed when it matches is discarded.",
        "eql-until-keyword",
    ),
    (
        "runs",
        "Repeat the preceding sequence query `runs` times (1 to 100).",
        "eql-with-runs-statement",
    ),
    (
        "any",
        "Matches events of any category.",
        "eql-syntax-match-any-event-category",
    ),
    ("where", "Event condition.", "eql-basic-syntax"),
    (
        ":",
        "Case-insensitive equality with `*` and `?` wildcards. Same as `like~`.",
        "eql-syntax-comparison-operators",
    ),
    (
        "like",
        "Case-sensitive wildcard match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "like~",
        "Case-insensitive wildcard match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "regex",
        "Case-sensitive regular expression match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "regex~",
        "Case-insensitive regular expression match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "in",
        "Case-sensitive membership in a list.",
        "eql-syntax-lookup-operators",
    ),
    (
        "in~",
        "Case-insensitive membership in a list.",
        "eql-syntax-lookup-operators",
    ),
    (
        "![",
        "Missing event: the sequence matches only when no such event occurs. Needs `maxspan`.",
        "eql-missing-events",
    ),
    (
        "?",
        "Optional field: a missing field reads as `null` instead of failing the query.",
        "eql-syntax-optional-fields",
    ),
];

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Parses `source` as Elasticsearch reads it (the lexer ends a block comment where its lexer
/// does, nested ones too), with what `lexical` finds about its comments.
fn parse_prepared(source: &str) -> Option<(parsed::Parsed, lexical::Prepared)> {
    let prepared = lexical::prepare(source);
    Some((parsed::parse(source), prepared))
}

thread_local! {
    /// The steps of the analysis's inner loops on this thread: [`steps`].
    static STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one step of an inner loop: a child looked at for a span or hover, an operand typed,
/// a run level folded, a parent climbed.
pub(crate) fn step() {
    STEPS.set(STEPS.get().wrapping_add(1));
}

/// How many steps of its inner loops the analysis has taken on this thread. For the tests that
/// hold the work to linear in the query (`tests/analysis_runs.rs`): counted, not timed, so the
/// checks are deterministic. Not API.
#[doc(hidden)]
pub fn steps() -> usize {
    STEPS.get()
}

#[cfg(test)]
thread_local! {
    /// The elements the analysis's walk visited on this thread: [`visits`].
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one element the analysis's walk visited, in tests (ADR 0014 §7).
#[inline]
pub(crate) fn count_visit() {
    #[cfg(test)]
    VISITS.set(VISITS.get() + 1);
}

/// How many elements the analysis's walk visited on this thread.
#[cfg(test)]
fn visits() -> usize {
    VISITS.get()
}

/// Analyze an EQL query: its diagnostics and highlight tokens. The findings'
/// ranges come from one line table ([`opentide_core::with_line_index`]).
pub fn analyze(source: &str) -> AnalyzeResult {
    opentide_core::with_line_index(source, || analyze_lines(source))
}

/// The EQL [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Eql
    }

    fn analyze_for(
        &self,
        source: &str,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> opentide_highlight::AnalyzeResult {
        let r = analyze(source);
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }

    fn hover(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Option<String> {
        hover(source, offset)
    }

    fn completions(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Vec<opentide_core::CompletionItem> {
        completions(source, offset)
    }

    fn signature_help(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Option<opentide_core::SignatureHelp> {
        signature_help(source, offset)
    }
}

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
fn analyze_lines(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    let catalog = Catalog::cached();
    let Some((parsed, prepared)) = parse_prepared(source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "failed to initialize the EQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let mut out = Vec::new();
    if let Some(problem) = parsed.problems.first() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            parse_error_message(problem, source),
            range(source, problem.token),
        ));
    }
    check_comments(&prepared.comments, source, &mut out);
    if let Some(span) = highlight::expression_depth_exceeded(&parsed.syntax, source) {
        out.push(Diagnostic::warning(
            codes::EQL_EXPRESSION_DEPTH,
            format!(
                "expression nesting exceeds {} levels (parentheses plus chained `not`/`-`/`+`): Elasticsearch 8.19.17+, 9.3.5+, 9.4.3+, and 9.5 reject this query; earlier patches and 9.0 to 9.2 accept it",
                lexical::MAX_EXPRESSION_DEPTH
            ),
            range(source, span),
        ));
    }
    let mut translated = semantics::Translated::default();
    semantics::forget_types();
    // One walk over every element: the checks read the nodes, the highlight
    // the tokens (ADR 0014 §5a).
    let mut spans = Vec::new();
    for element in parsed.syntax.descendants_with_tokens() {
        count_visit();
        match element {
            rowan::NodeOrToken::Node(node) => {
                check_node(&node, &parsed, &mut translated, source, catalog, &mut out);
            }
            rowan::NodeOrToken::Token(token) => spans.extend(highlight::capture_of(&token)),
        }
    }
    semantics::forget_types();
    if let Some(root) = ast::SourceFile::cast(parsed.syntax.clone()) {
        builder::check_pipes(&root, source, catalog, &mut out);
    }
    let tokens = highlight_spans(spec, source, spans);
    AnalyzeResult {
        diagnostics: out,
        tokens,
    }
}

fn check_comments(found: &[lexical::CommentFinding], source: &str, out: &mut Vec<Diagnostic>) {
    for finding in found {
        out.push(match finding {
            lexical::CommentFinding::Nested(span) => Diagnostic::warning(
                codes::EQL_NESTED_COMMENT,
                "Elasticsearch nests block comments, so this comment runs past its first `*/`; other EQL tools end it there. Avoid `/*` inside a comment",
                range(source, *span),
            ),
            lexical::CommentFinding::NotAComment(span) => Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "Elasticsearch nests block comments and finds no `*/` closing this one, so it reads `/` and `*` as operators",
                range(source, *span),
            ),
        });
    }
}

/// The parser's first error, worded for a reader: the token it stopped at and what it
/// expected there.
fn parse_error_message(problem: &parsed::Problem, source: &str) -> String {
    if problem.too_deep {
        return format!("EQL syntax error: {}", problem.message);
    }
    let near = source
        .get(problem.token.start..problem.token.end)
        .unwrap_or("")
        .trim();
    if near.starts_with('=') && !near.starts_with("==") {
        return "EQL syntax error: use `==` for equality; `=` is not a comparison".into();
    }
    // The lexer cuts an unclosed `/*` as `/` and `*`: name the comment, not the operator.
    if problem.token.end > problem.token.start
        && source
            .get(problem.token.start..)
            .is_some_and(|rest| rest.starts_with("/*"))
    {
        return "EQL syntax error: this `/*` comment is never closed".into();
    }
    // A quote the lexer could not close is a token of its own.
    match near {
        "\"" | "'" => return format!("EQL syntax error: this {near} string is never closed"),
        "`" => return "EQL syntax error: this ` quoted name is never closed".into(),
        _ => {}
    }
    let expected = problem
        .expected
        .as_deref()
        .map(|e| format!("; expected {e}"))
        .unwrap_or_default();
    if near.is_empty() {
        return format!("EQL syntax error: the query ends too early{expected}");
    }
    let lower = near.to_ascii_lowercase();
    if KEYWORD_WORDS.contains(&lower.as_str()) && near != lower {
        format!("EQL syntax error near `{near}`: keywords are lower case (`{lower}`)")
    } else {
        format!("EQL syntax error near `{near}`{expected}")
    }
}

/// Runs `check` on `node` as the typed node `N`.
fn with_ast<N: AstNode<Language = Lang>>(node: &SyntaxNode, check: impl FnOnce(N)) {
    if let Some(n) = N::cast(node.clone()) {
        check(n);
    }
}

fn check_node(
    node: &SyntaxNode,
    parsed: &parsed::Parsed,
    translated: &mut semantics::Translated,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    let kind = node.kind();
    let expression = matches!(
        kind,
        K::COMPARISON
            | K::PREDICATE_EXPRESSION
            | K::UNARY_EXPRESSION
            | K::NOT_EXPRESSION
            | K::FUNCTION_CALL
    );
    // An expression the parser could not finish (`startsWith(a, `) is not checked further: its
    // arity and types are those of a fragment, and the syntax error already says what is wrong.
    // (A span is a walk down the node's edges: worth it only when the parser found a problem.)
    if expression && parsed.has_problems() && parsed.broken(nav::span(node)) {
        return;
    }
    match kind {
        K::STRING => with_ast(node, |n| builder::check_string(&n, source, out)),
        K::INDEX | K::JOIN | K::RELATIONSHIP => builder::check_shape(node, source, out),
        K::FIELD => with_ast(node, |n| builder::check_field_case(&n, source, out)),
        K::EVENT_CATEGORY => with_ast(node, |n| builder::check_category_case(&n, source, out)),
        K::COMPARISON => with_ast(node, |n: ast::Comparison| {
            builder::check_comparison_wildcard(&n, source, out);
            semantics::check_comparison_fields(&n, translated, source, out);
        }),
        K::PREDICATE_EXPRESSION => with_ast(node, |n: ast::PredicateExpression| {
            builder::check_predicate_wildcard(&n, source, out);
            regex::check_regex(&n, source, out);
            semantics::check_predicate_types(&n, source, out);
            semantics::check_predicate_fields(&n, translated, source, out);
        }),
        // A run is checked at each level Elasticsearch's builder nests it in, the outermost
        // first; a level that holds a syntax error is not.
        K::BINARY_EXPRESSION | K::AND_EXPRESSION | K::OR_EXPRESSION => {
            let run = semantics::Run::of(node);
            for level in (0..run.len()).rev() {
                if parsed.broken(run.span(level)) {
                    continue;
                }
                if kind == K::BINARY_EXPRESSION {
                    semantics::check_level_types(&run, level, source, out);
                } else {
                    semantics::check_level_conditions(&run, level, source, out);
                }
            }
        }
        K::UNARY_EXPRESSION => with_ast(node, |n| semantics::check_unary_types(&n, source, out)),
        K::NOT_EXPRESSION => with_ast(node, |n: ast::NotExpression| {
            semantics::check_condition(n.operand(), source, out);
        }),
        K::EVENT_QUERY => with_ast(node, |n: ast::EventQuery| {
            semantics::check_condition(n.condition(), source, out);
        }),
        K::FUNCTION_CALL => with_ast(node, |n| {
            if builder::check_function(&n, source, catalog, out) {
                semantics::check_call_types(&n, source, out);
            }
        }),
        K::SEQUENCE => with_ast(node, |n| builder::check_sequence(&n, source, out)),
        K::SAMPLE => with_ast(node, |n| builder::check_sample(&n, source, out)),
        K::SUBQUERY => {
            with_ast(node, |n: ast::Subquery| {
                semantics::check_condition(n.condition(), source, out);
            });
            builder::check_shape(node, source, out);
        }
        _ => {}
    }
}

fn range(source: &str, span: ByteSpan) -> Range {
    span_to_range(source, span)
}

/// Each token's capture (`highlight::captures`), a known function's as `function.builtin`.
#[cfg(test)]
fn highlight(spec: &HighlightSpec, source: &str, root: &syntax::SyntaxNode) -> Vec<HighlightToken> {
    highlight_spans(spec, source, highlight::captures(root))
}

/// The semantic tokens of `spans`, with a catalog function's call marked a builtin.
fn highlight_spans(
    spec: &HighlightSpec,
    source: &str,
    mut spans: Vec<(ByteSpan, &'static str)>,
) -> Vec<HighlightToken> {
    let catalog = Catalog::cached();
    for (span, capture) in &mut spans {
        let name = source.get(span.start..span.end).unwrap_or("");
        if *capture == "function" && catalog.function(name.trim_end_matches('~')).is_some() {
            *capture = "function.builtin";
        }
    }
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
}

/// One `sequence` in a query, for rule-level checks such as Tide's
/// scheduling advisories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceInfo {
    /// The `sequence` keyword.
    pub span: ByteSpan,
    /// `with maxspan=...`, when the sequence has one.
    pub maxspan: Option<Maxspan>,
}

/// A sequence's `maxspan` clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Maxspan {
    /// The value and unit (`5m`).
    pub span: ByteSpan,
    /// Length in milliseconds; `None` when Elasticsearch rejects the value
    /// (`eql_maxspan_unit` reports why).
    pub millis: Option<u64>,
}

/// Every `sequence` in the query, with its `maxspan` in milliseconds.
pub fn sequences(source: &str) -> Vec<SequenceInfo> {
    let Some((parsed, _)) = parse_prepared(source) else {
        return Vec::new();
    };
    parsed
        .syntax
        .descendants()
        .filter_map(ast::Sequence::cast)
        .map(|sequence| {
            let maxspan = sequence
                .params()
                .next()
                .and_then(|p| p.maxspan())
                .map(|unit| Maxspan {
                    span: nav::span(unit.syntax()),
                    millis: maxspan_millis(&unit, source),
                });
            SequenceInfo {
                span: nav::first_child_span(sequence.syntax()),
                maxspan,
            }
        })
        .collect()
}

fn maxspan_millis(unit: &ast::TimeUnit, source: &str) -> Option<u64> {
    let value = unit
        .value()
        .and_then(|v| nav::text(v.syntax(), source).parse::<u64>().ok())
        .filter(|v| *v > 0)?;
    let suffix = nav::text(unit.unit()?.syntax(), source);
    let factor = MAXSPAN_UNITS.iter().find(|(n, _)| *n == suffix)?.1;
    Some(value.saturating_mul(factor))
}

/// Each valid `with maxspan=` in the query: its span and length in
/// milliseconds. Tide compares these with the rule's `scheduling`
/// ([elastic-1.0] Advisories). [`sequences`] also lists sequences without one.
pub fn sequence_maxspans(source: &str) -> Vec<(ByteSpan, u64)> {
    sequences(source)
        .into_iter()
        .filter_map(|s| s.maxspan)
        .filter_map(|m| m.millis.map(|ms| (m.span, ms)))
        .collect()
}

// ---- Hover ----------------------------------------------------------------

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset) {
        return None;
    }
    let (parsed, _) = parse_prepared(source)?;
    let (word, parent) = nav::element_at(&parsed.syntax, offset, source);
    let catalog = Catalog::cached();
    if parent == Some(K::FUNCTION_CALL) {
        let name = word.trim_end_matches('~');
        if let Some(row) = catalog.function(name) {
            return Some(function_hover(row));
        }
    }
    if parent == Some(K::PIPE_STAGE)
        && let Some(row) = catalog.pipe(word)
    {
        let mut md = format!(
            "**{}** (pipe)\n\n```eql\n{}\n```\n\n{}",
            row.name, row.signature, row.docs
        );
        if let Some(c) = &row.citation {
            md.push_str(&format!("\n\n[Elastic docs]({c})"));
        }
        return Some(md);
    }
    KEYWORDS
        .iter()
        .find(|(k, _, _)| *k == word)
        .map(|(k, doc, anchor)| {
            format!("**`{k}`**\n\n{doc}\n\n[Elastic docs]({SYNTAX_DOCS}#{anchor})")
        })
}

/// ` _string | null_`, or nothing when the docs list no types.
fn types_suffix(p: &ParamRow) -> String {
    if p.types.is_empty() {
        String::new()
    } else {
        format!(" _{}_", p.types.join(" | "))
    }
}

/// One parameter's description and accepted types, for signature help.
fn parameter_doc(p: &ParamRow) -> String {
    format!("{}{}", p.docs, types_suffix(p)).trim().to_string()
}

fn function_hover(row: &FunctionRow) -> String {
    let mut md = format!(
        "**{}** (function)\n\n```eql\n{}\n```",
        row.name, row.signature
    );
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    if !row.parameters.is_empty() {
        md.push_str("\n\n**Parameters**\n");
        for p in &row.parameters {
            let optional = if p.required { "" } else { " (optional)" };
            let types = types_suffix(p);
            let docs = if p.docs.is_empty() {
                String::new()
            } else {
                format!(" — {}", p.docs)
            };
            md.push_str(&format!("\n- `{}`{optional}{types}{docs}", p.name));
        }
    }
    if !row.returns.is_empty() {
        md.push_str(&format!("\n\n**Returns** _{}_", row.returns.join(" | ")));
    }
    if row.case_insensitive {
        md.push_str(&format!("\n\nCase-insensitive form: `{}~(...)`.", row.name));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

// ---- Completion -----------------------------------------------------------

/// ECS `event.category` values, the usual EQL event categories.
const EVENT_CATEGORIES: &[&str] = &[
    "any",
    "api",
    "authentication",
    "configuration",
    "database",
    "driver",
    "email",
    "file",
    "host",
    "iam",
    "intrusion_detection",
    "library",
    "malware",
    "network",
    "package",
    "process",
    "registry",
    "session",
    "threat",
    "vulnerability",
    "web",
];

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    let trimmed = before.trim_end();
    if trimmed.is_empty() {
        let mut items: Vec<CompletionItem> = ["sequence", "sample"]
            .iter()
            .map(|k| CompletionItem::new(*k, "keyword"))
            .collect();
        items.extend(
            EVENT_CATEGORIES
                .iter()
                .map(|c| CompletionItem::new(*c, "type")),
        );
        return items;
    }
    if trimmed.ends_with('|') {
        return catalog
            .pipes
            .iter()
            .map(|p| {
                CompletionItem::new(p.name.clone(), "command")
                    .with_detail(p.signature.clone())
                    .with_docs(p.docs.clone())
            })
            .collect();
    }
    if trimmed.ends_with('[') {
        return EVENT_CATEGORIES
            .iter()
            .map(|c| CompletionItem::new(*c, "type"))
            .collect();
    }
    if trimmed.ends_with("maxspan=") {
        return MAXSPAN_UNITS
            .iter()
            .map(|(u, _)| CompletionItem::new(format!("1{u}"), "enum"))
            .collect();
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .map(|f| {
            CompletionItem::new(f.name.clone(), "function")
                .with_detail(f.signature.clone())
                .with_docs(function_hover(f))
        })
        .collect();
    for kw in [
        "and", "or", "not", "in", "in~", "like", "like~", "regex", "regex~", "where", "by", "with",
        "until",
    ] {
        items.push(CompletionItem::new(kw, "keyword"));
    }
    items.extend(
        fields_in(source)
            .into_iter()
            .map(|f| CompletionItem::new(f, "property")),
    );
    items
}

fn fields_in(source: &str) -> Vec<String> {
    let Some((parsed, _)) = parse_prepared(source) else {
        return Vec::new();
    };
    let names: std::collections::BTreeSet<String> = parsed
        .syntax
        .descendants()
        .filter(|node| node.kind() == K::FIELD && !parsed.broken(nav::span(node)))
        .map(|node| nav::text(&node, source).trim_start_matches('?').to_string())
        .collect();
    names.into_iter().collect()
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
    let row = Catalog::cached().function(name.trim_end_matches('~'))?;
    let parameters: Vec<ParameterInformation> = row
        .parameters
        .iter()
        .map(|p| ParameterInformation {
            label: format!("<{}>", p.name),
            documentation: Some(parameter_doc(p)),
        })
        .collect();
    let active = active.min(parameters.len().saturating_sub(1) as u32);
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: row.signature.clone(),
            documentation: Some(row.docs.clone()),
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    })
}

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
    // `open` is a `(` byte, and the word before it starts on a char.
    let head = cut(before, 0, open);
    let name_start =
        opentide_core::word_start(head, |c| c.is_ascii_alphanumeric() || c == '_' || c == '~');
    let name = cut(head, name_start, head.len()).to_string();
    (!name.is_empty()).then_some((name, commas))
}

/// Whether `source` parses without an error: the parse alone, with no
/// analysis, for the throughput benchmark (`cargo bench --bench throughput`, ADR
/// 0014). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn parses(source: &str) -> bool {
    parser::parse(source).errors.is_empty()
}

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<syntax::Lang>(&parser::parse(source))
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<syntax::Lang>(&parser::parse(source))
}

/// The `Debug` names of the node kinds the grammar declares, the error node
/// left out: the productions the corpus gate of `opentide-analysis` asks a
/// fixture of. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_node_kinds() -> Vec<String> {
    syntax::node_kinds()
}

#[cfg(test)]
mod tests {
    use super::*;

    use opentide_core::Severity;

    /// The item-by-item read is field for field the whole-file parse (ADR 0013).
    #[test]
    fn the_catalogs_read_item_by_item_are_the_whole_files() {
        let (functions, pipes) = files();
        let whole: FunctionsFile = toml::from_str(functions_toml()).unwrap();
        assert_eq!(format!("{functions:?}"), format!("{whole:?}"));
        let whole: PipesFile = toml::from_str(pipes_toml()).unwrap();
        assert_eq!(format!("{pipes:?}"), format!("{whole:?}"));
    }

    /// Codes of errors, warnings, and information; hints are left out.
    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity != Severity::Hint)
            .map(|d| d.code)
            .collect()
    }

    /// The first syntax error's message, as `analyze` words it.
    fn parse_error(src: &str) -> String {
        analyze(src)
            .diagnostics
            .into_iter()
            .find(|d| d.code == codes::EQL_PARSE_ERROR)
            .map(|d| d.message)
            .unwrap_or_default()
    }

    /// The hints the tree-sitter engine gave stay: `=` for `==`, and upper-case keywords
    /// (#1408 review). The parser adds what it expected.
    #[test]
    fn syntax_errors_keep_their_hints_and_say_what_was_expected() {
        assert_eq!(
            parse_error("process where a = 1"),
            "EQL syntax error: use `==` for equality; `=` is not a comparison"
        );
        assert_eq!(
            parse_error("process where a == 1 AND b == 2"),
            "EQL syntax error near `AND`: keywords are lower case (`and`)"
        );
        assert_eq!(
            parse_error("sequence WITH maxspan=1m [a where true] [b where true]"),
            "EQL syntax error near `WITH`: keywords are lower case (`with`)"
        );
        let early = parse_error("process where a ==");
        assert!(
            early.starts_with("EQL syntax error: the query ends too early; expected "),
            "{early}"
        );
        assert_eq!(
            parse_error("process where /* unterminated true"),
            "EQL syntax error: this `/*` comment is never closed"
        );
        for (unclosed, message) in [
            ("process where a == \"x", "this \" string is never closed"),
            ("process where a == 'x", "this ' string is never closed"),
            (
                "process where a == \"\"\"x",
                "this \" string is never closed",
            ),
            (
                "process where `a == 1",
                "this ` quoted name is never closed",
            ),
        ] {
            assert_eq!(
                parse_error(unclosed),
                format!("EQL syntax error: {message}"),
                "{unclosed}"
            );
        }
        let near = parse_error("process where a == 1)");
        assert!(
            near.starts_with("EQL syntax error near `)`; expected ") && near.contains("`and`"),
            "{near}"
        );
    }

    /// #180: a backslash before a multi-byte character panicked.
    #[test]
    fn an_invalid_escape_of_a_multi_byte_character_is_one_error_on_it() {
        for (src, escaped) in [
            (r#"process where a == "x\é""#, "é"),
            (r#"process where a == "D:\日本""#, "日"),
            (r#"process where a == "tab\😀t""#, "😀"),
        ] {
            let found = analyze(src).diagnostics;
            let errors: Vec<_> = found
                .iter()
                .filter(|d| d.code == codes::EQL_PARSE_ERROR)
                .collect();
            assert_eq!(errors.len(), 1, "{src}: {found:?}");
            assert!(
                errors[0].message.contains(&format!("`\\{escaped}`")),
                "{src}: {}",
                errors[0].message
            );
            let line = src.lines().next().unwrap();
            let start = errors[0].range.start.character as usize;
            let end = errors[0].range.end.character as usize;
            let utf16: Vec<u16> = line.encode_utf16().collect();
            assert_eq!(
                String::from_utf16(&utf16[start..end]).unwrap(),
                format!("\\{escaped}")
            );
        }
    }

    #[test]
    fn cidr_match_on_a_non_ip_ecs_field_is_a_hint() {
        let found = with_severity(r#"network where cidrMatch(host.name, "10.0.0.0/8")"#);
        assert_eq!(
            found,
            vec![(codes::EQL_ARGUMENT_TYPE.to_string(), Severity::Hint)]
        );
        assert!(with_severity(r#"network where cidrMatch(source.ip, "10.0.0.0/8")"#).is_empty());
        assert!(with_severity(r#"network where cidrMatch(my.custom, "10.0.0.0/8")"#).is_empty());
    }

    fn with_severity(src: &str) -> Vec<(String, Severity)> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| (d.code, d.severity))
            .collect()
    }

    #[test]
    fn detection_rule_is_clean() {
        let src = "sequence by host.id with maxspan=1m\n  [process where event.type == \"start\" and process.name : \"cmd.exe\"]\n  [network where startsWith~(process.name, \"cmd\")]";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "function.builtin"));
    }

    #[test]
    fn maxspan_units_follow_the_builder() {
        let c = codes_of("sequence with maxspan=5w [process where true] [file where true]");
        assert!(c.contains(&codes::EQL_MAXSPAN_UNIT.to_string()), "{c:?}");
        let c = codes_of("sequence with maxspan=5 [process where true] [file where true]");
        assert!(c.contains(&codes::EQL_MAXSPAN_UNIT.to_string()), "{c:?}");
        assert!(
            codes_of("sequence with maxspan=500ms [process where true] [file where true]")
                .is_empty()
        );
    }

    #[test]
    fn maxspans_are_in_milliseconds() {
        let spans = sequence_maxspans("sequence with maxspan=500ms [a where true] [b where true]");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1, 500);
        let spans = sequence_maxspans("sequence with maxspan=2h [a where true] [b where true]");
        assert_eq!(spans[0].1, 7_200_000);
    }

    #[test]
    fn endgame_syntax_is_unsupported() {
        assert!(
            codes_of("process where process.name == 'cmd.exe'")
                .contains(&codes::EQL_PARSE_ERROR.to_string()),
            "single quotes are a lexer error in Elasticsearch"
        );
        for src in [
            "process where descendant of [process where true]",
            "process where true | unique process.name",
            "join [process where true] [file where true]",
        ] {
            assert!(
                codes_of(src).contains(&codes::EQL_UNSUPPORTED.to_string()),
                "{src}"
            );
        }
    }

    #[test]
    fn functions_resolve_case_insensitively_and_tilde_is_checked() {
        assert!(
            codes_of("process where startsWth(process.name, \"a\")")
                .contains(&codes::EQL_UNKNOWN_FUNCTION.to_string())
        );
        assert!(
            codes_of("process where startswith(process.name, \"a\")").is_empty(),
            "the registry ignores case"
        );
        assert!(
            codes_of("process where add~(1, 2) == 3")
                .contains(&codes::EQL_UNKNOWN_FUNCTION.to_string())
        );
        assert!(codes_of("process where endsWith~(process.name, \".EXE\")").is_empty());
    }

    #[test]
    fn sequence_shape_checks() {
        assert!(
            codes_of("sequence [process where true]").contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("sequence [process where true] ![file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("sequence [process where true] with runs=2").is_empty());
        assert!(
            codes_of("sequence [process where true] with runs=101 [file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where true | head 5").is_empty());
        // A Java `int`: 2147483647 runs, 2147483648 fails (Elasticsearch 9.5.5).
        assert!(codes_of("process where true | head 2147483647").is_empty());
        assert!(
            codes_of("process where true | head 2147483648")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("process where true | head").contains(&codes::EQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn elasticsearch_builder_and_lexer_rules() {
        assert!(
            codes_of("process where cidrmatch(source.ip, \"10.0.0.0/8\")").is_empty(),
            "names resolve case-insensitively"
        );
        assert!(
            codes_of("process where length(a, b) > 1")
                .contains(&codes::EQL_FUNCTION_ARITY.to_string())
        );
        assert!(
            codes_of("process where between(a, \"x\") == \"\"")
                .contains(&codes::EQL_FUNCTION_ARITY.to_string())
        );
        assert!(
            codes_of("process where file.path == \"C:\\Windows\"")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where file.path == \"C:\\\\Windows\"").is_empty());
        assert!(codes_of("process where file.path == \"\"\"C:\\Windows\"\"\"").is_empty());
        assert!(
            codes_of("process where process.args[0] == \"x\"")
                .contains(&codes::EQL_UNSUPPORTED.to_string())
        );
        assert!(codes_of("PROCESS where true").contains(&codes::EQL_CASE_SENSITIVE.to_string()));
        assert!(
            codes_of("process where x == TRUE").contains(&codes::EQL_CASE_SENSITIVE.to_string())
        );
        assert!(
            codes_of("process where process.name == \"*.exe\"")
                .contains(&codes::EQL_LITERAL_WILDCARD.to_string())
        );
        assert!(
            codes_of("process where process.name in (\"a\", \"*.exe\")")
                .contains(&codes::EQL_LITERAL_WILDCARD.to_string())
        );
        assert!(codes_of("process where process.name : \"*.exe\"").is_empty());
        assert!(codes_of("process where file.path == \"\\\\*\\\\ADMIN$\"").is_empty());
        assert!(
            codes_of("sequence by a [x where true] by b [y where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("sequence [x where true] by a [y where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where like == 1").contains(&codes::EQL_PARSE_ERROR.to_string()));
    }

    #[test]
    fn keywords_are_case_sensitive() {
        assert!(
            codes_of("SEQUENCE [process where true] [file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn hover_and_signature_help() {
        let src = "process where startsWith~(process.name, \"a\")";
        let h = hover(src, 16).expect("hover");
        assert!(h.contains("startsWith") && h.contains("elastic.co"), "{h}");
        let partial = "process where between(file.path, \"a\", ";
        let help = signature_help(partial, partial.len()).expect("signature");
        assert_eq!(help.active_parameter, 2);
        let h = hover("sequence [a where true] [b where true]", 2).expect("keyword");
        assert!(h.contains("sequence"));
    }

    #[test]
    fn completion_contexts() {
        assert!(completions("", 0).iter().any(|i| i.label == "sequence"));
        assert!(
            completions("process where true | ", 21)
                .iter()
                .any(|i| i.label == "head")
        );
        let src = "process where ";
        assert!(
            completions(src, src.len())
                .iter()
                .any(|i| i.label == "stringContains")
        );
    }

    fn has(src: &str, code: &str, severity: Severity) -> bool {
        with_severity(src)
            .iter()
            .any(|(c, s)| c == code && *s == severity)
    }

    #[test]
    fn nested_comments_follow_elasticsearch() {
        // Elasticsearch accepts this; the grammar alone would stop at the
        // first `*/` and fail on `still comment */`.
        let src = "process where /* outer /* inner */ still comment */ true";
        let found = with_severity(src);
        assert_eq!(
            found,
            vec![(codes::EQL_NESTED_COMMENT.to_string(), Severity::Warning)]
        );
        // Highlighting sees one comment over the whole nested span.
        let r = analyze(src);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "comment" && t.span == ByteSpan::new(14, 51)),
            "{:?}",
            r.tokens
        );
        // An inner `/*` with no second `*/` ends at the only `*/`, as in
        // Elasticsearch; nothing to report.
        assert!(codes_of("process where /* a /* b */ true").is_empty());
        assert!(codes_of("process where /* a */ true").is_empty());
    }

    #[test]
    fn expression_depth_is_a_versioned_warning() {
        let deep = format!("process where {}true{}", "(".repeat(251), ")".repeat(251));
        let found = with_severity(&deep);
        assert_eq!(
            found,
            vec![(codes::EQL_EXPRESSION_DEPTH.to_string(), Severity::Warning)]
        );
        let ok = format!("process where {}true{}", "(".repeat(250), ")".repeat(250));
        assert!(codes_of(&ok).is_empty());
        // Chains of prefix `not` count; comments between them do not break
        // the chain, other tokens do.
        let nots = format!("process where {}true", "not /* c */ ".repeat(251));
        assert!(codes_of(&nots).contains(&codes::EQL_EXPRESSION_DEPTH.to_string()));
        let reset = format!("process where {}a == 1", "not ".repeat(200));
        assert!(codes_of(&reset).is_empty());
    }

    #[test]
    fn literal_argument_types_follow_the_verifier() {
        for src in [
            "process where cidrMatch(\"10.0.0.1\", \"10.0.0.0/8\")",
            "process where cidrMatch(source.ip, 10)",
            "process where length(1) > 0",
            "process where substring(process.name, \"1\") == \"x\"",
            "process where substring(process.name, 1.5) == \"x\"",
            "process where between(file.path, \"a\", \"b\", \"true\") == \"x\"",
            "process where startsWith(process.name, 1)",
            "process where indexOf(process.name, \"a\", \"0\") == 1",
            "process where number(1) == 1",
            "process where substring(process.name, number(\"1\")) == \"x\"",
            "process where length(length(process.name)) == 1",
        ] {
            assert!(
                has(src, codes::EQL_ARGUMENT_TYPE, Severity::Error),
                "{src}: {:?}",
                with_severity(src)
            );
        }
        // Operator operands: the same Verifier rule. Live clusters 8.19-9.5
        // reject every one, `EventID:4624` included.
        for src in [
            "process where process.name : 1",
            "process where process.name : (\"a\", true)",
            "process where 1 : \"a\"",
            "process where process.name in~ (\"a\", 2)",
            "process where process.name regex 1",
            "process where process.pid + \"1\" == 2",
            "process where -\"a\" == 1",
        ] {
            assert_eq!(
                with_severity(src),
                vec![(codes::EQL_ARGUMENT_TYPE.to_string(), Severity::Error)],
                "{src}"
            );
        }
        // A non-constant CIDR block is rejected.
        assert!(has(
            "process where cidrMatch(source.ip, destination.ip)",
            codes::EQL_ARGUMENT_TYPE,
            Severity::Error
        ));
        for src in [
            "process where cidrMatch(source.ip, \"10.0.0.0/8\", \"192.168.0.0/16\")",
            "process where cidrMatch(null, \"10.0.0.0/8\")",
            "process where length(null) == 0",
            "process where substring(process.name, 1, -1) == \"x\"",
            "process where substring(process.name, length(process.name) - 2) == \"x\"",
            "process where between(file.path, \"a\", \"b\", true) == \"x\"",
            "process where process.name : null",
            "process where process.name like 1",
            "process where process.pid in (1, 2)",
            "process where process.pid + 1.5 > 2",
            "process where +\"a\" == \"a\"",
            "process where concat(1, true, \"a\") == \"1truea\"",
        ] {
            assert!(
                !has(src, codes::EQL_ARGUMENT_TYPE, Severity::Error),
                "{src}: {:?}",
                with_severity(src)
            );
        }
        // A hyphenated field name written bare is a subtraction.
        let d = analyze("any where cs-method:\"GET\"").diagnostics;
        assert!(
            d.iter()
                .any(|d| d.code == codes::EQL_ARGUMENT_TYPE
                    && d.message.contains("`` `cs-method` ``")),
            "{d:?}"
        );
        // An arity error is reported alone.
        assert!(
            !codes_of("process where length(1, 2) > 0")
                .contains(&codes::EQL_ARGUMENT_TYPE.to_string())
        );
    }

    #[test]
    fn field_comparisons_are_rejected_where_elasticsearch_translates_them() {
        for src in [
            "process where process.pid == process.parent.pid",
            "process where a != b",
            "process where a < b and c == 1",
            "process where not (length(a) > length(b))",
            "process where a in~ (\"x\", b)",
            "process where a in (\"x\", b)",
            "process where string(a in (b)) == \"true\"",
            "sequence [a where x == y] [b where true]",
        ] {
            assert!(
                has(src, codes::EQL_FIELD_COMPARISON, Severity::Error),
                "{src}: {:?}",
                with_severity(src)
            );
        }
        for src in [
            "process where a == 1",
            "process where 1 == a",
            "process where length(a) == length(\"abc\")",
            "process where startsWith(a, b)",
            "process where string(a == b) == \"true\"",
            "process where a == b or true",
        ] {
            assert!(
                !codes_of(src).contains(&codes::EQL_FIELD_COMPARISON.to_string()),
                "{src}: {:?}",
                with_severity(src)
            );
        }
        // An optional field reads as null when unmapped, so it is a warning.
        assert!(has(
            "process where a == ?b",
            codes::EQL_FIELD_COMPARISON,
            Severity::Warning
        ));
        assert!(has(
            "process where a in (?b)",
            codes::EQL_FIELD_COMPARISON,
            Severity::Warning
        ));
    }

    #[test]
    fn runs_and_until_warnings() {
        let found = with_severity("sequence [a where true] with runs=2.5 [b where true]");
        assert_eq!(
            found,
            vec![
                (codes::EQL_RUNS_IGNORED.to_string(), Severity::Warning),
                (codes::EQL_MAXSPAN_MISSING.to_string(), Severity::Hint),
            ],
            "a decimal runs is ignored, not an error"
        );
        // `runs=2.5` counts once, so this sequence has one query.
        assert!(
            codes_of("sequence [a where true] with runs=2.5")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        let src = "sequence [a where true] [b where true] until [c where true] with runs=2";
        assert_eq!(codes_of(src), vec![codes::EQL_UNTIL_TERM.to_string()]);
        // The `until` copies count toward the minimum, as in Elasticsearch.
        assert!(
            !codes_of("sequence [a where true] until [c where true] with runs=3")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("sequence [a where true] until [c where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        let src = "sequence with maxspan=1m [a where true] [b where true] until ![c where true]";
        assert_eq!(codes_of(src), vec![codes::EQL_UNTIL_TERM.to_string()]);
        assert!(
            codes_of("sequence [a where true] [b where true] until [c where true] with runs=101")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn regex_patterns_are_linted_as_lucene() {
        let src = "process where process.name regex \"^cmd\\\\.exe$\"";
        assert_eq!(codes_of(src), vec![codes::EQL_REGEX.to_string()]);
        let src = "process where process.name regex~ (\"a@b\", \"\"\"x<y\"\"\")";
        assert_eq!(
            codes_of(src),
            vec![codes::EQL_REGEX.to_string(), codes::EQL_REGEX.to_string()]
        );
        assert!(codes_of("process where process.name regex \"\"\"cmd\\.exe\"\"\"").is_empty());
        assert!(codes_of("process where process.name regex \"a\\\\@b[$^]\"").is_empty());
        assert_eq!(
            codes_of("process where process.name regex \"(?i)cmd\""),
            vec![codes::EQL_REGEX.to_string()]
        );
        // `like` patterns are wildcards, not regex.
        assert!(codes_of("process where process.name like \"^a$\"").is_empty());
    }

    #[test]
    fn sequences_report_maxspan_for_tide() {
        let src = "sequence by host.id with maxspan=5m [a where true] [b where true]\n";
        let found = sequences(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].span, ByteSpan::new(0, 8));
        assert_eq!(
            found[0].maxspan.as_ref().and_then(|m| m.millis),
            Some(300_000)
        );
        let found = sequences("sequence [a where true] [b where true]");
        assert_eq!(found.len(), 1);
        assert!(found[0].maxspan.is_none());
        let found = sequences("sequence with maxspan=5w [a where true] [b where true]");
        assert_eq!(found[0].maxspan.as_ref().map(|m| m.millis), Some(None));
        assert!(
            sequence_maxspans("sequence with maxspan=5w [a where true] [b where true]").is_empty()
        );
        assert!(sequences("process where true").is_empty());
        // Without maxspan: a hint, not a warning.
        assert!(has(
            "sequence [a where true] [b where true]",
            codes::EQL_MAXSPAN_MISSING,
            Severity::Hint
        ));
        assert!(!has(
            "sequence with maxspan=1m [a where true] [b where true]",
            codes::EQL_MAXSPAN_MISSING,
            Severity::Hint
        ));
    }

    #[test]
    fn parameter_descriptions_reach_hover_and_signature_help() {
        let src = "process where substring(process.name, 1)";
        let h = hover(src, 16).expect("hover");
        let row = Catalog::cached().function("substring").unwrap();
        for p in &row.parameters {
            assert!(!p.docs.is_empty(), "{} has no description", p.name);
            assert!(h.contains(&p.docs), "{h}");
        }
        let partial = "process where substring(process.name, ";
        let help = signature_help(partial, partial.len()).expect("signature");
        let doc = help.signatures[0].parameters[1]
            .documentation
            .clone()
            .unwrap_or_default();
        assert!(doc.starts_with(&row.parameters[1].docs), "{doc}");
        for f in &Catalog::cached().functions {
            for p in &f.parameters {
                assert!(
                    !p.docs.is_empty(),
                    "{}.{} has no description",
                    f.name,
                    p.name
                );
            }
        }
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "process where process.name == \"\u{e9}\" and length(\"\u{e9}\") > 1";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside).is_empty());
        assert_eq!(hover(src, inside), None);
        assert!(signature_help(src, inside).is_none());
    }

    /// Queries with multi-byte text in every place the crate cuts: string
    /// escapes (`\é`, `\u{…}`), raw strings, quoted names, comments, the
    /// regex operators and calls. The ranges are checked in debug builds
    /// (`cut`).
    const MULTI_BYTE: &[&str] = &[
        "process where `é😀`.`a``😀` == \"é\\é\\😀\\u{é}\\u{1F600}\" and é😀 : \"\"\"é😀\"\"\"\"\" /* é😀 /* */ // 😀\n and startsWith~(é😀, \"😀",
        "process where process.name regex~ (\"é😀.*\", \"\"\"😀[é-😀]\"\"\") and `é😀 ?\"é\" ?'😀' /* é😀",
        "sequence by é😀 [process where `😀` == 'é'] ![network where é😀(\"😀\", ] until [é where \"\"\"é\n\"\"\"",
        "é😀 where true | filter é😀 > 1 | head é | unique `é``",
    ];

    #[test]
    fn multi_byte_text_is_read_whole_everywhere() {
        for query in MULTI_BYTE {
            let result = analyze(query);
            for token in &result.tokens {
                assert!(
                    query.get(token.span.start..token.span.end).is_some(),
                    "{query}"
                );
            }
            let _ = ecs_diagnostics(query);
            let _ = sequences(query);
            for (offset, _) in query.char_indices().chain([(query.len(), ' ')]) {
                let _ = hover(query, offset);
                let _ = completions(query, offset);
                let _ = signature_help(query, offset);
                let prefix = query.get(..offset).unwrap();
                let _ = analyze(prefix);
                let _ = lexical::prepare(prefix);
            }
        }
    }

    #[test]
    fn multi_byte_escapes_and_names_are_read_whole() {
        assert_eq!(cut("é😀x", 0, 2), "é");
        assert_eq!(cut("é😀x", 2, 7), "😀x");
        let messages: Vec<String> = analyze("process where a == \"é\\😀\"")
            .diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect();
        assert!(messages.iter().any(|m| m.contains("\\😀")), "{messages:?}");
        let call = "process where é😀 and startsWith(é, ";
        assert_eq!(
            signature_help(call, call.len()).map(|h| h.active_parameter),
            Some(1)
        );
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    /// Queries like the corpus's, written here: an engine crate reads no file
    /// (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        "sequence by host.id with maxspan=5m [process where process.name : \"cmd.exe\"] [network where destination.port in (22, 3389)] until [process where event.type == \"end\"]",
        "process where process.name in~ (\"cmd.exe\", \"powershell.exe\") and not process.args : \"*-enc*\" | head 5",
        "sample by host.id [file where file.extension == \"exe\"] [process where true]",
        "process where length(process.args) > 3 and ?process.parent.name == null and `odd field` != \"x\" // c",
        "network where cidrMatch(destination.ip, \"10.0.0.0/8\") and /* block */ startsWith~(process.name, \"svc\")",
        "process where a == 0x10 and b : (\"x\", \"y\") | filter c > 1 | unique d",
        "process where process.pid ==",
        "sequence [a where true] ![b where true] [c where",
    ];

    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        let cut: Vec<String> = SAMPLES
            .iter()
            .flat_map(|t| {
                t.char_indices()
                    .map(|(i, _)| t.get(..i).unwrap().to_owned())
            })
            .collect();
        out.extend(cut);
        out
    }

    /// The one walk meets the nodes in the order the checks' preorder did,
    /// and gives the tokens the highlight's walk gave (ADR 0014 §5a).
    #[test]
    fn one_walk_is_the_checks_walk_and_the_highlights() {
        let spec = HighlightSpec::shared().expect("highlight spec");
        for source in texts() {
            let parsed = parsed::parse(&source);
            let preorder: Vec<_> = parsed
                .syntax
                .preorder()
                .filter_map(|e| match e {
                    rowan::WalkEvent::Enter(n) => Some(n),
                    rowan::WalkEvent::Leave(_) => None,
                })
                .collect();
            let nodes: Vec<_> = parsed
                .syntax
                .descendants_with_tokens()
                .filter_map(rowan::NodeOrToken::into_node)
                .collect();
            assert_eq!(nodes, preorder, "{source:?}");
            let tokens = analyze(&source).tokens;
            assert_eq!(
                format!("{tokens:?}"),
                format!("{:?}", highlight(spec, &source, &parsed.syntax)),
                "{source:?}"
            );
        }
    }

    /// An analysis walks every element once (ADR 0014 §7): the checks walked
    /// the nodes and the highlight every element again. Every walk over the
    /// elements counts, the highlight's (`visible_tokens`) and the depth
    /// check's included, so a second walk fails it.
    #[test]
    fn an_analysis_visits_each_element_once() {
        for source in [SAMPLES[0], SAMPLES[6]] {
            let elements = parsed::parse(source)
                .syntax
                .descendants_with_tokens()
                .count();
            let before = visits();
            analyze(source);
            assert_eq!(visits() - before, elements, "{source:?}");
        }
    }
}
