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

mod lexical;
mod regex;
mod semantics;

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Position, Range,
    Severity, SignatureHelp, SignatureInformation, codes, position_to_offset, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use serde::Deserialize;
use std::sync::OnceLock;
use tree_sitter::Node;

const FUNCTIONS_TOML: &str = include_str!("../../../catalogs/eql/functions.toml");
const PIPES_TOML: &str = include_str!("../../../catalogs/eql/pipes.toml");

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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

impl Catalog {
    pub fn cached() -> &'static Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| {
            let functions: FunctionsFile = toml::from_str(FUNCTIONS_TOML).expect("eql functions");
            let pipes: PipesFile = toml::from_str(PIPES_TOML).expect("eql pipes");
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

/// Parses `source` as Elasticsearch reads it: block comments that its lexer
/// nests are blanked inside (same byte offsets) so the grammar ends them at
/// the same place.
fn parse_prepared(source: &str) -> Option<(tree_sitter::Tree, lexical::Prepared<'_>)> {
    let prepared = lexical::prepare(source);
    let tree = ts_parse(LanguageId::Eql, &prepared.text)?;
    Some((tree, prepared))
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let Some((tree, prepared)) = parse_prepared(source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "failed to initialize the EQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut out = Vec::new();
    if let Some(err) = first_error(root) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    check_comments(&prepared.comments, source, &mut out);
    if let Some(span) = lexical::expression_depth_exceeded(root) {
        out.push(Diagnostic::warning(
            codes::EQL_EXPRESSION_DEPTH,
            format!(
                "expression nesting exceeds {} levels (parentheses plus chained `not`/`-`/`+`): Elasticsearch 8.19.17+, 9.3.5+, 9.4.3+, and 9.5 reject this query; earlier patches and 9.0 to 9.2 accept it",
                lexical::MAX_EXPRESSION_DEPTH
            ),
            range(source, span),
        ));
    }
    let mut translated = std::collections::HashMap::new();
    opentide_syntax::walk_with_ancestors(root, |node, ancestors| {
        check_node(node, ancestors, &mut translated, source, catalog, &mut out)
    });
    check_pipes(root, source, catalog, &mut out);
    let tokens = highlight(&spec, source, &prepared.text);
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

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("EQL syntax error: missing `{}`", err.kind());
    }
    let snippet = text(err, source).trim();
    if snippet.starts_with('=') && !snippet.starts_with("==") {
        return "EQL syntax error: use `==` for equality; `=` is not a comparison".into();
    }
    match snippet.split_whitespace().next() {
        Some(first) => {
            let lower = first.to_ascii_lowercase();
            if KEYWORD_WORDS.contains(&lower.as_str()) && first != lower {
                format!("EQL syntax error near `{first}`: keywords are lower case (`{lower}`)")
            } else {
                format!("EQL syntax error near `{first}`")
            }
        }
        None => "EQL syntax error".into(),
    }
}

fn check_node(
    node: Node,
    ancestors: &[Node],
    translated: &mut std::collections::HashMap<usize, bool>,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    // Keyword tokens share their kind with the node (`sequence`, `join`).
    if !node.is_named() {
        return;
    }
    match node.kind() {
        "string" => check_string(node, source, out),
        "index" => out.push(Diagnostic::error(
            codes::EQL_UNSUPPORTED,
            "array indexes are not supported in Elasticsearch EQL",
            range(source, node_span(node)),
        )),
        "field" => check_field_case(node, source, out),
        "event_category" => check_category_case(node, source, out),
        "comparison" => {
            check_literal_wildcard(node, source, out);
            semantics::check_field_comparisons(node, ancestors, translated, source, out);
        }
        "predicate_expression" => {
            check_literal_wildcard(node, source, out);
            regex::check_regex(node, source, out);
            semantics::check_types(node, source, out);
            semantics::check_field_comparisons(node, ancestors, translated, source, out);
        }
        "binary_expression" | "unary_expression" => semantics::check_types(node, source, out),
        "and_expression" | "or_expression" | "not_expression" | "event_query" => {
            semantics::check_conditions(node, source, out)
        }
        "function_call" => {
            if check_function(node, source, catalog, out) {
                semantics::check_types(node, source, out);
            }
        }
        "sequence" => check_sequence(node, source, out),
        "sample" => check_sample(node, source, out),
        "join" => out.push(unsupported(
            node,
            source,
            "Elasticsearch EQL does not support `join`; use `sequence` or `sample`",
            keyword_span(node),
        )),
        "relationship" => {
            let relation = node
                .child_by_field_name("relation")
                .map(|n| text(n, source))
                .unwrap_or("of");
            out.push(unsupported(
                node,
                source,
                &format!("Elasticsearch EQL does not support the lineage keyword `{relation} of`"),
                node_span(node),
            ));
        }
        "subquery" => {
            semantics::check_conditions(node, source, out);
            let missing = node
                .child_by_field_name("open")
                .is_some_and(|o| o.kind() == "missing_event_open");
            let in_sequence = ancestors
                .iter()
                .rev()
                .nth(1)
                .is_some_and(|g| g.kind() == "sequence");
            if missing && !in_sequence {
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    "missing events (`![ ... ]`) are supported only in sequences",
                    range(source, node_span(node)),
                ));
            }
        }
        _ => {}
    }
}

fn check_string(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source);
    let message = if t.starts_with('\'') {
        Some("use double quotes [\"] for string literals, not single quotes [']")
    } else if t.starts_with('?') {
        Some(
            "`?\"` and `?'` are not raw strings in Elasticsearch EQL; use triple double quotes [\"\"\"]",
        )
    } else {
        None
    };
    // Elasticsearch's lexer has no token for these, so they fail to parse.
    if let Some(message) = message {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            message,
            range(source, node_span(node)),
        ));
        return;
    }
    if t.starts_with("\"\"\"") {
        return;
    }
    // `"…"` accepts only these escapes; anything else fails the lexer.
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let bad = match next {
            b'b' | b't' | b'n' | b'f' | b'r' | b'"' | b'\'' | b'\\' => false,
            b'u' => {
                let rest = &t[i + 2..];
                let digits = rest
                    .strip_prefix('{')
                    .and_then(|r| r.split_once('}'))
                    .map(|(h, _)| h);
                !digits.is_some_and(|h| {
                    (2..=8).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit())
                })
            }
            _ => true,
        };
        if bad {
            let at = node.start_byte() + i;
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!(
                    "invalid escape `\\{}`: EQL strings accept \\b \\t \\n \\f \\r \\\" \\' \\\\ and \\u{{2-8 hex}}; use `\\\\` or a triple-quoted string",
                    next as char
                ),
                range(source, ByteSpan::new(at, at + 2)),
            ));
            return;
        }
        i += 2;
    }
}

/// `x == TRUE` reads a field named `TRUE`: keywords are lower case.
fn check_field_case(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source).trim_start_matches('?').trim();
    let lower = t.to_ascii_lowercase();
    if KEYWORD_WORDS.contains(&lower.as_str()) && t != lower {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!("EQL keywords are lower case: `{t}` here is a field name, not `{lower}`"),
                range(source, node_span(node)),
            )
            .with_suggestion(lower),
        );
    }
}

/// Categories compare case-sensitively with `event.category`, which ECS
/// keeps lower case: `PROCESS where` matches nothing.
fn check_category_case(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source).trim_matches('"');
    if t.chars().any(|c| c.is_ascii_uppercase()) {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!(
                    "event category `{t}` is compared case-sensitively; ECS categories are lower case"
                ),
                range(source, node_span(node)),
            )
            .with_suggestion(t.to_ascii_lowercase()),
        );
    }
}

/// `==`, `!=`, `in`, and `in~` do not expand wildcards, so `"*.exe"` is
/// matched literally. A `*` next to a backslash (`\\*\\ADMIN$`) is left alone.
fn check_literal_wildcard(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let operator = node
        .child_by_field_name("operator")
        .map(|o| text(o, source))
        .unwrap_or("");
    if !matches!(operator, "==" | "!=" | "in" | "in~") {
        return;
    }
    let mut cursor = node.walk();
    let candidates: Vec<Node> = if node.kind() == "comparison" {
        node.child_by_field_name("right").into_iter().collect()
    } else {
        node.children_by_field_name("values", &mut cursor).collect()
    };
    for value in candidates {
        if value.kind() != "string" {
            continue;
        }
        let t = text(value, source);
        let bytes = t.as_bytes();
        let wild = bytes.iter().enumerate().any(|(i, b)| {
            *b == b'*'
                && bytes.get(i.wrapping_sub(1)) != Some(&b'\\')
                && bytes.get(i + 1) != Some(&b'\\')
        });
        if wild {
            let suggestion = if operator.starts_with("in") {
                ":"
            } else {
                "like"
            };
            out.push(
                Diagnostic::warning(
                    codes::EQL_LITERAL_WILDCARD,
                    format!(
                        "`{operator}` matches `*` literally; use `{suggestion}` for a wildcard"
                    ),
                    range(source, node_span(value)),
                )
                .with_suggestion(suggestion),
            );
            return;
        }
    }
}

/// Name, `~`, and arity checks. Returns whether the call resolves, so its
/// argument types are worth checking.
fn check_function(node: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) -> bool {
    let Some(name_node) = node.child_by_field_name("name") else {
        return false;
    };
    let raw = text(name_node, source);
    let (name, insensitive) = match raw.strip_suffix('~') {
        Some(base) => (base, true),
        None => (raw, false),
    };
    let span = node_span(name_node);
    match catalog.function(name) {
        Some(row) if insensitive && !row.case_insensitive => {
            out.push(Diagnostic::error(
                codes::EQL_UNKNOWN_FUNCTION,
                format!("function `{name}` has no case-insensitive `{name}~` form"),
                range(source, span),
            ));
            false
        }
        Some(row) => {
            let mut c = node.walk();
            // The field spans the comma list, so count named nodes only.
            let args = node
                .children_by_field_name("arguments", &mut c)
                .filter(|n| n.is_named())
                .count();
            let too_many = row.max_args.is_some_and(|m| args > m);
            if args < row.min_args || too_many {
                let expected = match row.max_args {
                    Some(m) if m == row.min_args => format!("{m}"),
                    Some(m) => format!("{} to {m}", row.min_args),
                    None => format!("at least {}", row.min_args),
                };
                out.push(Diagnostic::error(
                    codes::EQL_FUNCTION_ARITY,
                    format!("`{}` takes {expected} arguments, found {args}", row.name),
                    range(source, node_span(node)),
                ));
                return false;
            }
            true
        }
        None => {
            let mut d = Diagnostic::error(
                codes::EQL_UNKNOWN_FUNCTION,
                format!("unknown EQL function `{name}`"),
                range(source, span),
            );
            if let Some(s) = catalog
                .functions
                .iter()
                .map(|f| (f.name.as_str(), edit_distance(&f.name, name)))
                .filter(|(_, d)| *d <= 2)
                .min_by_key(|(_, d)| *d)
                .map(|(n, _)| n)
            {
                if s != name {
                    d = d.with_suggestion(s);
                }
            }
            out.push(d);
            false
        }
    }
}

fn check_sequence(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    // `sequence with maxspan=... by k` is rejected: `by` must come first.
    let params_pos = children.iter().position(|c| c.kind() == "sequence_params");
    let by_pos = children.iter().position(|c| {
        c.kind() == "join_keys" && node.child_by_field_name("by").map(|b| b.id()) == Some(c.id())
    });
    if let (Some(p), Some(b)) = (params_pos, by_pos) {
        if p < b {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "specify sequence `by` before `with maxspan`, not after",
                range(source, node_span(children[b])),
            ));
        }
    }
    let maxspan = params_pos.and_then(|p| children[p].child_by_field_name("maxspan"));
    if let Some(unit) = maxspan {
        check_maxspan(unit, source, out);
    }
    // `LogicalPlanBuilder.visitSequence` expands `runs` over every term,
    // the `until` term included, then takes the last query as `until`.
    let mut expanded: Vec<bool> = Vec::new();
    let mut cursor = node.walk();
    for term in node.children_by_field_name("term", &mut cursor) {
        let runs = check_runs(term, source, out);
        expanded.extend(std::iter::repeat_n(is_missing_term(term), runs as usize));
    }
    let until = node.child_by_field_name("until");
    if let Some(until) = until {
        let runs = check_runs(until, source, out);
        expanded.extend(std::iter::repeat_n(is_missing_term(until), runs as usize));
        check_until(until, runs, source, out);
    }
    let queries = expanded.len() as u64;
    if queries < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("a sequence requires a minimum of 2 queries, found [{queries}]"),
            range(source, keyword_span(node)),
        ));
    } else if until.is_some() && queries == 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires a minimum of 2 queries besides `until`, found [1]",
            range(source, keyword_span(node)),
        ));
    }
    if queries > MAX_SEQUENCE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sequence cannot contain more than {MAX_SEQUENCE_QUERIES} queries after `runs`, found [{queries}]"
            ),
            range(source, keyword_span(node)),
        ));
    }
    check_key_counts(node, source, out);
    if until.is_some() {
        expanded.pop();
    }
    let missing = expanded.iter().filter(|m| **m).count();
    if missing > 0 && maxspan.is_none() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "`maxspan` is required for sequences with missing events",
            range(source, keyword_span(node)),
        ));
    }
    if !expanded.is_empty() && missing == expanded.len() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires at least one positive event query",
            range(source, keyword_span(node)),
        ));
    }
    if maxspan.is_none() && missing == 0 {
        out.push(Diagnostic {
            severity: Severity::Hint,
            ..Diagnostic::warning(
                codes::EQL_MAXSPAN_MISSING,
                "sequence has no `with maxspan=`: its events can be any distance apart within the search window. A maxspan bounds matches and the partial sequences Elasticsearch keeps",
                range(source, keyword_span(node)),
            )
        });
    }
}

fn is_missing_term(term: Node) -> bool {
    term.named_child(0)
        .and_then(|s| s.child_by_field_name("open"))
        .is_some_and(|o| o.kind() == "missing_event_open")
}

/// `until [...] with runs=n` repeats the `until` query: only the last copy
/// ends sequences, the other copies become ordinary steps. `until ![...]`
/// parses, but Elasticsearch documents no meaning for it.
fn check_until(until: Node, runs: u64, source: &str, out: &mut Vec<Diagnostic>) {
    if let Some(option) = term_option(until) {
        if runs > 1 {
            out.push(Diagnostic::warning(
                codes::EQL_UNTIL_TERM,
                format!(
                    "`runs` on the `until` term adds {} copies of it as ordinary sequence steps before the real `until`; remove `with runs`",
                    runs - 1
                ),
                range(source, node_span(option)),
            ));
        }
    }
    if is_missing_term(until) {
        let open = until
            .named_child(0)
            .and_then(|s| s.child_by_field_name("open"))
            .unwrap_or(until);
        out.push(Diagnostic::warning(
            codes::EQL_UNTIL_TERM,
            "a missing event (`![`) as the `until` term parses, but Elasticsearch documents no behaviour for it; use `[`",
            range(source, node_span(open)),
        ));
    }
}

fn term_option(term: Node) -> Option<Node> {
    term.child_by_field_name("term_option").or_else(|| {
        let mut c = term.walk();
        term.named_children(&mut c)
            .find(|n| n.kind() == "term_option")
    })
}

/// Number of queries a term contributes (`with runs=n` repeats it).
fn check_runs(term: Node, source: &str, out: &mut Vec<Diagnostic>) -> u64 {
    let Some(option) = term_option(term) else {
        return 1;
    };
    let key = option
        .child_by_field_name("key")
        .map(|k| text(k, source))
        .unwrap_or("");
    if key != "runs" {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("unrecognized option [{key}], expecting [runs]"),
            range(source, node_span(option)),
        ));
        return 1;
    }
    let value = option
        .child_by_field_name("value")
        .map(|v| text(v, source))
        .unwrap_or("");
    // Only an integer literal is read; a decimal leaves `runs` at 1.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        out.push(
            Diagnostic::warning(
                codes::EQL_RUNS_IGNORED,
                format!(
                    "Elasticsearch ignores a decimal `runs` value: [{value}] runs the query once; use an integer from 1 to {MAX_RUNS}"
                ),
                range(source, node_span(option)),
            ),
        );
        return 1;
    }
    match value.parse::<u64>() {
        Ok(n) if (1..=MAX_RUNS).contains(&n) => n,
        Ok(0) => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "a positive `runs` value is required; found [0]",
                range(source, node_span(option)),
            ));
            1
        }
        // Larger than a long reads as a double, whose long value is still
        // over the limit.
        _ => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("a query cannot be repeated more than {MAX_RUNS} times; found [{value}]"),
                range(source, node_span(option)),
            ));
            1
        }
    }
}

fn check_maxspan(unit: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let value = unit
        .child_by_field_name("value")
        .map(|v| text(v, source))
        .unwrap_or("");
    let suffix = unit.child_by_field_name("unit").map(|u| text(u, source));
    let span = node_span(unit);
    match value.parse::<u64>() {
        Ok(0) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            "a positive `maxspan` value is required; found [0]",
            range(source, span),
        )),
        Ok(_) => {}
        Err(_) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            format!("decimal time interval [{value}] is not supported; use a positive integer"),
            range(source, span),
        )),
    }
    match suffix {
        None => out.push(
            Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("no time unit in `maxspan={value}`; use one of ms, s, m, h, d"),
                range(source, span),
            )
            .with_suggestion(format!("{value}s")),
        ),
        Some(u) if !MAXSPAN_UNITS.iter().any(|(name, _)| *name == u) => {
            out.push(Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("unrecognized time unit [{u}] in `maxspan`; use one of ms, s, m, h, d"),
                range(source, span),
            ))
        }
        Some(_) => {}
    }
}

fn check_sample(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let terms: Vec<Node> = node.children_by_field_name("term", &mut cursor).collect();
    if terms.len() < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample requires a minimum of 2 queries, found [{}]",
                terms.len()
            ),
            range(source, keyword_span(node)),
        ));
    }
    if terms.len() > MAX_SAMPLE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample cannot contain more than {MAX_SAMPLE_QUERIES} queries, found [{}]",
                terms.len()
            ),
            range(source, node_span(terms[MAX_SAMPLE_QUERIES])),
        ));
    }
    check_key_counts(node, source, out);
    let shared_keys = node.child_by_field_name("by").is_some();
    if !shared_keys && terms.iter().any(|t| t.child_by_field_name("by").is_none()) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sample must have at least one join key, found none",
            range(source, keyword_span(node)),
        ));
    }
}

/// Every term of a sequence or sample (and `until`) names the same number
/// of join keys.
fn check_key_counts(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut terms = Vec::new();
    let mut cursor = node.walk();
    terms.extend(node.children_by_field_name("term", &mut cursor));
    if let Some(until) = node.child_by_field_name("until") {
        terms.push(until);
    }
    let mut expected: Option<usize> = None;
    for term in terms {
        let keys = term
            .child_by_field_name("by")
            .map_or(0, |b| b.named_child_count());
        match expected {
            None => expected = Some(keys),
            Some(e) if e != keys => {
                let at = term.child_by_field_name("by").unwrap_or(term);
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    format!("inconsistent number of join keys specified; expected [{e}] but found [{keys}]"),
                    range(source, node_span(at)),
                ));
                return;
            }
            _ => {}
        }
    }
}

fn check_pipes(root: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let is_sample = root
        .child_by_field_name("query")
        .is_some_and(|q| q.kind() == "sample");
    let mut cursor = root.walk();
    for pipe in root.children_by_field_name("pipe", &mut cursor) {
        let Some(name_node) = pipe.child_by_field_name("name") else {
            continue;
        };
        let name = text(name_node, source);
        if is_sample {
            out.push(Diagnostic::error(
                codes::EQL_UNSUPPORTED,
                "samples do not support pipes",
                range(source, node_span(pipe)),
            ));
            continue;
        }
        if catalog.pipe(name).is_none() {
            let endgame = matches!(
                name,
                "count" | "filter" | "sort" | "unique" | "unique_count"
            );
            let message = if endgame {
                format!(
                    "Elasticsearch EQL does not support the `{name}` pipe; only `head` and `tail`"
                )
            } else {
                format!("unrecognized pipe [{name}]; Elasticsearch EQL supports `head` and `tail`")
            };
            out.push(unsupported(pipe, source, &message, node_span(name_node)));
            continue;
        }
        let mut c = pipe.walk();
        let args: Vec<Node> = pipe
            .children_by_field_name("arguments", &mut c)
            .filter(|n| n.is_named())
            .collect();
        let positive_int = args.len() == 1
            && args[0].kind() == "number"
            // A Java `int`: Elasticsearch rejects `head 2147483648`.
            && text(args[0], source).parse::<i32>().is_ok_and(|n| n >= 0);
        if !positive_int {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("pipe [{name}] expects exactly one positive integer argument"),
                range(source, node_span(pipe)),
            ));
        }
    }
}

fn unsupported(_node: Node, source: &str, message: &str, span: ByteSpan) -> Diagnostic {
    Diagnostic::error(codes::EQL_UNSUPPORTED, message, range(source, span))
}

fn keyword_span(node: Node) -> ByteSpan {
    let first = node.child(0).unwrap_or(node);
    node_span(first)
}

/// Pre-order traversal without recursion, so deeply nested input cannot
/// exhaust the stack.
fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    let mut cursor = node.walk();
    loop {
        f(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() || cursor.node().id() == node.id() {
                return;
            }
        }
    }
}

fn range(source: &str, span: ByteSpan) -> Range {
    span_to_range(source, span)
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(!ca.eq_ignore_ascii_case(cb));
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// `parsed` is `source` with nested comments blanked; offsets are the same.
fn highlight(spec: &HighlightSpec, source: &str, parsed: &str) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures(
        LanguageId::Eql,
        parsed,
        opentide_highlight::EQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    for (span, capture) in spans.iter_mut() {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name.trim_end_matches('~')).is_some() {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
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
    let Some((tree, _)) = parse_prepared(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() != "sequence" || !node.is_named() {
            return;
        }
        let maxspan = node
            .named_children(&mut node.walk())
            .find(|c| c.kind() == "sequence_params")
            .and_then(|p| p.child_by_field_name("maxspan"))
            .map(|unit| Maxspan {
                span: node_span(unit),
                millis: maxspan_millis(unit, source),
            });
        out.push(SequenceInfo {
            span: keyword_span(node),
            maxspan,
        });
    });
    out
}

fn maxspan_millis(unit: Node, source: &str) -> Option<u64> {
    let value = unit
        .child_by_field_name("value")
        .and_then(|v| text(v, source).parse::<u64>().ok())
        .filter(|v| *v > 0)?;
    let suffix = text(unit.child_by_field_name("unit")?, source);
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

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let (tree, _) = parse_prepared(source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let catalog = Catalog::cached();
    let parent = node.parent();
    if parent.is_some_and(|p| p.kind() == "function_call") {
        let name = text(node, source).trim_end_matches('~');
        if let Some(row) = catalog.function(name) {
            return Some(function_hover(row));
        }
    }
    if parent.is_some_and(|p| p.kind() == "pipe") {
        if let Some(row) = catalog.pipe(text(node, source)) {
            let mut md = format!(
                "**{}** (pipe)\n\n```eql\n{}\n```\n\n{}",
                row.name, row.signature, row.docs
            );
            if let Some(c) = &row.citation {
                md.push_str(&format!("\n\n[Elastic docs]({c})"));
            }
            return Some(md);
        }
    }
    let word = match node.kind() {
        "missing_event_open" => "![",
        "optional_marker" => "?",
        _ => text(node, source),
    };
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
    let catalog = Catalog::cached();
    let before = &source[..offset.min(source.len())];
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
    let Some((tree, _)) = parse_prepared(source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field" && !node.has_error() {
            names.insert(text(node, source).trim_start_matches('?').to_string());
        }
    });
    names.into_iter().collect()
}

// ---- Signature help -------------------------------------------------------

pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let before = &source[..offset.min(source.len())];
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
    let name_start = before[..open]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '~'))
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = before[name_start..open].to_string();
    (!name.is_empty()).then_some((name, commas))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codes of errors, warnings, and information; hints are left out.
    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity != Severity::Hint)
            .map(|d| d.code)
            .collect()
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
        let h = hover(src, Position::new(0, 16)).expect("hover");
        assert!(h.contains("startsWith") && h.contains("elastic.co"), "{h}");
        let partial = "process where between(file.path, \"a\", ";
        let help = signature_help(partial, partial.len()).expect("signature");
        assert_eq!(help.active_parameter, 2);
        let h = hover(
            "sequence [a where true] [b where true]",
            Position::new(0, 2),
        )
        .expect("keyword");
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
        let h = hover(src, Position::new(0, 16)).expect("hover");
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
}
