//! The tree-sitter engine of `src/lib.rs`, copied verbatim (tests removed, paths adjusted) as the old side of the differential. Deleted with the engine in the last PR of #1228.

mod columns;
mod ecs;
mod gates;

pub use columns::output_columns;
pub use ecs::{ecs_diagnostics, source_indices};
pub use opentide_esql::catalog::{
    Catalog, CommandRow, FunctionRow, Lifecycle, StackVersion, TypeRow,
};
pub use opentide_esql::version::{self, Availability, RELEASES, StackTarget};

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Range, Severity,
    SignatureHelp, SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse, walk};
use tree_sitter::Node;

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
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_for(source: &str, target: Option<StackTarget>) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let Some(tree) = ts_parse(LanguageId::Esql, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::ESQL_PARSE_ERROR,
                "failed to initialize the ES|QL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    let to_range = |span: ByteSpan| range(source, span);
    walk(root, |node| {
        for gate in gates::syntax_gates(node, source) {
            diagnostics.extend(gate.diagnostic(target, to_range));
        }
        if let Some((spacing, span)) = gates::command_spacing(node, source) {
            let word = node.child(0).map(|k| text(k, source)).unwrap_or_default();
            match gates::spacing_gate(word, spacing, span, to_range(span)) {
                Ok(gate) => diagnostics.extend(gate.diagnostic(target, to_range)),
                Err(d) => diagnostics.push(*d),
            }
        }
        if node.kind() == "unknown_command" {
            diagnostics.push(unknown_command(node, source, catalog));
        } else if let Some(name) = command_name(node, source) {
            if let Some(row) = catalog.command(&name)
                && let Some(d) = availability(
                    target,
                    &display_name(&name),
                    "command",
                    row.snapshot_only,
                    &Lifecycle::parse(&row.stack),
                    row.availability(),
                    keyword_span(node),
                    &to_range,
                )
            {
                diagnostics.push(d);
            }
        } else if node.kind() == "function_call" {
            if let Some(d) = function_diagnostic(target, node, source, catalog) {
                diagnostics.push(d);
            }
        } else if node.kind() == "inline_cast" {
            if let Some(d) = cast_diagnostic(target, node, source, catalog) {
                diagnostics.push(d);
            }
        } else if node.kind() == "qualified_name" {
            if let Some(d) = reserved_name(node, source) {
                diagnostics.push(d);
            }
        } else if node.kind() == "string" {
            if let Some(d) = string_escape(node, source) {
                diagnostics.push(d);
            }
        } else if node.kind() == "like_expression" {
            diagnostics.extend(pattern_problems(node, source));
        } else if node.kind() == "selector" {
            let name = text(node, source);
            if !matches!(name.to_ascii_lowercase().as_str(), "data" | "failures") {
                diagnostics.push(Diagnostic::error(
                    codes::ESQL_PARSE_ERROR,
                    format!("unknown index selector `::{name}`; Elasticsearch knows `::data` and `::failures`"),
                    range(source, node_span(node)),
                ));
            }
        } else if node.kind() == "qualified_interval" {
            let value = node.child_by_field_name("value").map(|v| text(v, source));
            if value.is_some_and(|v| !v.bytes().all(|b| b.is_ascii_digit())) {
                diagnostics.push(Diagnostic::error(
                    codes::ESQL_PARSE_ERROR,
                    "a time span needs a whole number (`90 minutes`, not `1.5 hours`)",
                    range(source, node_span(node)),
                ));
            }
        }
    });
    // Elasticsearch caps expression depth: 400 until 8.19.16, 9.0-9.2,
    // 9.3.4, and 9.4.2; 300 from 8.19.17, 9.3.5, 9.4.3, and 9.5.
    let (depth, deepest) = expression_depth(root);
    if depth > 300 {
        let span = deepest.map_or_else(|| node_span(root), node_span);
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
        && let Some(d) = metadata_id_advisory(root, source)
    {
        diagnostics.push(d);
    }
    // The indices `FROM` reads: undeclared ones, and ECS field checks when
    // every one holds ECS documents.
    opentide_ecs::merge(&mut diagnostics, ecs::dataset_diagnostics(root, source));
    let tokens = highlight(&spec, source, catalog);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// Words the expression lexer always reads as keywords. A field with one of
/// these names needs backticks: `` `by` ``.
const EXPRESSION_KEYWORDS: &[&str] = &[
    "and", "asc", "by", "desc", "false", "first", "in", "is", "last", "like", "not", "null",
    "nulls", "on", "or", "rlike", "true", "where", "with",
];

fn reserved_name(node: Node, source: &str) -> Option<Diagnostic> {
    let mut cursor = node.walk();
    let part = node.named_children(&mut cursor).find(|part| {
        part.kind() == "identifier"
            && EXPRESSION_KEYWORDS.contains(&text(*part, source).to_ascii_lowercase().as_str())
    })?;
    let word = text(part, source);
    Some(
        Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            format!(
                "`{word}` is an ES|QL keyword here; quote a field with that name as `` `{word}` ``"
            ),
            range(source, node_span(part)),
        )
        .with_suggestion(format!("`{word}`")),
    )
}

/// Double-quoted strings allow only `\t \n \r \" \\`; anything else, such as
/// `"C:\Windows"`, fails the lexer. Triple-quoted strings take no escapes.
fn string_escape(node: Node, source: &str) -> Option<Diagnostic> {
    let t = text(node, source);
    if t.starts_with("\"\"\"") {
        return None;
    }
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            if !matches!(bytes[i + 1], b't' | b'n' | b'r' | b'"' | b'\\') {
                let at = node.start_byte() + i;
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
fn pattern_problems(node: Node, source: &str) -> Vec<Diagnostic> {
    let rlike = node
        .child_by_field_name("operator")
        .is_some_and(|o| text(o, source).eq_ignore_ascii_case("rlike"));
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for pattern in node.children_by_field_name("pattern", &mut cursor) {
        if pattern.kind() != "string" {
            continue;
        }
        let Some(value) = string_value(text(pattern, source)) else {
            continue;
        };
        let at = range(source, node_span(pattern));
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
/// arithmetic, predicate, cast, call, or parenthesized node adds one.
fn expression_depth(root: Node) -> (usize, Option<Node>) {
    const NESTING: &[&str] = &[
        "not_expression",
        "and_expression",
        "or_expression",
        "in_expression",
        "is_null_expression",
        "like_expression",
        "match_expression",
        "comparison",
        "unary_expression",
        "binary_expression",
        "parenthesized_expression",
        "inline_cast",
        "function_call",
    ];
    // Iterative: a 10 000-term chain must not overflow the stack.
    let mut cursor = root.walk();
    let mut depth = 0usize;
    let mut stack: Vec<bool> = Vec::new();
    let (mut max, mut deepest) = (0usize, None);
    loop {
        let node = cursor.node();
        let counts = NESTING.contains(&node.kind());
        if counts {
            depth += 1;
            if depth > max {
                max = depth;
                deepest = Some(node);
            }
        }
        stack.push(counts);
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if stack.pop() == Some(true) {
                depth -= 1;
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return (max, deepest);
            }
        }
    }
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("ES|QL syntax error: missing `{}`", err.kind());
    }
    let text = source
        .get(err.start_byte()..err.end_byte())
        .unwrap_or("")
        .trim();
    let first = text.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        "ES|QL syntax error".to_string()
    } else {
        format!("ES|QL syntax error near `{first}`")
    }
}

fn range(source: &str, span: ByteSpan) -> Range {
    span_to_range(source, span)
}

pub(crate) fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

/// Catalog name of a command node: `stats`, `inline stats`, `lookup join`.
pub fn command_name(node: Node, source: &str) -> Option<String> {
    let kind = node.kind();
    let base = kind.strip_suffix("_command")?;
    Some(match base {
        "unknown" => return None,
        "inline_stats" => {
            let first = node.child(0).map(|c| text(c, source).to_ascii_lowercase());
            if first.as_deref() == Some("inlinestats") {
                "inlinestats".into()
            } else {
                "inline stats".into()
            }
        }
        "join" => {
            let join_kind = node
                .child_by_field_name("kind")
                .map(|k| text(k, source).to_ascii_lowercase())
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

/// The command's leading keywords (`LOOKUP JOIN`, `INLINE STATS`).
pub(crate) fn keyword_span(node: Node) -> ByteSpan {
    let start = node.start_byte();
    let mut end = start;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            break;
        }
        if child.kind() == "|" || child.kind() == "(" {
            break;
        }
        end = child.end_byte();
        if node.kind() != "inline_stats_command" && node.kind() != "join_command" {
            break;
        }
    }
    if node.kind() == "join_command"
        && let Some(kind) = node.child_by_field_name("kind")
    {
        end = end.max(kind.end_byte());
        if let Some(join) = kind.next_sibling() {
            end = end.max(join.end_byte());
        }
    }
    ByteSpan::new(start, end.max(start + 1))
}

fn unknown_command(node: Node, source: &str, catalog: &Catalog) -> Diagnostic {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = text(name_node, source);
    let mut d = Diagnostic::error(
        codes::ESQL_UNKNOWN_COMMAND,
        format!(
            "unknown ES|QL command `{name}`; Elasticsearch rejects it, and Kibana 9.4 and 9.5 run a non-aggregating rule without it"
        ),
        range(source, node_span(name_node)),
    );
    if let Some(s) = catalog.suggest_command(name) {
        d = d.with_suggestion(display_name(&s));
    }
    d
}

fn function_diagnostic(
    target: Option<StackTarget>,
    node: Node,
    source: &str,
    catalog: &Catalog,
) -> Option<Diagnostic> {
    let name_node = node.child_by_field_name("name")?;
    if name_node.kind() == "parameter" {
        return None;
    }
    let name = text(name_node, source);
    let span = node_span(name_node);
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
            &Lifecycle::parse(&row.stack),
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
            if let Some(s) = catalog.suggest_function(name) {
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
    node: Node,
    source: &str,
    catalog: &Catalog,
) -> Option<Diagnostic> {
    let type_node = node.child_by_field_name("type")?;
    let name = text(type_node, source);
    if name.starts_with('?') || name.starts_with('`') {
        return None;
    }
    let span = node_span(type_node);
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
            if let Some(s) = catalog.suggest_type(name) {
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
    let range = to_range(span);
    if snapshot_only {
        return Some(Diagnostic::error(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` exists only in Elasticsearch snapshot builds; release clusters reject it"
            ),
            range,
        ));
    }
    let described = lifecycle.describe();
    if let Some(available) = available {
        let gate = gates::Gate {
            subject: format!("{what} `{name}`"),
            available,
            note: (!described.is_empty()).then(|| described.clone()),
            suggestion: None,
            floor_severity: None,
            span,
        };
        if let Some(d) = gate.diagnostic(target, to_range) {
            return Some(d);
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
                range,
            ));
        }
    } else if let Some(first) = lifecycle.after_floor() {
        let mut d = Diagnostic::warning(
            codes::ESQL_UNAVAILABLE,
            format!(
                "{what} `{name}` needs Elasticsearch {first} or later ({}); an 8.19 cluster rejects it",
                lifecycle.describe()
            ),
            range,
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
            range,
        );
        d.severity = Severity::Information;
        return Some(d);
    }
    None
}

/// Non-aggregating `FROM` queries need `METADATA _id` so Elastic Security can
/// de-duplicate alerts ([elastic-1.0] Advisories).
fn metadata_id_advisory(root: Node, source: &str) -> Option<Diagnostic> {
    let query = named_child_of_kind(root, "query")?;
    let source_cmd = query.child_by_field_name("source")?;
    if source_cmd.kind() != "from_command" {
        return None;
    }
    let mut cursor = query.walk();
    let aggregates = query
        .children_by_field_name("command", &mut cursor)
        .any(|c| c.kind() == "stats_command");
    if aggregates {
        return None;
    }
    let metadata = source_cmd.child_by_field_name("metadata");
    let has_id = metadata.is_some_and(|m| {
        let mut c = m.walk();
        m.children_by_field_name("field", &mut c)
            .any(|f| text(f, source) == "_id")
    });
    if has_id {
        return None;
    }
    let span = metadata
        .map(node_span)
        .unwrap_or_else(|| keyword_span(source_cmd));
    Some(
        Diagnostic::warning(
            codes::ESQL_METADATA_ID,
            "non-aggregating ES|QL query lacks `METADATA _id`; before 9.4 Elastic Security cannot de-duplicate its alerts (9.4 and later add it)",
            range(source, span),
        )
        .with_suggestion("METADATA _id, _version, _index"),
    )
}

fn named_child_of_kind<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|c| c.kind() == kind)
}

fn highlight(spec: &HighlightSpec, source: &str, catalog: &Catalog) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures(
        LanguageId::Esql,
        source,
        opentide_highlight::ESQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    for (span, capture) in &mut spans {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name).is_some() {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
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
    let tree = ts_parse(LanguageId::Esql, source)?;
    let catalog = Catalog::cached();
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    // Function name.
    if let Some(parent) = node.parent() {
        if parent.kind() == "function_call"
            && parent.child_by_field_name("name").map(|n| n.id()) == Some(node.id())
        {
            return catalog.function(text(node, source)).map(function_hover);
        }
        if parent.kind() == "metadata_field" || node.kind() == "metadata_field" {
            let name = text(node, source);
            return METADATA_FIELDS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(n, d)| format!("**`{n}`** (METADATA field)\n\n{d}"));
        }
    }
    // Command keyword.
    let mut cur = Some(node);
    while let Some(n) = cur {
        if n.kind().ends_with("_command") {
            let span = keyword_span(n);
            if offset >= span.start && offset < span.end {
                if n.kind() == "unknown_command" {
                    return None;
                }
                let name = command_name(n, source)?;
                return catalog.command(&name).map(command_hover);
            }
            break;
        }
        cur = n.parent();
    }
    // Operator.
    if !node.is_named() {
        let symbol = text(node, source);
        if let Some(op) = catalog.operator(symbol) {
            return Some(operator_hover(op));
        }
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

fn operator_hover(row: &opentide_esql::catalog::OperatorRow) -> String {
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
    let Some(tree) = ts_parse(LanguageId::Esql, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), |node| {
        if matches!(node.kind(), "qualified_name" | "name_pattern") && !node.has_error() {
            let name = text(node, source);
            if !name.contains('*') && !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    });
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
