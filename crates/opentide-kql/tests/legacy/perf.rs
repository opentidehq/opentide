//! Warnings for public slow KQL shapes.
//!
//! Source: <https://learn.microsoft.com/en-us/kusto/query/best-practices>
//!
//! Join cardinality and `hint.shufflekey` are intentionally absent: the engine
//! cannot know which side is larger.

use super::schema::{Analysis, Known};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, codes};
use tree_sitter::Node;

const CITE: &str = "https://learn.microsoft.com/en-us/kusto/query/best-practices";

/// One tabular expression as the checks read it: its span, and its
/// operators (the tree-sitter node name of each, and its span).
pub(crate) struct Pipeline {
    pub(crate) span: ByteSpan,
    pub(crate) ops: Vec<Op>,
}

/// An operator of a [`Pipeline`].
#[derive(Clone, Copy)]
pub(crate) struct Op {
    pub(crate) kind: &'static str,
    pub(crate) span: ByteSpan,
}

pub(crate) fn collect(root: Node, source: &str, columns: &Analysis, out: &mut Vec<Diagnostic>) {
    let mut pipelines = Vec::new();
    walk(root, &mut pipelines);
    check(&pipelines, source, columns, out);
}

/// The checks over the pipelines of a query, in source order, and over its
/// text.
pub(crate) fn check(
    pipelines: &[Pipeline],
    source: &str,
    columns: &Analysis,
    out: &mut Vec<Diagnostic>,
) {
    let lines = LineIndex::new(source);
    for pipeline in pipelines {
        warn_pipeline(pipeline, &lines, columns, out);
    }
    warn_scope(source, &lines, out);
}

fn walk(node: Node, out: &mut Vec<Pipeline>) {
    if node.kind() == "tabular_expression" {
        out.push(Pipeline {
            span: span(node),
            ops: operators(node),
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, out);
    }
}

fn operators(expr: Node<'_>) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut cursor = expr.walk();
    for child in expr.children(&mut cursor) {
        if child.kind() != "tabular_operator" {
            continue;
        }
        let mut inner = child.walk();
        for grand in child.children(&mut inner) {
            if grand.kind().ends_with("_operator") {
                ops.push(Op {
                    kind: grand.kind(),
                    span: span(grand),
                });
                break;
            }
        }
    }
    ops
}

/// The pipeline starts from a table (or ASIM parser), not a `let`.
fn source_is_table(expr: ByteSpan, columns: &Analysis) -> bool {
    columns.pipeline(expr).is_some_and(|p| p.reads_dataset())
}

fn span(node: Node) -> ByteSpan {
    ByteSpan::new(node.start_byte(), node.end_byte())
}

/// The filter reads a column an operator before it makes, so it cannot move
/// ahead of that operator (#109): one an `extend` (or `summarize`, `parse`,
/// ...) made, or one the source does not have, which a `join`, `lookup` or
/// `union` brought in.
fn reads_made_column(filter: ByteSpan, expr: ByteSpan, columns: &Analysis) -> bool {
    let source = columns
        .pipeline(expr)
        .map(|p| &p.source)
        .filter(|s| s.known != Known::Open);
    columns.reads(filter).any(|r| {
        let made = r
            .column
            .as_ref()
            .and_then(|c| c.made_by)
            .is_some_and(|made| made.span.end <= filter.start);
        made || source.is_some_and(|s| s.column(&r.name).is_none())
    })
}

fn is_filter(kind: &str) -> bool {
    matches!(kind, "where_operator" | "filter_operator")
}

fn is_narrowing_project(kind: &str) -> bool {
    matches!(
        kind,
        "project_operator" | "project_keep_operator" | "project_away_operator"
    )
}

/// The operator leaves only the columns it names or makes: a `join` after it
/// is already narrow (#109).
fn narrows(kind: &str) -> bool {
    is_narrowing_project(kind)
        || matches!(
            kind,
            "summarize_operator" | "distinct_operator" | "count_operator" | "make_series_operator"
        )
}

fn warn_pipeline(
    pipeline: &Pipeline,
    lines: &LineIndex,
    columns: &Analysis,
    out: &mut Vec<Diagnostic>,
) {
    let ops = &pipeline.ops;
    let expr = pipeline.span;
    if source_is_table(expr, columns)
        && let Some(first) = ops.first()
        && !is_filter(first.kind)
        && let Some(late) = ops
            .iter()
            .find(|op| is_filter(op.kind))
            .filter(|late| !reads_made_column(late.span, expr, columns))
    {
        let keyword = if late.kind == "filter_operator" {
            "filter"
        } else {
            "where"
        };
        push(
            out,
            lines,
            codes::KQL_WHERE_NOT_FIRST,
            format!(
                "`{keyword}` is not the first operator after the table reference; filter before later operators ({CITE})"
            ),
            late.span.start,
            late.span.end,
        );
    }

    // Warn only when a `join` runs on wide columns and a later `project`
    // shows the reversed order. A project, summarize or distinct already
    // before the join, or no project at all, is not this diagnostic. A `let`
    // (or a `union` of them) that ends in one of those is narrow already.
    // `summarize` itself is never warned: it already returns only the
    // columns it names, and projecting before `arg_max(T, *)` would change
    // its result (#109).
    let mut narrowed = columns.pipeline(expr).is_some_and(|p| p.source.narrowed);
    for (index, op) in ops.iter().enumerate() {
        if narrows(op.kind) {
            narrowed = true;
            continue;
        }
        if narrowed || op.kind != "join_operator" {
            continue;
        }
        let project_later = ops
            .iter()
            .skip(index + 1)
            .any(|later| is_narrowing_project(later.kind));
        if !project_later {
            continue;
        }
        push(
            out,
            lines,
            codes::KQL_JOIN_SUMMARIZE_BEFORE_PROJECT,
            format!(
                "`join` runs before `project` narrows columns; project the needed columns first ({CITE})"
            ),
            op.span.start,
            op.span.end,
        );
    }
}

#[derive(Debug)]
enum Kind {
    Word(String),
    Star,
    Pipe,
    LParen,
    RParen,
    Semi,
    String,
}

struct Tok {
    start: usize,
    end: usize,
    kind: Kind,
}

fn tokenize(source: &str) -> Vec<Tok> {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'@' && matches!(bytes.get(i + 1), Some(b'"' | b'\'')) {
            let quote = bytes[i + 1];
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            out.push(Tok {
                start,
                end: i,
                kind: Kind::String,
            });
            continue;
        }
        if c == b'"' || c == b'\'' {
            let start = i;
            i = end_quoted(bytes, i);
            out.push(Tok {
                start,
                end: i,
                kind: Kind::String,
            });
            continue;
        }
        if c == b'*' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Star,
            });
            i += 1;
            continue;
        }
        if c == b'|' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Pipe,
            });
            i += 1;
            continue;
        }
        if c == b'(' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::LParen,
            });
            i += 1;
            continue;
        }
        if c == b')' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::RParen,
            });
            i += 1;
            continue;
        }
        if c == b';' {
            out.push(Tok {
                start: i,
                end: i + 1,
                kind: Kind::Semi,
            });
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
            {
                i += 1;
            }
            out.push(Tok {
                start,
                end: i,
                kind: Kind::Word(source[start..i].to_string()),
            });
            continue;
        }
        i += 1;
    }
    out
}

fn end_quoted(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

enum SearchShape {
    Unscoped,
    Scoped,
    Wildcard(Vec<(usize, usize)>),
}

fn warn_scope(source: &str, lines: &LineIndex, out: &mut Vec<Diagnostic>) {
    let tokens = tokenize(source);
    let mut depth = 0i32;
    let mut at_source = true;
    let mut after_pipe = false;
    for (i, tok) in tokens.iter().enumerate() {
        match &tok.kind {
            Kind::LParen => {
                depth += 1;
            }
            Kind::RParen => {
                depth = (depth - 1).max(0);
                after_pipe = false;
            }
            Kind::Semi if depth == 0 => {
                at_source = true;
                after_pipe = false;
            }
            Kind::Pipe => {
                after_pipe = true;
                at_source = false;
            }
            Kind::Star if at_source => {
                push(
                    out,
                    lines,
                    codes::KQL_WILDCARD_TABLE,
                    format!(
                        "wildcard table `*` scans every table; name the table instead ({CITE})"
                    ),
                    tok.start,
                    tok.end,
                );
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(word) if word == "search" && at_source => {
                match classify_search(&tokens, i) {
                    SearchShape::Unscoped => push(
                        out,
                        lines,
                        codes::KQL_UNSCOPED_SEARCH,
                        format!(
                            "unscoped `search` reads every table; scope it with `in (Table, ...)` or start from a table ({CITE})"
                        ),
                        tok.start,
                        tok.end,
                    ),
                    SearchShape::Wildcard(stars) => {
                        for (start, end) in stars {
                            push(
                                out,
                                lines,
                                codes::KQL_WILDCARD_TABLE,
                                format!(
                                    "wildcard table `*` scans every table; name the table instead ({CITE})"
                                ),
                                start,
                                end,
                            );
                        }
                    }
                    SearchShape::Scoped => {}
                }
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(word) if word == "union" && (at_source || after_pipe) => {
                if let Some((start, end)) = union_star(&tokens, i) {
                    push(
                        out,
                        lines,
                        codes::KQL_UNSCOPED_UNION,
                        format!(
                            "unscoped `union` uses wildcard table `*` and reads every table; name the tables instead ({CITE})"
                        ),
                        start,
                        end,
                    );
                }
                at_source = false;
                after_pipe = false;
            }
            Kind::Word(_) | Kind::String | Kind::Star => {
                if at_source {
                    at_source = false;
                }
                after_pipe = false;
            }
            Kind::Semi => {}
        }
    }
}

fn classify_search(tokens: &[Tok], index: usize) -> SearchShape {
    let mut depth = 0i32;
    let mut saw_in = false;
    let mut list_at = None;
    let mut predicate = false;
    for (offset, tok) in tokens.iter().enumerate().skip(index + 1) {
        match &tok.kind {
            Kind::Pipe | Kind::Semi if depth == 0 => break,
            Kind::RParen if depth == 0 => break,
            Kind::LParen => {
                if saw_in && depth == 0 && list_at.is_none() {
                    list_at = Some(offset);
                }
                depth += 1;
            }
            Kind::RParen => {
                depth -= 1;
            }
            Kind::Word(word) if depth == 0 && word == "in" => {
                saw_in = true;
            }
            Kind::Word(word)
                if depth == 0 && word != "kind" && word != "isfuzzy" && word != "withsource" =>
            {
                predicate = true;
            }
            Kind::Star | Kind::String if depth == 0 => {
                predicate = true;
            }
            _ => {}
        }
    }
    if let Some(paren) = list_at {
        let stars = stars_in_list(tokens, paren);
        if stars.is_empty() {
            SearchShape::Scoped
        } else {
            SearchShape::Wildcard(stars)
        }
    } else if predicate {
        SearchShape::Unscoped
    } else {
        SearchShape::Scoped
    }
}

fn stars_in_list(tokens: &[Tok], paren_idx: usize) -> Vec<(usize, usize)> {
    let mut depth = 0i32;
    let mut stars = Vec::new();
    for tok in tokens.iter().skip(paren_idx) {
        match &tok.kind {
            Kind::LParen => depth += 1,
            Kind::RParen => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Kind::Star if depth == 1 => stars.push((tok.start, tok.end)),
            _ => {}
        }
    }
    stars
}

fn union_star(tokens: &[Tok], union_idx: usize) -> Option<(usize, usize)> {
    let mut depth = 0i32;
    for tok in tokens.iter().skip(union_idx + 1) {
        match &tok.kind {
            Kind::Pipe | Kind::Semi if depth == 0 => break,
            Kind::RParen if depth == 0 => break,
            Kind::LParen => depth += 1,
            Kind::RParen => depth -= 1,
            Kind::Star if depth == 0 => return Some((tok.start, tok.end)),
            _ => {}
        }
    }
    None
}

fn push(
    out: &mut Vec<Diagnostic>,
    lines: &LineIndex,
    code: &str,
    message: String,
    start: usize,
    end: usize,
) {
    // The spans come from the query itself: never past its end.
    if start >= end {
        return;
    }
    let range = lines.range(ByteSpan::new(start, end));
    if out.iter().any(|d| d.code == code && d.range == range) {
        return;
    }
    out.push(Diagnostic::warning(code, message, range));
}
