//! I/O-free Kibana Query Language (`kuery`) engine: parse, Kibana's literal
//! rules, Lucene syntax that KQL reads as plain text, highlighting, hover, and
//! completion. `kuery` is Elastic's KQL; Kusto KQL is the `kql` language.
//!
//! The grammar follows Kibana's `kuery/grammar/grammar.peggy`. Two Kibana
//! behaviours sit below the grammar and are checked here: an unquoted literal
//! ends at an unescaped `not` followed by whitespace, and Lucene operators
//! (`[a TO b]`, `_exists_`, `~`, `^`, `/re/`) are searched as literal text.
//!
//! The parser is pure Rust: a logos lexer and a hand-written recursive-descent
//! grammar (`parser`) over the `opentide-parse` toolkit, into a lossless rowan
//! tree (`syntax`).
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

use opentide_core::{ByteSpan, CompletionItem, Diagnostic, LineIndex, Range, Severity, codes};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_parse::TokenSet;
use regex::Regex;
use rowan::{NodeOrToken, TextRange, TextSize, WalkEvent};
use std::sync::OnceLock;
use syntax::{SyntaxElement, SyntaxKind as K, SyntaxNode, SyntaxToken};

mod ecs;
mod parser;
mod syntax;

/// The tree of `source` and its errors as indented text, for the snapshot
/// tests of the parser (`tests/trees.rs`). Not part of the API.
#[doc(hidden)]
pub fn debug_parse(source: &str) -> String {
    parser::debug(source)
}

pub use ecs::ecs_diagnostics;

/// Whether Kibana's KQL grammar accepts `source` as written: no syntax error,
/// without the masking of a trailing `or`, `and` or `not` that [`analyze`]
/// applies. The Lucene engine asks it of a query it rejects (a sign the query
/// was written for `language: kuery`).
#[must_use]
pub fn parses(source: &str) -> bool {
    parser::accepts(source, false)
}

/// The parse [`analyze`] runs, tree included, and its error count: the
/// throughput benchmark's parse (`cargo bench --bench throughput`, ADR 0014).
/// Not API.
#[doc(hidden)]
#[must_use]
pub fn parse_tree(source: &str) -> usize {
    parser::parse(source, true).1.errors.len()
}

const KQL_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/kql";

/// What [`analyze`] finds in one query.
pub struct AnalyzeResult {
    /// The query's diagnostics, parse error included.
    pub diagnostics: Vec<Diagnostic>,
    /// The query's highlight tokens (HighlightSpec captures).
    pub tokens: Vec<HighlightToken>,
}

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
/// Parses a Kibana KQL query as Kibana reads it, checks it, and highlights it.
///
/// `lucene_parses` is the Lucene grammar's verdict on a text (pass
/// `opentide_lucene::parses`): a query Kibana rejects and Lucene accepts is one
/// sign that it was written for `language: lucene`. The Lucene engine depends
/// on this one ([`parses`]), so it cannot be called from here.
pub fn analyze(source: &str, lucene_parses: fn(&str) -> bool) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    // Kibana reads `or`, `and`, and `not` as keywords only with whitespace
    // after them; at the end of the query or before `)` they are value text.
    let parsed = parser::parse_memo(source);
    let (root, parse) = &*parsed;
    let lines = LineIndex::new(source);
    // Recovery builds fragments after a syntax error that Kibana never
    // reads: the advice about text and Lucene shapes is for what Kibana
    // parsed, so a node past the first error gets none.
    let first_error = parse.errors.iter().map(|e| e.gap.start()).min();
    // The characters no token takes (a lone `\`), sorted: a node glued to
    // one (`process\-name`) is part of the same broken word.
    let error_tokens: Vec<TextRange> = if first_error.is_some() {
        root.descendants_with_tokens()
            .filter(|e| e.kind() == K::ErrorToken)
            .map(|e| e.text_range())
            .collect()
    } else {
        Vec::new()
    };
    let error_starts_at = |at: TextSize| {
        error_tokens
            .binary_search_by_key(&at, |r| r.start())
            .is_ok()
    };
    let error_ends_at = |at: TextSize| error_tokens.binary_search_by_key(&at, |r| r.end()).is_ok();
    let glued_after = |node: &SyntaxNode| error_starts_at(node.text_range().end());
    let recovered = |node: &SyntaxNode| {
        first_error.is_some_and(|at| node.text_range().end() > at) || glued_after(node)
    };
    // Lucene shapes: reported on a clean parse. On a broken one they still
    // count toward `looks_like_lucene` (Lucene text breaks KQL), except in a
    // fragment glued to a character no token takes (`process\-name`: the
    // `-` follows a `\`, it is no prefix).
    let glued = |node: &SyntaxNode| error_ends_at(node.text_range().start());
    let mut lucene_signals = Vec::new();
    let mut diagnostics = Vec::new();
    if let Some(d) = parse_error(root, parse, source, &lines) {
        diagnostics.push(d);
    }
    for event in root.preorder_with_tokens() {
        let WalkEvent::Enter(element) = event else {
            continue;
        };
        match element {
            NodeOrToken::Node(node) => match node.kind() {
                K::UnquotedLiteral => {
                    diagnostics.extend(embedded_not(&node, source, &lines));
                    if !glued(&node)
                        && let Some(d) = lucene_syntax(&node, source, &lines)
                    {
                        if first_error.is_none() {
                            diagnostics.push(d.clone());
                        }
                        lucene_signals.push(d);
                    }
                    diagnostics.extend(unquoted_escapes(&node, source, &lines));
                    diagnostics.extend(question_mark(&node, source, &lines));
                }
                K::NestedQuery => diagnostics.extend(exclusive_range(&node, source, &lines)),
                K::RangeExpression => diagnostics.extend(range_type(&node, source, &lines)),
                K::ValueExpression if !recovered(&node) => {
                    diagnostics.extend(free_text(&node, source, &lines));
                }
                _ => {}
            },
            NodeOrToken::Token(token) => match token.kind() {
                K::OrKw | K::AndKw | K::NotKw => {
                    diagnostics.extend(keyword_spacing(&token, source, &lines));
                }
                K::QuotedString => diagnostics.extend(quoted_string(&token, &lines)),
                _ => {}
            },
        }
    }
    let lucene_only = !parse.errors.is_empty() && lucene_parses(source);
    if let Some(d) = looks_like_lucene(lucene_only, source, &lines, &lucene_signals) {
        diagnostics.push(d);
    }
    let tokens = highlight(spec, root, source);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// The first syntax error, in words: what is missing or which rule was
/// broken. (Kibana's own text, `Expected AND, OR, or end of input but ":"
/// found.`, comes from its PEG parser's furthest failure.)
fn parse_error(
    root: &SyntaxNode,
    parse: &opentide_parse::Parse,
    source: &str,
    lines: &LineIndex<'_>,
) -> Option<Diagnostic> {
    let err = parse.errors.first()?;
    let at = usize::from(err.gap.start());
    let before = source[..at].trim_end();
    let (message, span) = match err.message.as_str() {
        parser::MISSING_PAREN => ("KQL syntax error: a `(` is never closed".into(), point(at)),
        parser::MISSING_BRACE => (
            "KQL syntax error: a nested query `field:{` is never closed".into(),
            point(at),
        ),
        // Nothing names what is missing (`)` at the start): the token there
        // is the error.
        parser::MISSING_VALUE
            if missing_after(before).ends_with("too early")
                && usize::from(err.gap.end()) < source.trim_end().len() =>
        {
            let next = root
                .token_at_offset(err.gap.end())
                .right_biased()
                .map_or(point(usize::from(err.gap.end())), |t| {
                    node_span(t.text_range())
                });
            (unexpected_message(source, next, err.expected), next)
        }
        parser::MISSING_VALUE => (missing_after(before), point(at)),
        other => {
            // An error node starts where the gap ends.
            let node = root
                .descendants()
                .find(|n| n.kind() == K::Error && n.text_range().start() >= err.gap.end());
            let span = node.map_or(point(usize::from(err.gap.end())), |n| {
                node_span(n.text_range())
            });
            let message = if other == parser::UNEXPECTED {
                unexpected_message(source, span, err.expected)
            } else {
                format!("KQL syntax error: {other}")
            };
            // An unclosed quote: from the quote to the end of the query.
            match unclosed_quote(source) {
                Some(at) if message.ends_with("quoted string is never closed") => {
                    (message, ByteSpan::new(at, source.len()))
                }
                _ => (message, span),
            }
        }
    };
    // At the end of the query: an empty span after its last token, not one
    // over the blanks that follow it.
    let span = if span.start >= source.trim_end().len() {
        ByteSpan::new(span.start, span.start)
    } else {
        span
    };
    Some(Diagnostic::error(
        codes::KUERY_PARSE_ERROR,
        message,
        range(lines, span),
    ))
}

/// Text that does not fit where it stands.
/// The expected set says what would fit there (Kibana's own message names
/// it too: `Expected AND, OR, or end of input but ":" found.`).
fn unexpected_message(source: &str, span: ByteSpan, expected: TokenSet) -> String {
    let before = source[..span.start].trim_end();
    // An unclosed quote anywhere breaks the query; recovery reads past the
    // first error, and the quote is what to fix (tree-sitter's error ran to
    // the end of the text and said so).
    if unclosed_quote(source).is_some() {
        return "KQL syntax error: a quoted string is never closed".into();
    }
    let t = source.get(span.start..span.end).unwrap_or("");
    // `a:1 b:2`: KQL has no implicit `and`, so `1 b` is one value and the
    // second `:` is out of place.
    if let Some((value, op)) = implicit_and(source, span.start, span.end) {
        return format!(
            "KQL syntax error: KQL has no implicit `and`; `{value}` is read as one value, so the `{op}` after it is unexpected. Join the clauses with `and`"
        );
    }
    if t.trim().is_empty() || span.start >= source.trim_end().len() {
        return missing_after(before);
    }
    let expected = opentide_parse::describe_expected(expected, |k| K::from_raw(k).describe())
        .map_or_else(String::new, |names| format!("; expected {names}"));
    match t.split_whitespace().next() {
        Some(word) => format!("KQL syntax error near `{word}`{expected}"),
        None => "KQL syntax error".into(),
    }
}

/// `kuery_range_type` (hint): a range on a field ECS maps as a string type
/// compares text, not numbers (`"10" < "9"`). Fields outside ECS, or with a
/// numeric, date, or ip type, are left alone: the list is never closed.
fn range_type(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    let field = child(node, K::Field)?;
    let name = text(field.text_range(), source).trim_matches('"');
    let ecs = opentide_ecs::field(name)?;
    if ecs.class() != opentide_ecs::TypeClass::Text {
        return None;
    }
    let mut d = Diagnostic::warning(
        codes::KUERY_RANGE_TYPE,
        format!(
            "ECS {} maps `{name}` as `{}`: a range compares it as text, so \"10\" sorts before \"9\"",
            opentide_ecs::version(),
            ecs.type_name
        ),
        range(lines, node_span(node.text_range())),
    );
    d.severity = opentide_core::Severity::Hint;
    Some(d)
}

/// Kibana's `UnquotedCharacter` stops at `!Keyword`, and `Keyword` includes
/// `'not'i Space` with no space required before it. `cannot run` therefore
/// ends the value at `can`, and the query fails.
#[expect(
    clippy::expect_used,
    reason = "a regex literal: an invalid pattern fails every test that reaches it"
)]
fn embedded_not(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    static NOT_SPACE: OnceLock<Regex> = OnceLock::new();
    let re = NOT_SPACE.get_or_init(|| Regex::new(r"(?i)not[ \t\r\n\u{00A0}]").expect("regex"));
    let (start, mut end) = bounds(node.text_range());
    // The literal plus the whitespace Kibana reads after it, when more follows.
    // Kibana parses the text as given; a trailing `not ` fails too.
    let rest = source.get(end..).unwrap_or("");
    let ws = rest.len()
        - rest
            .trim_start_matches([' ', '\t', '\r', '\n', '\u{00A0}'])
            .len();
    if ws > 0 {
        end += rest.chars().next().map_or(0, char::len_utf8);
    }
    let window = source.get(start..end)?;
    let m = re
        .find_iter(window)
        .find(|m| m.start() == 0 || window.as_bytes()[m.start() - 1] != b'\\')?;
    let at = start + m.start();
    Some(
        Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            "Kibana ends an unquoted value at `not ` and rejects the query; quote the value",
            range(lines, ByteSpan::new(at, at + 3)),
        )
        .with_suggestion(format!("\"{}\"", text(node.text_range(), source))),
    )
}

/// Lucene syntax KQL parses as literal text, so the rule silently matches
/// something else. Ranges, `_exists_`, and prefix operators are warnings;
/// regex and fuzzy/boost shapes are hints, because paths and 8.3 names look
/// alike.
fn lucene_syntax(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    let literal = text(node.text_range(), source);
    let in_field = node.parent().is_some_and(|p| p.kind() == K::Field);
    let span = node_span(node.text_range());
    let diagnostic = |severity: Severity, message: &str| {
        let mut d = Diagnostic::warning(codes::KUERY_LUCENE_SYNTAX, message, range(lines, span));
        d.severity = severity;
        Some(d)
    };
    let trimmed = literal.trim();
    if in_field {
        if literal == "_exists_" {
            diagnostic(
                Severity::Warning,
                "`_exists_:field` is Lucene; in KQL write `field:*`",
            )
        } else if literal.starts_with(['+', '-', '!']) {
            diagnostic(
                Severity::Warning,
                "`+`, `-`, and `!` prefixes are Lucene; KQL reads them as part of the field name. Use `not field:value`",
            )
        } else {
            None
        }
    } else if (trimmed.starts_with('[') || trimmed.starts_with('{'))
        && (trimmed.contains(" TO ") || trimmed.contains(" to "))
    {
        diagnostic(
            Severity::Warning,
            "`[a TO b]` is a Lucene range; KQL searches it as text. Use `field >= a and field <= b`",
        )
    } else if matches!(trimmed, "&&" | "||") {
        diagnostic(
            Severity::Warning,
            "`&&` and `||` are Lucene; KQL uses `and` and `or`",
        )
    } else if looks_like_regex(trimmed) {
        diagnostic(
            Severity::Hint,
            "`/regex/` is Lucene; KQL has no regular expressions and searches it as text",
        )
    } else if fuzzy_or_boost(trimmed) {
        diagnostic(
            Severity::Hint,
            "`~` (fuzzy, proximity) and `^` (boost) are Lucene; KQL searches them as text",
        )
    } else {
        None
    }
}

/// Kibana's `Or` and `And` need whitespace on both sides and `Not` after it:
/// `not(a:1)` and `a:1 and(b:2)` are syntax errors.
fn keyword_spacing(token: &SyntaxToken, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    let (start, end) = bounds(token.text_range());
    let before = source[..start].chars().next_back();
    let after = source[end..].chars().next();
    let needs_before = token.kind() != K::NotKw;
    let missing =
        (needs_before && !before.is_some_and(is_kql_space)) || !after.is_some_and(is_kql_space);
    missing.then(|| {
        let word = token.text();
        let place = if needs_before { "around" } else { "after" };
        Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            format!("Kibana needs whitespace {place} `{word}`"),
            range(lines, node_span(token.text_range())),
        )
    })
}

/// `field:{1 TO 5}` is a Lucene exclusive range; Kibana reads a nested query.
fn exclusive_range(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    // The nested query is the node after the field.
    let query = node.children().nth(1)?;
    let body = text(query.text_range(), source);
    (query.kind() == K::ValueExpression && (body.contains(" TO ") || body.contains(" to "))).then(|| {
        Diagnostic::warning(
            codes::KUERY_LUCENE_SYNTAX,
            "`{a TO b}` is a Lucene range; Kibana reads `field:{ ... }` as a nested query. Use `field > a and field < b`",
            range(lines, node_span(node.text_range())),
        )
    })
}

/// `\not` outside quotes: Kibana reads `\n` first, a newline plus `ot`.
fn unquoted_escapes(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Vec<Diagnostic> {
    let (start, _) = bounds(node.text_range());
    text(node.text_range(), source)
        .match_indices("\\not")
        .map(|(i, _)| {
            let at = start + i;
            Diagnostic::warning(
                codes::KUERY_ESCAPE,
                "Kibana reads `\\not` as a newline followed by `ot`; write `\\NOT` or quote the value",
                range(lines, ByteSpan::new(at, at + 4)),
            )
            .with_suggestion("\\NOT")
        })
        .collect()
}

/// Inside quotes Kibana turns `\t`, `\r`, and `\n` into control characters
/// (`"C:\temp"` searches a TAB), and `*` is a literal asterisk.
fn quoted_string(token: &SyntaxToken, lines: &LineIndex<'_>) -> Vec<Diagnostic> {
    let t = token.text();
    let (start, _) = bounds(token.text_range());
    let bytes = t.as_bytes();
    let mut out = Vec::new();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            let followed_by_word = bytes.get(i + 2).is_some_and(u8::is_ascii_alphanumeric);
            if matches!(next, b't' | b'r' | b'n') && followed_by_word {
                let at = start + i;
                out.push(
                    Diagnostic::warning(
                        codes::KUERY_ESCAPE,
                        format!(
                            "Kibana turns `\\{}` inside quotes into a control character; write `\\\\{}` for a backslash",
                            next as char, next as char
                        ),
                        range(lines, ByteSpan::new(at, at + 2)),
                    )
                    .with_suggestion(format!("\\\\{}", next as char)),
                );
                break;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    let inner = t.get(1..t.len().saturating_sub(1)).unwrap_or("");
    if inner.contains('*') && inner != "*" {
        let mut d = Diagnostic::warning(
            codes::KUERY_QUOTED_WILDCARD,
            "`*` inside quotes is a literal asterisk in KQL, not a wildcard; drop the quotes and escape spaces to match a pattern",
            range(lines, node_span(token.text_range())),
        );
        d.severity = opentide_core::Severity::Hint;
        out.push(d);
    }
    out
}

/// `?` is not a wildcard in KQL: `jo?n` searches the text `jo?n`.
fn question_mark(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    let t = text(node.text_range(), source);
    let i = t.find('?')?;
    // A URL query string (`/path?x=1`, `/api/secrets?limit*`) is a real
    // question mark: a path before it and none after it.
    let (path, query) = t.split_at(i);
    if t.contains('=') || t.contains("://") || (path.contains('/') && !query.contains('/')) {
        return None;
    }
    let at = bounds(node.text_range()).0 + i;
    let mut d = Diagnostic::warning(
        codes::KUERY_QUESTION_MARK,
        "`?` is a literal character in KQL, not a single-character wildcard; use `*` to match any characters",
        range(lines, ByteSpan::new(at, at + 1)),
    );
    d.severity = Severity::Hint;
    Some(d)
}

/// A value with no field. Kibana searches it in every field
/// (`index.query.default_field`), and after `f:a and` it is easy to read
/// `b` as part of `f`.
fn free_text(node: &SyntaxNode, source: &str, lines: &LineIndex<'_>) -> Option<Diagnostic> {
    let value = text(node.text_range(), source);
    if value.trim() == "*" {
        return None;
    }
    // Inside a nested query the field context is the nested field.
    if node.ancestors().any(|n| n.kind() == K::NestedQuery) {
        return None;
    }
    // A chain is one flat node; the binary grammar's `left` of the second
    // operand is the first one, and of any later operand a whole chain.
    let parent = node.parent();
    let sibling_field = parent.as_ref().and_then(|parent| {
        if !matches!(parent.kind(), K::AndQuery | K::OrQuery) {
            return None;
        }
        let mut operands = parent.children();
        let left = operands.next()?;
        (operands.next().as_ref() == Some(node) && left.kind() == K::FieldValueExpression)
            .then_some(left)
    });
    let message = match (sibling_field, parent) {
        (Some(left), Some(parent)) => {
            let field = child(&left, K::Field).map_or("", |f| text(f.text_range(), source));
            let op = parent
                .children_with_tokens()
                .find(|e| matches!(e.kind(), K::AndKw | K::OrKw))
                .map_or_else(
                    || "and".into(),
                    |o| text(o.text_range(), source).to_ascii_lowercase(),
                );
            let first = field_value(&left).map_or("", |v| text(v.text_range(), source));
            format!(
                "`{value}` has no field, so Kibana searches it in every field, not in `{field}`; to search `{field}` write `{field}:({first} {op} {value})`"
            )
        }
        _ => format!(
            "`{value}` has no field, so Kibana searches it in every field (`index.query.default_field`); name the field (`field:{value}`)"
        ),
    };
    let mut d = Diagnostic::warning(
        codes::KUERY_FREE_TEXT,
        message,
        range(lines, node_span(node.text_range())),
    );
    d.severity = Severity::Hint;
    Some(d)
}

/// KQL text that reads like Lucene. One sign can be a coincidence; two
/// different kinds of Lucene syntax are a rule written for `language: lucene`.
fn looks_like_lucene(
    lucene_only: bool,
    source: &str,
    lines: &LineIndex<'_>,
    found: &[Diagnostic],
) -> Option<Diagnostic> {
    let mut signals: Vec<&str> = Vec::new();
    for d in found
        .iter()
        .filter(|d| d.code == codes::KUERY_LUCENE_SYNTAX)
    {
        let kind = if d.message.contains("TO b") {
            "ranges"
        } else if d.message.contains("_exists_") {
            "`_exists_`"
        } else if d.message.starts_with("`+`") {
            "`+`/`-` prefixes"
        } else if d.message.starts_with("`&&`") {
            "`&&`/`||`"
        } else if d.message.contains("/regex/") {
            "a regular expression"
        } else {
            "fuzzy or boost suffixes"
        };
        if !signals.contains(&kind) {
            signals.push(kind);
        }
    }
    // Kibana rejects the text, and the Lucene grammar accepts it.
    if lucene_only {
        signals.push("text only Lucene parses");
    }
    (signals.len() >= 2).then(|| {
        Diagnostic::warning(
            codes::KUERY_LOOKS_LIKE_LUCENE,
            format!(
                "this query reads like Lucene ({}); if it is an Elastic rule, set `language: lucene`",
                signals.join(", ")
            ),
            range(lines, ByteSpan::new(0, source.len())),
        )
    })
}

fn is_kql_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{00A0}')
}

/// A value with whitespace in it followed by `:`, `<`, or `>` near the
/// error: two clauses with no `and` between them.
fn implicit_and(source: &str, start: usize, end: usize) -> Option<(String, char)> {
    // Back up to the start of the clause the error is in.
    let from = source[..start]
        .rfind(['(', ')', ':', '<', '>', '"'])
        .map_or(0, |i| i + 1);
    let to = (end + 1).min(source.len());
    let region = source.get(from..to)?;
    let mut segment = String::new();
    let mut in_quotes = false;
    for c in region.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                segment.clear();
            }
            _ if in_quotes => {}
            ':' | '<' | '>' => {
                let value = segment.trim();
                if value.contains(char::is_whitespace) {
                    return Some((value.to_string(), c));
                }
                segment.clear();
            }
            '(' | ')' | '=' => segment.clear(),
            _ => segment.push(c),
        }
    }
    None
}

/// What the query lacks when it ends after `before`.
fn missing_after(before: &str) -> String {
    // The last word, without the brackets glued before it (`(b:` names `b:`).
    let last = before
        .rsplit(|c: char| is_kql_space(c) || matches!(c, '(' | '{'))
        .next()
        .unwrap_or("");
    let lower = last.to_ascii_lowercase();
    if last.ends_with([':', '<', '>', '=']) {
        format!("KQL syntax error: a value is missing after `{last}`")
    } else if matches!(lower.as_str(), "or" | "and" | "not") {
        format!("KQL syntax error: a query is missing after `{last}`")
    } else {
        "KQL syntax error: the query ends too early".into()
    }
}

/// Byte offset of an opening `"` with no closing quote.
fn unclosed_quote(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut open: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // In a quoted string a backslash escapes any character but a
            // line break, as the lexer reads it: `"x\<LF>` never closes.
            b'\\' if open.is_some() && bytes.get(i + 1) == Some(&b'\n') => return open,
            b'\\' => i += 1,
            b'"' => open = if open.is_some() { None } else { Some(i) },
            _ => {}
        }
        i += 1;
    }
    open
}

/// `/…/` with a regex metacharacter. A plain path such as
/// `/var/lib/tool/` is not one.
fn looks_like_regex(word: &str) -> bool {
    word.len() > 2
        && word.starts_with('/')
        && word.ends_with('/')
        && word[1..word.len() - 1].contains(['^', '$', '+', '?', '|', '[', ']', '\\'])
}

fn fuzzy_or_boost(word: &str) -> bool {
    // `PROGRA~1` and paths are 8.3 short names, not fuzzy terms.
    if word.contains(['\\', '.', '/']) {
        return false;
    }
    if let Some((head, _)) = word.split_once('~')
        && head.len() <= 6
        && head
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    let tail = |sep: char| {
        word.rsplit_once(sep).is_some_and(|(head, n)| {
            !head.is_empty()
                && !head.ends_with('\\')
                && (n.is_empty() || n.chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
    };
    tail('~') || tail('^')
}

/// The first child node of `kind`.
fn child(node: &SyntaxNode, kind: K) -> Option<SyntaxNode> {
    node.children().find(|c| c.kind() == kind)
}

/// The value of a `field:value` node: a list node, or a literal (a node or
/// a quoted-string token), the first element after the `:`.
fn field_value(node: &SyntaxNode) -> Option<SyntaxElement> {
    node.children_with_tokens()
        .skip_while(|e| e.kind() != K::Colon)
        .skip(1)
        .find(|e| e.kind() != K::Whitespace)
}

fn bounds(r: TextRange) -> (usize, usize) {
    (usize::from(r.start()), usize::from(r.end()))
}

/// A range, never empty so editors can show it.
fn node_span(r: TextRange) -> ByteSpan {
    let (start, end) = bounds(r);
    ByteSpan::new(start, end.max(start + 1))
}

fn point(at: usize) -> ByteSpan {
    ByteSpan::new(at, at + 1)
}

/// The LSP range of `span`: a binary search in the line index, so a query
/// with thousands of diagnostics stays linear.
fn range(lines: &LineIndex<'_>, span: ByteSpan) -> Range {
    lines.range(span)
}

fn text(r: TextRange, source: &str) -> &str {
    source.get(std::ops::Range::<usize>::from(r)).unwrap_or("")
}

/// The HighlightSpec capture of each token: the tree-sitter highlight query
/// (`highlights/queries/kuery/highlights.scm`) as a match on kinds.
#[expect(
    clippy::expect_used,
    reason = "regex literals: an invalid pattern fails every test that reaches it"
)]
fn capture(token: &SyntaxToken) -> Option<&'static str> {
    static NUMBER: OnceLock<Regex> = OnceLock::new();
    let in_field = |levels: usize| {
        token
            .parent_ancestors()
            .nth(levels)
            .is_some_and(|n| n.kind() == K::Field)
    };
    Some(match token.kind() {
        K::Word
            if token
                .parent()
                .is_some_and(|p| p.kind() == K::UnquotedLiteral)
                && in_field(1) =>
        {
            "property"
        }
        K::QuotedString if in_field(0) => "property",
        K::Word => {
            let t = token.text();
            let number =
                NUMBER.get_or_init(|| Regex::new(r"^-?[0-9]+(\.[0-9]+)?$").expect("regex"));
            if t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("false") {
                "boolean"
            } else if t.eq_ignore_ascii_case("null") {
                "constant"
            } else if number.is_match(t) {
                "number"
            } else {
                "string"
            }
        }
        K::QuotedString => "string",
        K::OrKw | K::AndKw | K::NotKw => "keyword",
        K::Colon | K::Lt | K::Lte | K::Gt | K::Gte => "operator",
        K::LParen | K::RParen | K::LBrace | K::RBrace => "punctuation.bracket",
        _ => return None,
    })
}

fn highlight(spec: &HighlightSpec, root: &SyntaxNode, source: &str) -> Vec<HighlightToken> {
    let spans: Vec<(ByteSpan, &str)> = root
        .descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .filter_map(|t| {
            let (start, end) = bounds(t.text_range());
            Some((ByteSpan::new(start, end), capture(&t)?))
        })
        .collect();
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
}

/// Field names a query mentions, for completion and for Tide checks.
pub fn fields(source: &str) -> Vec<String> {
    let parsed = parser::parse_memo(source);
    let root = &parsed.0;
    let names: std::collections::BTreeSet<String> = root
        .descendants()
        .filter(|n| n.kind() == K::Field)
        .map(|n| text(n.text_range(), source).trim_matches('"').to_string())
        .collect();
    names.into_iter().collect()
}

const OPERATORS: &[(&str, &str)] = &[
    (
        "and",
        "Both clauses must match. Case-insensitive; binds tighter than `or`.",
    ),
    ("or", "Either clause matches. Case-insensitive."),
    ("not", "Negates the clause that follows. Case-insensitive."),
    (
        ":",
        "`field:value` matches a value; `field:*` matches documents that have the field; `field:{ ... }` queries a nested field.",
    ),
    ("<", "Range: less than."),
    ("<=", "Range: less than or equal."),
    (">", "Range: greater than."),
    (">=", "Range: greater than or equal."),
];

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset) {
        return None;
    }
    let (root, _) = parser::parse(source, false);
    // The token under the cursor (the one that starts there at a boundary),
    // else the smallest node around it.
    let at = TextSize::from(u32::try_from(offset).ok()?);
    // As tree-sitter's root: from the first token to the end of the text.
    let first = root
        .descendants_with_tokens()
        .find(|e| e.as_token().is_some_and(|t| t.kind() != K::Whitespace));
    let end = root.text_range().end();
    let mut range = TextRange::new(first.map_or(end, |f| f.text_range().start()), end);
    let mut node = root;
    loop {
        let inner = node
            .children_with_tokens()
            .filter(|e| e.kind() != K::Whitespace)
            .find(|e| e.text_range().start() <= at && at < e.text_range().end());
        match inner {
            Some(NodeOrToken::Node(n)) => {
                range = n.text_range();
                node = n;
            }
            Some(NodeOrToken::Token(t)) => {
                range = t.text_range();
                break;
            }
            None => break,
        }
    }
    let word = text(range, source).to_ascii_lowercase();
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (KQL)\n\n{d}\n\n[Elastic docs]({KQL_DOCS})"))
}

/// The completions at byte `offset` of `source`.
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let mut items = Vec::new();
    let after_value = before
        .trim_end()
        .chars()
        .last()
        .is_some_and(|c| !matches!(c, ':' | '(' | '{' | '<' | '>' | '='));
    if after_value && before.ends_with(char::is_whitespace) {
        for kw in ["and", "or", "not"] {
            items.push(CompletionItem::new(kw, "keyword"));
        }
    }
    items.extend(
        fields(source)
            .into_iter()
            .map(|f| CompletionItem::new(f, "property")),
    );
    items
}

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<syntax::Kuery>(&parser::parse(source, false).1)
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<syntax::Kuery>(&parser::parse(source, false).1)
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

    /// [`super::analyze`] with a Lucene grammar that accepts nothing: the
    /// Lucene engine depends on this crate, so its verdict is out of reach
    /// here. opentide-lucene's `tests/language_hints.rs` runs the two
    /// engines together.
    fn analyze(source: &str) -> AnalyzeResult {
        super::analyze(source, |_| false)
    }

    #[test]
    fn range_on_an_ecs_text_field_is_a_hint() {
        let hints = |src: &str| -> Vec<String> {
            analyze(src)
                .diagnostics
                .into_iter()
                .filter(|d| d.code == codes::KUERY_RANGE_TYPE)
                .map(|d| d.message)
                .collect()
        };
        assert_eq!(hints("process.name >= 10").len(), 1);
        assert!(hints("source.port >= 1024").is_empty());
        assert!(hints("@timestamp > now-1d").is_empty());
        assert!(hints("my.custom.count > 5").is_empty());
    }

    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn detection_query_is_clean() {
        let src = "event.category:process and process.name:(\"cmd.exe\" or powershell.exe) and not user.name:SYSTEM and source.port >= 1024";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
    }

    #[test]
    fn not_inside_an_unquoted_value_fails_in_kibana() {
        assert!(codes_of("message: cannot run").contains(&codes::KUERY_PARSE_ERROR.to_string()));
        assert!(codes_of("message:knot and x:1").contains(&codes::KUERY_PARSE_ERROR.to_string()));
        assert!(codes_of("message:knot").is_empty());
        assert!(codes_of("message:\"cannot run\"").is_empty());
        // `\not` escapes the keyword, but Kibana reads `\n` first.
        let c = codes_of("message: can\\not run");
        assert!(!c.contains(&codes::KUERY_PARSE_ERROR.to_string()), "{c:?}");
        assert!(c.contains(&codes::KUERY_ESCAPE.to_string()), "{c:?}");
        assert!(codes_of("not message:x").is_empty());
        assert!(codes_of("process.executable:/var/lib/command-not-found/").is_empty());
        assert!(codes_of("file.name:PROGRA~1").is_empty());
    }

    #[test]
    fn lucene_constructs_are_flagged() {
        for src in [
            "bytes:[100 TO 200]",
            "_exists_:host.name",
            "name:jon~2",
            "title:/joh?n/",
            "path:/[a-z]+/",
            "-user.name:root",
        ] {
            assert!(
                codes_of(src).contains(&codes::KUERY_LUCENE_SYNTAX.to_string()),
                "{src}"
            );
        }
    }

    #[test]
    fn kibana_whitespace_and_escape_rules() {
        for src in ["not(a:1)", "a:1 and(b:2)", "(a:1)and(b:2)"] {
            assert!(
                codes_of(src).contains(&codes::KUERY_PARSE_ERROR.to_string()),
                "{src}"
            );
        }
        assert!(codes_of("(a:1) and (b:2)").is_empty());
        assert!(codes_of("x:{1 TO 5}").contains(&codes::KUERY_LUCENE_SYNTAX.to_string()));
        assert!(codes_of("path:\"C:\\temp\\x\"").contains(&codes::KUERY_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\\\temp\"").is_empty());
        assert!(codes_of("msg:can\\not").contains(&codes::KUERY_ESCAPE.to_string()));
        let r = analyze("process.name:\"cmd*\"");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::KUERY_QUOTED_WILDCARD)
            .expect("quoted wildcard");
        assert_eq!(d.severity, opentide_core::Severity::Hint);
        assert!(codes_of("x:\"*\"").is_empty());
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert!(codes_of("a:1 AND b:2 Or NOT c:3").is_empty());
    }

    fn find(src: &str, code: &str) -> Option<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .find(|d| d.code == code)
    }

    #[test]
    fn trailing_keywords_are_values() {
        // Kibana reads a keyword with no whitespace after it as value text.
        for src in [
            "process.name:cmd.exe or",
            "tags:(a and)",
            "host.os.type:(not)",
            "host.os.type:(windows or)",
            "a:(b or) or c:(d and)",
            "f:{a:1 and}",
            "not",
        ] {
            let r = analyze(src);
            assert!(
                r.diagnostics.iter().all(|d| d.severity != Severity::Error),
                "{src}: {:?}",
                r.diagnostics
            );
        }
        // With whitespace after it, it is a keyword again, and the query fails.
        for src in ["response:200 or ", "response:(200 or )", "tags:(a and )"] {
            assert!(
                codes_of(src).contains(&codes::KUERY_PARSE_ERROR.to_string()),
                "{src}"
            );
        }
        let r = analyze("process.name:cmd.exe or");
        assert!(r.tokens.iter().all(|t| t.capture != "keyword"));
    }

    #[test]
    fn parse_errors_say_what_is_wrong() {
        let message = |src: &str| {
            find(src, codes::KUERY_PARSE_ERROR)
                .unwrap_or_else(|| panic!("{src}"))
                .message
        };
        assert!(message("a:1 b:2").contains("no implicit `and`"));
        assert!(message("message:\"failed login").contains("never closed"));
        assert!(message("(a:1 or b:2").contains("`(` is never closed"));
        assert!(message("process.name:").contains("missing after `process.name:`"));
        assert!(message("a:1 or ").contains("missing after `or`"));
        // `not ` at the very end fails in Kibana as well.
        assert!(codes_of("message:cannot ").contains(&codes::KUERY_PARSE_ERROR.to_string()));
    }

    #[test]
    fn recovery_fragments_get_no_advice() {
        // Kibana reads nothing past the first error: one syntax error, no
        // free-text or Lucene advice on what recovery rebuilt after it.
        for src in [
            r"process\-name:cmd.exe",
            "} or x\" and not  and :b}",
            r"\ not  and 1 :ba:",
        ] {
            let codes = codes_of(src);
            for code in [
                codes::KUERY_FREE_TEXT,
                codes::KUERY_LUCENE_SYNTAX,
                codes::KUERY_LOOKS_LIKE_LUCENE,
            ] {
                assert!(!codes.contains(&code.to_string()), "{src}: {codes:?}");
            }
        }
        // Before the error, and on a clean parse, the advice stays.
        assert!(codes_of("powershell and (b:").contains(&codes::KUERY_FREE_TEXT.to_string()));
        assert!(codes_of("a:[1 TO 2] OR b:x~").contains(&codes::KUERY_LUCENE_SYNTAX.to_string()));
    }

    #[test]
    fn an_unclosed_quote_after_the_first_error_is_named() {
        let d = find("\u{e9}:b1not :b or \"x", codes::KUERY_PARSE_ERROR).expect("an error");
        assert!(
            d.message.ends_with("a quoted string is never closed"),
            "{}",
            d.message
        );
        assert_eq!(d.range.start.character, 14);
    }

    #[test]
    fn an_escaped_line_break_leaves_the_quote_open() {
        // The lexer takes no `\` before a line break inside quotes, so the
        // string never closes; the message says so, from its quote.
        let d = find("a:\"x\\\ny\"", codes::KUERY_PARSE_ERROR).expect("an error");
        assert!(
            d.message.ends_with("a quoted string is never closed"),
            "{}",
            d.message
        );
        assert_eq!(d.range.start.character, 2);
        assert!(find("a:\"x\\ny\"", codes::KUERY_PARSE_ERROR).is_none());
    }

    #[test]
    fn a_missing_value_names_the_field_not_the_bracket() {
        let d = find("a and (b:", codes::KUERY_PARSE_ERROR).expect("an error");
        assert_eq!(d.message, "KQL syntax error: a value is missing after `b:`");
    }

    #[test]
    fn many_diagnostics_convert_their_spans_in_linear_time() {
        // Each diagnostic's range used to scan from the start of the text.
        // A non-ASCII line too: its columns came from a scan of the line.
        for src in [
            format!("a:{}", "\"x ".repeat(8_000)),
            "\u{e9}:\"\u{fc} ".repeat(8_000),
        ] {
            let started = std::time::Instant::now();
            let n = analyze(&src).diagnostics.len();
            assert!(n >= 1);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "{n} diagnostics took {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn analyze_fields_and_ecs_share_one_parse() {
        let src = "source.port:80 and process.name:x";
        let first = parser::parse_memo(src);
        let _ = (analyze(src), fields(src), ecs_diagnostics(src));
        assert!(std::rc::Rc::ptr_eq(&first, &parser::parse_memo(src)));
        assert!(!std::rc::Rc::ptr_eq(&first, &parser::parse_memo("a:1")));
        // A text past the cap is parsed but not kept.
        let large = "a:1 or ".repeat(parser::MEMO_MAX / 7 + 1) + "b:2";
        let once = parser::parse_memo(&large);
        assert!(!std::rc::Rc::ptr_eq(&once, &parser::parse_memo(&large)));
    }

    #[test]
    fn hints_for_kql_literals() {
        let d = find("user.name:jo?n", codes::KUERY_QUESTION_MARK).expect("?");
        assert_eq!(d.severity, Severity::Hint);
        assert!(find("url.original:/a?b=1", codes::KUERY_QUESTION_MARK).is_none());
        assert!(find("uri:/api/v1/secrets?limit*", codes::KUERY_QUESTION_MARK).is_none());
        assert!(find("path:*/GitHub?Copilot/*", codes::KUERY_QUESTION_MARK).is_some());
        assert!(find("user.name:\"jo?n\"", codes::KUERY_QUESTION_MARK).is_none());
        let d = find("powershell", codes::KUERY_FREE_TEXT).expect("free text");
        assert_eq!(d.severity, Severity::Hint);
        let d = find(
            "process.name:cmd.exe and powershell.exe",
            codes::KUERY_FREE_TEXT,
        )
        .expect("free text after a field");
        assert!(
            d.message
                .contains("process.name:(cmd.exe and powershell.exe)"),
            "{}",
            d.message
        );
        assert!(find("*", codes::KUERY_FREE_TEXT).is_none());
        assert!(find("a:1 and b:2", codes::KUERY_FREE_TEXT).is_none());
        assert!(find("user:{ name:x }", codes::KUERY_FREE_TEXT).is_none());
    }

    #[test]
    fn lucene_text_in_a_kuery_rule() {
        let d = find(
            "_exists_:host.name AND bytes:[100 TO 200]",
            codes::KUERY_LOOKS_LIKE_LUCENE,
        )
        .expect("two signals");
        assert_eq!(d.severity, Severity::Warning);
        assert!(d.message.contains("language: lucene"));
        // One signal alone is not enough.
        assert!(find("bytes:[100 TO 200]", codes::KUERY_LOOKS_LIKE_LUCENE).is_none());
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 and b:2", 5).expect("hover");
        assert!(h.contains("and"));
        let items = completions("host.name:x ", 12);
        assert!(items.iter().any(|i| i.label == "and"));
        assert!(items.iter().any(|i| i.label == "host.name"));
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "user.name:\u{e9} and host.name:x";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside).is_empty());
        assert_eq!(hover(src, inside), None);
    }
}
