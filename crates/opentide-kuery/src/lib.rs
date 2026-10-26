//! I/O-free Kibana Query Language (`kuery`) engine: parse, Kibana's literal
//! rules, Lucene syntax that KQL reads as plain text, highlighting, hover, and
//! completion. `kuery` is Elastic's KQL; Kusto KQL is the `kql` language.
//!
//! The grammar follows Kibana's `kuery/grammar/grammar.peggy`. Two Kibana
//! behaviours sit below the grammar and are checked here: an unquoted literal
//! ends at an unescaped `not` followed by whitespace, and Lucene operators
//! (`[a TO b]`, `_exists_`, `~`, `^`, `/re/`) are searched as literal text.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Position, Range, Severity, codes,
    position_to_offset, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use regex::Regex;
use std::sync::OnceLock;
use tree_sitter::Node;

const KQL_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/kql";

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    // Kibana reads `or`, `and`, and `not` as keywords only with whitespace
    // after them; at the end of the query or before `)` they are value text.
    let masked = mask_trailing_keywords(source);
    let Some(tree) = ts_parse(LanguageId::Kuery, &masked) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::KUERY_PARSE_ERROR,
                "failed to initialize the KQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    opentide_syntax::walk_with_ancestors(root, |node, ancestors| match node.kind() {
        "unquoted_literal" => {
            if let Some(d) = embedded_not(node, source) {
                diagnostics.push(d);
            }
            diagnostics.extend(lucene_syntax(node, ancestors, source));
            diagnostics.extend(unquoted_escapes(node, source));
            if let Some(d) = question_mark(node, source) {
                diagnostics.push(d);
            }
        }
        "or" | "and" | "not" => {
            if let Some(d) = keyword_spacing(node, source) {
                diagnostics.push(d);
            }
        }
        "nested_query" => {
            if let Some(d) = exclusive_range(node, source) {
                diagnostics.push(d);
            }
        }
        "range_expression" => {
            if let Some(d) = range_type(node, source) {
                diagnostics.push(d);
            }
        }
        "value_expression" => {
            if let Some(d) = free_text(node, ancestors, source) {
                diagnostics.push(d);
            }
        }
        "quoted_string" => diagnostics.extend(quoted_string(node, source)),
        _ => {}
    });
    if let Some(d) = looks_like_lucene(root, source, &diagnostics) {
        diagnostics.push(d);
    }
    let tokens = highlight(&spec, &masked, source);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// `kuery_range_type` (hint): a range on a field ECS maps as a string type
/// compares text, not numbers (`"10" < "9"`). Fields outside ECS, or with a
/// numeric, date, or ip type, are left alone: the list is never closed.
fn range_type(node: Node, source: &str) -> Option<Diagnostic> {
    let field = node.child_by_field_name("field")?;
    let name = text(field, source).trim_matches('"');
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
        range(source, node_span(node)),
    );
    d.severity = opentide_core::Severity::Hint;
    Some(d)
}

fn is_word_char(c: char) -> bool {
    !is_kql_space(c) && !matches!(c, '\\' | '(' | ')' | ':' | '<' | '>' | '"' | '{' | '}')
}

/// A copy of `source` (same byte offsets) in which an `or`, `and`, or `not`
/// that ends the query or sits before `)` or `}` is replaced by a plain word,
/// because Kibana reads it as part of the value (`f:a or`, `f:(not)`). With
/// whitespace after it, it is a keyword again, and `f:a or ` fails, as
/// Kibana's own syntax-error tests expect.
fn mask_trailing_keywords(source: &str) -> String {
    let end = source.len();
    let bytes = source.as_bytes();
    let mut masked: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < end {
        let c = source[i..].chars().next().unwrap_or(' ');
        if c == '"' {
            // Skip a quoted string.
            i += 1;
            while i < end && bytes[i] != b'"' {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
            continue;
        }
        if !is_word_char(c) && c != '\\' {
            i += c.len_utf8();
            continue;
        }
        // One word token: word characters and backslash escapes.
        let start = i;
        while i < end {
            let c = source[i..].chars().next().unwrap_or(' ');
            if c == '\\' {
                i += 1 + source[i + 1..].chars().next().map_or(0, char::len_utf8);
            } else if is_word_char(c) {
                i += c.len_utf8();
            } else {
                break;
            }
        }
        let word = &source[start..i.min(end)];
        let next = source[i.min(end)..end].chars().next();
        let keyword = ["or", "and", "not"]
            .iter()
            .any(|k| word.eq_ignore_ascii_case(k));
        if keyword && matches!(next, None | Some(')') | Some('}')) {
            let m = masked.get_or_insert_with(|| bytes.to_vec());
            for b in &mut m[start + 1..i] {
                *b = b'_';
            }
        }
    }
    match masked {
        Some(m) => String::from_utf8(m).unwrap_or_else(|_| source.to_string()),
        None => source.to_string(),
    }
}

/// A syntax error in words: what is missing or which rule was broken.
/// (Kibana's own text, `Expected AND, OR, or end of input but ":" found.`,
/// comes from its PEG parser's furthest failure; tree-sitter recovers at a
/// different point, so its lookahead set rarely matches that text.)
fn parse_error_message(err: Node, source: &str) -> String {
    let before = source[..err.start_byte()].trim_end();
    if err.is_missing() {
        return match err.kind() {
            ")" => "KQL syntax error: a `(` is never closed".into(),
            "}" => "KQL syntax error: a nested query `field:{` is never closed".into(),
            _ => missing_after(before),
        };
    }
    if let Some(at) = unclosed_quote(source) {
        if at <= err.end_byte() {
            return "KQL syntax error: a quoted string is never closed".into();
        }
    }
    let t = text(err, source);
    // `a:1 b:2`: KQL has no implicit `and`, so `1 b` is one value and the
    // second `:` is out of place.
    if let Some((value, op)) = implicit_and(source, err.start_byte(), err.end_byte()) {
        return format!(
            "KQL syntax error: KQL has no implicit `and`; `{value}` is read as one value, so the `{op}` after it is unexpected. Join the clauses with `and`"
        );
    }
    if t.trim().is_empty() || err.start_byte() >= source.trim_end().len() {
        return missing_after(before);
    }
    match t.split_whitespace().next() {
        Some(word) => format!("KQL syntax error near `{word}`"),
        None => "KQL syntax error".into(),
    }
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
    let last = before.split_whitespace().next_back().unwrap_or("");
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
            b'\\' => i += 1,
            b'"' => open = if open.is_some() { None } else { Some(i) },
            _ => {}
        }
        i += 1;
    }
    open
}

/// Kibana's `UnquotedCharacter` stops at `!Keyword`, and `Keyword` includes
/// `'not'i Space` with no space required before it. `cannot run` therefore
/// ends the value at `can`, and the query fails.
fn embedded_not(node: Node, source: &str) -> Option<Diagnostic> {
    static NOT_SPACE: OnceLock<Regex> = OnceLock::new();
    let re = NOT_SPACE.get_or_init(|| Regex::new(r"(?i)not[ \t\r\n\u{00A0}]").expect("regex"));
    let start = node.start_byte();
    // The literal plus the whitespace Kibana reads after it, when more follows.
    let mut end = node.end_byte();
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
    for m in re.find_iter(window) {
        let escaped = m.start() > 0 && window.as_bytes()[m.start() - 1] == b'\\';
        if !escaped {
            let at = start + m.start();
            return Some(
                Diagnostic::error(
                    codes::KUERY_PARSE_ERROR,
                    "Kibana ends an unquoted value at `not ` and rejects the query; quote the value",
                    range(source, ByteSpan::new(at, at + 3)),
                )
                .with_suggestion(format!("\"{}\"", source.get(node.start_byte()..node.end_byte()).unwrap_or(""))),
            );
        }
    }
    None
}

/// Lucene syntax KQL parses as literal text, so the rule silently matches
/// something else. Ranges, `_exists_`, and prefix operators are warnings;
/// regex and fuzzy/boost shapes are hints, because paths and 8.3 names look
/// alike.
fn lucene_syntax(node: Node, ancestors: &[Node], source: &str) -> Vec<Diagnostic> {
    let literal = text(node, source);
    let in_field = ancestors.last().is_some_and(|p| p.kind() == "field");
    let span = node_span(node);
    let diagnostic = |severity: Severity, message: &str| {
        let mut d = Diagnostic::warning(codes::KUERY_LUCENE_SYNTAX, message, range(source, span));
        d.severity = severity;
        d
    };
    let trimmed = literal.trim();
    let found = if in_field {
        if literal == "_exists_" {
            Some(diagnostic(
                Severity::Warning,
                "`_exists_:field` is Lucene; in KQL write `field:*`",
            ))
        } else if literal.starts_with(['+', '-', '!']) {
            Some(diagnostic(
                Severity::Warning,
                "`+`, `-`, and `!` prefixes are Lucene; KQL reads them as part of the field name. Use `not field:value`",
            ))
        } else {
            None
        }
    } else if (trimmed.starts_with('[') || trimmed.starts_with('{'))
        && (trimmed.contains(" TO ") || trimmed.contains(" to "))
    {
        Some(diagnostic(
            Severity::Warning,
            "`[a TO b]` is a Lucene range; KQL searches it as text. Use `field >= a and field <= b`",
        ))
    } else if matches!(trimmed, "&&" | "||") {
        Some(diagnostic(
            Severity::Warning,
            "`&&` and `||` are Lucene; KQL uses `and` and `or`",
        ))
    } else if looks_like_regex(trimmed) {
        Some(diagnostic(
            Severity::Hint,
            "`/regex/` is Lucene; KQL has no regular expressions and searches it as text",
        ))
    } else if fuzzy_or_boost(trimmed) {
        Some(diagnostic(
            Severity::Hint,
            "`~` (fuzzy, proximity) and `^` (boost) are Lucene; KQL searches them as text",
        ))
    } else {
        None
    };
    found.into_iter().collect()
}

/// `/…/` with a regex metacharacter. A plain path such as
/// `/var/lib/tool/` is not one.
fn looks_like_regex(word: &str) -> bool {
    word.len() > 2
        && word.starts_with('/')
        && word.ends_with('/')
        && word[1..word.len() - 1].contains(['^', '$', '+', '?', '|', '[', ']', '\\'])
}

fn is_kql_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{00A0}')
}

/// Kibana's `Or` and `And` need whitespace on both sides and `Not` after it:
/// `not(a:1)` and `a:1 and(b:2)` are syntax errors.
fn keyword_spacing(node: Node, source: &str) -> Option<Diagnostic> {
    let before = source[..node.start_byte()].chars().next_back();
    let after = source[node.end_byte()..].chars().next();
    let needs_before = node.kind() != "not";
    let missing =
        (needs_before && !before.is_some_and(is_kql_space)) || !after.is_some_and(is_kql_space);
    missing.then(|| {
        let word = text(node, source);
        let place = if needs_before { "around" } else { "after" };
        Diagnostic::error(
            codes::KUERY_PARSE_ERROR,
            format!("Kibana needs whitespace {place} `{word}`"),
            range(source, node_span(node)),
        )
    })
}

/// `field:{1 TO 5}` is a Lucene exclusive range; Kibana reads a nested query.
fn exclusive_range(node: Node, source: &str) -> Option<Diagnostic> {
    let query = node.child_by_field_name("query")?;
    let body = text(query, source);
    (query.kind() == "value_expression" && (body.contains(" TO ") || body.contains(" to "))).then(|| {
        Diagnostic::warning(
            codes::KUERY_LUCENE_SYNTAX,
            "`{a TO b}` is a Lucene range; Kibana reads `field:{ ... }` as a nested query. Use `field > a and field < b`",
            range(source, node_span(node)),
        )
    })
}

/// `\not` outside quotes: Kibana reads `\n` first, a newline plus `ot`.
fn unquoted_escapes(node: Node, source: &str) -> Vec<Diagnostic> {
    let t = text(node, source);
    let mut out = Vec::new();
    for (i, _) in t.match_indices("\\not") {
        let at = node.start_byte() + i;
        out.push(
            Diagnostic::warning(
                codes::KUERY_ESCAPE,
                "Kibana reads `\\not` as a newline followed by `ot`; write `\\NOT` or quote the value",
                range(source, ByteSpan::new(at, at + 4)),
            )
            .with_suggestion("\\NOT"),
        );
    }
    out
}

/// Inside quotes Kibana turns `\t`, `\r`, and `\n` into control characters
/// (`"C:\temp"` searches a TAB), and `*` is a literal asterisk.
fn quoted_string(node: Node, source: &str) -> Vec<Diagnostic> {
    let t = text(node, source);
    let bytes = t.as_bytes();
    let mut out = Vec::new();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            let next = bytes[i + 1];
            let followed_by_word = bytes.get(i + 2).is_some_and(|b| b.is_ascii_alphanumeric());
            if matches!(next, b't' | b'r' | b'n') && followed_by_word {
                let at = node.start_byte() + i;
                out.push(
                    Diagnostic::warning(
                        codes::KUERY_ESCAPE,
                        format!(
                            "Kibana turns `\\{}` inside quotes into a control character; write `\\\\{}` for a backslash",
                            next as char, next as char
                        ),
                        range(source, ByteSpan::new(at, at + 2)),
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
            range(source, node_span(node)),
        );
        d.severity = opentide_core::Severity::Hint;
        out.push(d);
    }
    out
}

/// `?` is not a wildcard in KQL: `jo?n` searches the text `jo?n`.
fn question_mark(node: Node, source: &str) -> Option<Diagnostic> {
    let t = text(node, source);
    let i = t.find('?')?;
    // A URL query string (`/path?x=1`, `/api/secrets?limit*`) is a real
    // question mark: a path before it and none after it.
    let (path, query) = t.split_at(i);
    if t.contains('=') || t.contains("://") || (path.contains('/') && !query.contains('/')) {
        return None;
    }
    let at = node.start_byte() + i;
    let mut d = Diagnostic::warning(
        codes::KUERY_QUESTION_MARK,
        "`?` is a literal character in KQL, not a single-character wildcard; use `*` to match any characters",
        range(source, ByteSpan::new(at, at + 1)),
    );
    d.severity = Severity::Hint;
    Some(d)
}

/// A value with no field. Kibana searches it in every field
/// (`index.query.default_field`), and after `f:a and` it is easy to read
/// `b` as part of `f`.
fn free_text(node: Node, ancestors: &[Node], source: &str) -> Option<Diagnostic> {
    let value = text(node, source);
    if value.trim() == "*" {
        return None;
    }
    // Inside a nested query the field context is the nested field.
    if ancestors.iter().any(|n| n.kind() == "nested_query") {
        return None;
    }
    let parent = ancestors.last().copied();
    let sibling_field = parent.and_then(|parent| {
        if !matches!(parent.kind(), "and_query" | "or_query") {
            return None;
        }
        let left = parent.child_by_field_name("left")?;
        (left.kind() == "field_value_expression" && left.end_byte() <= node.start_byte())
            .then_some(left)
    });
    let message = match sibling_field {
        Some(left) => {
            let field = left
                .child_by_field_name("field")
                .map(|f| text(f, source))
                .unwrap_or("");
            let op = parent
                .and_then(|p| p.child(1))
                .map(|o| text(o, source).to_ascii_lowercase())
                .unwrap_or_else(|| "and".into());
            let first = left
                .child_by_field_name("value")
                .map(|v| text(v, source))
                .unwrap_or("");
            format!(
                "`{value}` has no field, so Kibana searches it in every field, not in `{field}`; to search `{field}` write `{field}:({first} {op} {value})`"
            )
        }
        None => format!(
            "`{value}` has no field, so Kibana searches it in every field (`index.query.default_field`); name the field (`field:{value}`)"
        ),
    };
    let mut d = Diagnostic::warning(
        codes::KUERY_FREE_TEXT,
        message,
        range(source, node_span(node)),
    );
    d.severity = Severity::Hint;
    Some(d)
}

/// KQL text that reads like Lucene. One sign can be a coincidence; two
/// different kinds of Lucene syntax are a rule written for `language: lucene`.
fn looks_like_lucene(root: Node, source: &str, found: &[Diagnostic]) -> Option<Diagnostic> {
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
    if root.has_error()
        && ts_parse(LanguageId::Lucene, source).is_some_and(|t| !t.root_node().has_error())
    {
        signals.push("text only Lucene parses");
    }
    (signals.len() >= 2).then(|| {
        Diagnostic::warning(
            codes::KUERY_LOOKS_LIKE_LUCENE,
            format!(
                "this query reads like Lucene ({}); if it is an Elastic rule, set `language: lucene`",
                signals.join(", ")
            ),
            range(source, ByteSpan::new(0, source.len())),
        )
    })
}

fn fuzzy_or_boost(word: &str) -> bool {
    // `PROGRA~1` and paths are 8.3 short names, not fuzzy terms.
    if word.contains(['\\', '.', '/']) {
        return false;
    }
    if let Some((head, _)) = word.split_once('~') {
        if head.len() <= 6
            && head
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return false;
        }
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

/// Pre-order walk. Iterative: a query thousands of levels deep (a long
/// `OR` chain) must not overflow the stack, notably in WASM.
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
            if !cursor.goto_parent() {
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

fn highlight(spec: &HighlightSpec, parsed: &str, source: &str) -> Vec<HighlightToken> {
    let Ok(spans) = opentide_syntax::query_captures(
        LanguageId::Kuery,
        parsed,
        opentide_highlight::KUERY_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

/// Field names a query mentions, for completion and for Tide checks.
pub fn fields(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Kuery, &mask_trailing_keywords(source)) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field" && !node.has_error() {
            names.insert(text(node, source).trim_matches('"').to_string());
        }
    });
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

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Kuery, source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let word = text(node, source).to_ascii_lowercase();
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (KQL)\n\n{d}\n\n[Elastic docs]({KQL_DOCS})"))
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let before = &source[..offset.min(source.len())];
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // Implicit AND is a KQL error that Lucene accepts.
        assert!(find("a:1 b:2 AND _exists_:c", codes::KUERY_LOOKS_LIKE_LUCENE).is_some());
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 and b:2", Position::new(0, 5)).expect("hover");
        assert!(h.contains("and"));
        let items = completions("host.name:x ", 12);
        assert!(items.iter().any(|i| i.label == "and"));
        assert!(items.iter().any(|i| i.label == "host.name"));
    }
}
