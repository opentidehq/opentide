//! I/O-free engine for the Lucene classic query syntax, as Elasticsearch's
//! `query_string` reads it (Elastic Security rules with `language: lucene`),
//! and as Carbon Black Cloud watchlist queries use it.
//!
//! Boolean operators are upper case only: a lower-case `and` between two
//! clauses is a search term, so the clause list silently widens. Clauses have
//! no precedence (`a OR b AND c` is `a +b +c`), escapes are dropped one
//! backslash at a time, and a tab or newline inside a range glues tokens.
//! `/regexp/` bodies are Lucene's own regular-expression grammar
//! ([`regexp`]). Those are the checks this engine adds after the grammar.

pub mod regexp;

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Position, Range, Severity, codes,
    position_to_offset, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};

use tree_sitter::Node;

const SYNTAX_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query#query-string-syntax";

/// Which product runs the query. One grammar serves both; the diagnostics
/// differ where the products do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// Elasticsearch `query_string` (Elastic Security `language: lucene`).
    #[default]
    Elastic,
    /// Carbon Black Cloud watchlist queries (Solr's classic parser, default
    /// operator AND). Deploy joins the lines of the query with spaces.
    CarbonBlack,
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_dialect(source, Dialect::Elastic)
}

pub fn analyze_dialect(source: &str, dialect: Dialect) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    // Carbon Black deploy collapses newlines to spaces; same byte offsets.
    let joined;
    let text = if dialect == Dialect::CarbonBlack && source.contains(['\n', '\r']) {
        joined = source.replace(['\n', '\r'], " ");
        joined.as_str()
    } else {
        source
    };
    let Some(tree) = ts_parse(LanguageId::Lucene, text) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::LUCENE_PARSE_ERROR,
                "failed to initialize the Lucene parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::LUCENE_PARSE_ERROR,
            parse_error_message(err, text),
            range(text, node_span(err)),
        ));
    }
    let elastic = dialect == Dialect::Elastic;
    opentide_syntax::walk_with_ancestors(root, |node, ancestors| match node.kind() {
        "boolean_query" => {
            lowercase_operators(node, text, &mut diagnostics);
            mixed_operators(node, text, &mut diagnostics);
            kuery_ranges(node, text, &mut diagnostics);
            bare_terms(node, text, dialect, &mut diagnostics);
            glued_regexps(node, text, &mut diagnostics);
        }
        "field_name" => {
            field_wildcard(node, text, &mut diagnostics);
            if !elastic {
                elasticsearch_field_syntax(node, text, &mut diagnostics);
            }
        }
        "field_query" => range_operator(node, text, dialect, &mut diagnostics),
        "range_query" => range_whitespace(node, text, &mut diagnostics),
        "term" | "wildcard_term" | "phrase" | "range_term" => escapes(node, text, &mut diagnostics),
        "fuzzy" => fuzziness(node, ancestors, text, dialect, &mut diagnostics),
        "regexp" => regexp_body(node, ancestors, text, dialect, &mut diagnostics),
        _ => {}
    });
    if elastic && let Some(d) = looks_like_kuery(root, text, &diagnostics) {
        diagnostics.push(d);
    }
    // The checks ran on the joined text, where every newline is a space:
    // move their ranges back onto the source's lines (same byte offsets).
    if !std::ptr::eq(text, source) {
        for d in &mut diagnostics {
            let start = position_to_offset(text, d.range.start);
            let end = position_to_offset(text, d.range.end);
            d.range = range(source, ByteSpan::new(start, end));
        }
    }
    let tokens = highlight(&spec, source);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("Lucene syntax error: missing `{}`", err.kind());
    }
    let t = text(err, source);
    // An unescaped `/` opens a regexp; without a closing `/` the lexer fails.
    if let Some(rest) = t.strip_prefix('/') {
        let glued = source[..err.start_byte()]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_whitespace() && !matches!(c, '(' | ':'));
        let word = rest.split_whitespace().next().unwrap_or("");
        return if glued {
            format!(
                "`/` inside a value starts a Lucene regular expression that is never closed (`/{word}`); escape it as `\\/` or quote the value"
            )
        } else {
            format!(
                "`/` starts a Lucene regular expression that is never closed (`/{word}`); escape it as `\\/` or quote the value"
            )
        };
    }
    match t.split_whitespace().next() {
        Some(first) => format!("Lucene syntax error near `{first}`"),
        None => "Lucene syntax error".into(),
    }
}

/// A bare `and`, `or`, or `not` term between two clauses.
fn lowercase_operators(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let items: Vec<Node> = node.named_children(&mut cursor).collect();
    for (i, item) in items.iter().enumerate() {
        if i == 0 || i + 1 == items.len() || item.kind() != "term_query" {
            continue;
        }
        let word = text(*item, source);
        let upper = word.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") && word != upper {
            out.push(
                Diagnostic::warning(
                    codes::LUCENE_LOWERCASE_OPERATOR,
                    format!(
                        "`{word}` is a search term in Lucene, not an operator; operators are upper case (`{upper}`)"
                    ),
                    range(source, node_span(*item)),
                )
                .with_suggestion(upper),
            );
        }
    }
}

/// `a OR b AND c` is `a +b +c`: Lucene marks clauses pairwise and has no
/// precedence, so mixing the two at one level is never what it looks like.
fn mixed_operators(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let ops: Vec<Node> = node
        .children_by_field_name("operator", &mut cursor)
        .collect();
    let has_and = ops.iter().any(|o| o.kind() == "and");
    let has_or = ops.iter().any(|o| o.kind() == "or");
    if has_and && has_or {
        let first_or = ops
            .iter()
            .find(|o| o.kind() == "or")
            .copied()
            .unwrap_or(node);
        out.push(Diagnostic::warning(
            codes::LUCENE_MIXED_OPERATORS,
            "Lucene has no AND/OR precedence (`a OR b AND c` means `a +b +c`); add parentheses",
            range(source, node_span(first_or)),
        ));
    }
}

/// `field >= 10` is KQL. In Lucene it is three terms; write `field:>=10`.
fn kuery_ranges(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let items: Vec<Node> = node.named_children(&mut cursor).collect();
    for pair in items.windows(2) {
        let op = text(pair[1], source);
        if pair[0].kind() == "term_query"
            && pair[1].kind() == "term_query"
            && matches!(op, "<" | "<=" | ">" | ">=")
        {
            out.push(Diagnostic::warning(
                codes::LUCENE_KUERY_SYNTAX,
                format!(
                    "`{} {op}` is KQL; Lucene searches `{op}` as a term. Write `{}:{op}value`",
                    text(pair[0], source),
                    text(pair[0], source)
                ),
                range(source, node_span(pair[1])),
            ));
        }
    }
}

fn field_wildcard(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    if node
        .named_child(0)
        .is_some_and(|c| c.kind() == "wildcard_term")
    {
        let name = text(node, source);
        out.push(
            Diagnostic::error(
                codes::LUCENE_PARSE_ERROR,
                "Lucene rejects `*` or `?` in a field name; escape it (`book.\\*:`)",
                range(source, node_span(node)),
            )
            .with_suggestion(name.replace('*', "\\*").replace('?', "\\?")),
        );
    }
}

/// Lucene's range lexer splits bounds on a space only: `[1 TO<newline>5]`
/// reads `TO<newline>5` as one bound and fails.
fn range_whitespace(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut in_phrase = false;
    for (i, c) in text(node, source).char_indices() {
        match c {
            '"' => in_phrase = !in_phrase,
            '\t' | '\n' | '\r' if !in_phrase => {
                let at = node.start_byte() + i;
                out.push(Diagnostic::error(
                    codes::LUCENE_PARSE_ERROR,
                    "Lucene allows only spaces inside a range; a tab or newline joins `TO` to a bound",
                    range(source, ByteSpan::new(at, at + 1)),
                ));
                return;
            }
            _ => {}
        }
    }
}

/// `\uXXXX` needs four hex digits; any other single backslash is dropped, so
/// `"C:\Windows"` searches `C:Windows`.
fn escapes(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source);
    let bytes = t.as_bytes();
    let phrase = node.kind() == "phrase";
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let at = node.start_byte() + i;
        if next == b'u' {
            let hex = t.get(i + 2..i + 6).unwrap_or("");
            if hex.len() < 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                out.push(Diagnostic::error(
                    codes::LUCENE_ESCAPE,
                    "`\\u` must be followed by four hex digits; Lucene rejects the query. Write `\\\\u` for a literal backslash",
                    range(source, ByteSpan::new(at, at + 2)),
                ));
                return;
            }
        } else if phrase && next.is_ascii_alphanumeric() {
            out.push(
                Diagnostic::warning(
                    codes::LUCENE_ESCAPE,
                    format!(
                        "Lucene drops a single backslash: `\\{}` searches `{}`. Write `\\\\` for a literal backslash",
                        next as char, next as char
                    ),
                    range(source, ByteSpan::new(at, at + 2)),
                )
                .with_suggestion(format!("\\\\{}", next as char)),
            );
            return;
        }
        i += 2;
    }
    // A range bound is taken up to the next space, so `[a\ TO b]` leaves a
    // bound that ends in a backslash, which Lucene rejects.
    if i + 1 == bytes.len() && bytes[i] == b'\\' {
        let at = node.start_byte() + i;
        out.push(Diagnostic::error(
            codes::LUCENE_ESCAPE,
            "a value cannot end with a lone backslash; Lucene rejects the query. Write `\\\\` for a literal backslash",
            range(source, ByteSpan::new(at, at + 1)),
        ));
    }
}

/// `f:v w`: `w` has no field. Elasticsearch searches it in every field
/// (`index.query.default_field`); Carbon Black searches its default fields
/// and, with its default operator, requires it.
fn bare_terms(node: Node, source: &str, dialect: Dialect, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for pair in children.windows(2) {
        let (prev, item) = (pair[0], pair[1]);
        if prev.kind() != "field_query" || !matches!(item.kind(), "term_query" | "phrase_query") {
            continue;
        }
        let word = text(item, source);
        let upper = word.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT")
            || matches!(word, "<" | "<=" | ">" | ">=")
            || source[prev.end_byte()..item.start_byte()].is_empty()
        {
            continue;
        }
        let field = prev
            .child_by_field_name("field")
            .map(|f| text(f, source))
            .unwrap_or("");
        let value = prev
            .child_by_field_name("query")
            .map(|q| text(q, source))
            .unwrap_or("");
        let (severity, place) = match dialect {
            Dialect::Elastic => (Severity::Hint, "Elasticsearch searches it in every field"),
            Dialect::CarbonBlack => (
                Severity::Warning,
                "Carbon Black searches its default fields and requires it",
            ),
        };
        let mut d = Diagnostic::warning(
            codes::LUCENE_BARE_TERM,
            format!(
                "`{word}` has no field, so {place}; to search `{field}` for both, write `{field}:({value} {word})`"
            ),
            range(source, node_span(item)),
        );
        d.severity = severity;
        out.push(d);
    }
}

/// `/x/` glued to a term (`a/b/c`, `path:/var/log`): an unescaped `/`
/// starts a regexp, so the value splits into clauses.
fn glued_regexps(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    for (i, item) in children.iter().enumerate() {
        let regexp = match item.kind() {
            "regexp_query" => *item,
            "field_query" => match item.child_by_field_name("query") {
                Some(q) if q.kind() == "regexp_query" => q,
                _ => continue,
            },
            _ => continue,
        };
        let before = i > 0 && children[i - 1].end_byte() == item.start_byte();
        let after = children
            .get(i + 1)
            .is_some_and(|n| n.start_byte() == regexp.end_byte());
        if before || after {
            out.push(Diagnostic::warning(
                codes::LUCENE_UNESCAPED_SLASH,
                format!(
                    "`{}` is read as a regular expression because `/` is unescaped, so the value splits into separate clauses; escape the slashes (`\\/`) or quote the value",
                    text(regexp, source)
                ),
                range(source, node_span(regexp)),
            ));
        }
    }
}

/// `f:> 10`: Elasticsearch's one-sided range needs the value right after
/// the operator. With a space, `f` is searched for the text `>` (and `>=`
/// becomes a range from `=`), and `10` is searched in every field.
fn range_operator(node: Node, source: &str, dialect: Dialect, out: &mut Vec<Diagnostic>) {
    let Some(query) = node.child_by_field_name("query") else {
        return;
    };
    let op = text(query, source);
    if query.kind() != "term_query" {
        return;
    }
    if dialect == Dialect::CarbonBlack {
        if op.len() > 1 && op.starts_with(['<', '>']) {
            out.push(Diagnostic::warning(
                codes::LUCENE_ELASTICSEARCH_ONLY,
                format!(
                    "`{}` is Elasticsearch's one-sided range; Carbon Black searches `{op}` as text. Use `[a TO *]`",
                    text(node, source)
                ),
                range(source, node_span(query)),
            ));
        }
        return;
    }
    if !matches!(op, "<" | "<=" | ">" | ">=") {
        return;
    }
    let field = node
        .child_by_field_name("field")
        .map(|f| text(f, source))
        .unwrap_or("");
    let next = node
        .next_sibling()
        .filter(|n| n.kind() == "term_query" && source[node.end_byte()..n.start_byte()] == *" ");
    let mut d = Diagnostic::warning(
        codes::LUCENE_RANGE_OPERATOR,
        format!(
            "`{field}:{op}` needs its value without a space (`{field}:{op}10`); as written, Elasticsearch searches `{field}` for the text `{op}`{}",
            if next.is_some() {
                " and the next word in every field"
            } else {
                ""
            }
        ),
        range(source, node_span(query)),
    );
    if let Some(next) = next {
        d.range = range(source, ByteSpan::new(query.start_byte(), next.end_byte()));
        d = d.with_suggestion(format!("{op}{}", text(next, source)));
    }
    out.push(d);
}

/// `_exists_` and escaped wildcards in field names are Elasticsearch
/// extensions; Carbon Black reads them literally.
fn elasticsearch_field_syntax(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let name = text(node, source);
    let message = if name == "_exists_" {
        "`_exists_:field` is Elasticsearch syntax; Carbon Black searches a field named `_exists_`. Use `field:*`"
    } else if name.contains("\\*") || name.contains("\\?") {
        "`\\*` in a field name is an Elasticsearch field pattern; Carbon Black reads a literal field name"
    } else {
        return;
    };
    out.push(Diagnostic::warning(
        codes::LUCENE_ELASTICSEARCH_ONLY,
        message,
        range(source, node_span(node)),
    ));
}

/// `term~N`. Elasticsearch reads `N` as a fuzziness: `0`, `1`, `2`, or
/// `AUTO`; anything else fails the query. Lucene itself clamps `~3` to 2
/// and reads `~0.5` as a similarity, which is what Carbon Black's Solr does.
fn fuzziness(
    node: Node,
    ancestors: &[Node],
    source: &str,
    dialect: Dialect,
    out: &mut Vec<Diagnostic>,
) {
    // Phrase slop (`"a b"~3`) is a proximity, not an edit distance.
    if ancestors.last().is_none_or(|p| p.kind() != "term_query") {
        return;
    }
    let slop = &text(node, source)[1..];
    if slop.is_empty() {
        return;
    }
    let span = node_span(node);
    match dialect {
        Dialect::Elastic => {
            if let Some(message) = elastic_fuzziness_error(slop) {
                out.push(Diagnostic::error(
                    codes::LUCENE_FUZZY,
                    message,
                    range(source, span),
                ));
            }
        }
        Dialect::CarbonBlack => {
            let Ok(value) = slop.parse::<f32>() else {
                return;
            };
            let message = if value < 0.0 {
                "a fuzzy edit distance cannot be negative; Lucene rejects the query".to_string()
            } else if value >= 1.0 && value.fract() != 0.0 {
                "Lucene rejects a fractional edit distance; use `~1` or `~2`".to_string()
            } else if value > 2.0 {
                format!("Lucene allows at most 2 edits; `~{slop}` is searched as `~2`")
            } else {
                return;
            };
            out.push(Diagnostic::warning(
                codes::LUCENE_FUZZY,
                message,
                range(source, span),
            ));
        }
    }
}

/// Elasticsearch's `Fuzziness.fromString`, as `query_string` applies it.
fn elastic_fuzziness_error(slop: &str) -> Option<String> {
    let upper = slop.to_ascii_uppercase();
    if upper == "AUTO" {
        return None;
    }
    let value = match java_float(&upper) {
        JavaFloat::Value(v) => v,
        // Hexadecimal floats: not evaluated here.
        JavaFloat::Unknown => return None,
        JavaFloat::Invalid => {
            return Some(format!(
                "Elasticsearch rejects the fuzziness `{slop}`; use `~`, `~0`, `~1`, `~2`, or `~AUTO`"
            ));
        }
    };
    if value % 1.0 > 0.0 {
        return Some(format!(
            "Elasticsearch rejects a fractional fuzziness (`~{slop}`); use `~0`, `~1`, `~2`, or `~AUTO`"
        ));
    }
    let edits = value as i32;
    (!(0..=2).contains(&edits)).then(|| {
        format!(
            "Elasticsearch allows an edit distance of 0, 1, or 2, and rejects `~{slop}`; use `~2` or `~AUTO`"
        )
    })
}

enum JavaFloat {
    Value(f32),
    Invalid,
    Unknown,
}

/// The decimal forms Java's `Float.parseFloat` accepts of an upper-cased
/// string, as `Fuzziness.fromString` passes it: an optional sign, digits with
/// an optional fraction and exponent, and an optional `F`/`D` suffix. Java's
/// `NaN` and `Infinity` are case-sensitive, so their upper-cased forms fail
/// (Elasticsearch 9.5.5: "fuzziness cannot be [NaN]").
fn java_float(s: &str) -> JavaFloat {
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    if unsigned.starts_with("0X") {
        return JavaFloat::Unknown;
    }
    let negative = s.starts_with('-');
    let signed = |v: f32| JavaFloat::Value(if negative { -v } else { v });
    let body = unsigned.strip_suffix(['F', 'D']).unwrap_or(unsigned);
    let (mantissa, exponent) = match body.split_once('E') {
        Some((m, e)) => (m, Some(e)),
        None => (body, None),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |d: &str| d.chars().all(|c| c.is_ascii_digit());
    let mantissa_ok = digits(int) && digits(frac) && !(int.is_empty() && frac.is_empty());
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    if !mantissa_ok || !exponent_ok {
        return JavaFloat::Invalid;
    }
    let normalized = body.replace('E', "e");
    match normalized.parse::<f32>() {
        Ok(v) => signed(v),
        Err(_) => JavaFloat::Invalid,
    }
}

/// Whether a node with these ancestors sits under a `field:` clause.
fn has_field(ancestors: &[Node]) -> bool {
    ancestors.iter().any(|n| n.kind() == "field_query")
}

/// The body of `/.../`, checked as Lucene's `RegExp` the way Elasticsearch
/// compiles it.
fn regexp_body(
    node: Node,
    ancestors: &[Node],
    source: &str,
    dialect: Dialect,
    out: &mut Vec<Diagnostic>,
) {
    let t = text(node, source);
    if t.len() < 2 {
        return;
    }
    let body = &t[1..t.len() - 1];
    let start = node.start_byte() + 1;
    let at_char = |at: usize| {
        let b = body.char_indices().nth(at).map_or(body.len(), |(b, _)| b);
        let width = body[b..].chars().next().map_or(1, char::len_utf8);
        if b >= body.len() {
            node_span(node)
        } else {
            ByteSpan::new(start + b, start + b + width)
        }
    };
    for problem in regexp::elasticsearch_problems(body) {
        // Carbon Black's Solr version is not known: syntax advice only.
        if dialect == Dialect::CarbonBlack && !problem.syntax {
            continue;
        }
        let span = problem.at.map_or_else(|| node_span(node), at_char);
        // Without a field, `query_string` searches every field (`*`), which
        // Elasticsearch runs leniently: the term matches nothing instead of
        // failing the query.
        let fielded = has_field(ancestors);
        let message = if fielded {
            problem.message
        } else {
            format!(
                "{}; with no field, Elasticsearch searches every field leniently, so this term silently matches nothing",
                problem.message
            )
        };
        let mut d = Diagnostic::error(codes::LUCENE_REGEXP, message, range(source, span));
        d.severity = match dialect {
            Dialect::Elastic if fielded => problem.severity,
            Dialect::Elastic | Dialect::CarbonBlack => Severity::Warning,
        };
        out.push(d);
        if problem.syntax {
            return;
        }
    }
    regexp_pcre_habits(body, start, source, dialect, out);
}

/// Valid Lucene, but not what a PCRE author meant: `(?:`, `(?i)`, and the
/// anchors `^` and `$` are literal text, because Lucene regexps always match
/// the whole term. Carbon Black matches lower-cased tokens, so upper-case
/// letters cannot match on tokenized fields.
fn regexp_pcre_habits(
    body: &str,
    start: usize,
    source: &str,
    dialect: Dialect,
    out: &mut Vec<Diagnostic>,
) {
    let chars: Vec<(usize, char)> = body.char_indices().collect();
    let (mut group, mut anchor, mut upper) = (None, None, None);
    let mut i = 0;
    while i < chars.len() {
        let (b, c) = chars[i];
        match c {
            '\\' => {
                // `\D`, `\S`, `\W` are classes, not letters.
                i += 2;
                continue;
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i].1 != '"' {
                    upper = upper.or(chars[i].1.is_uppercase().then_some(chars[i].0));
                    i += 1;
                }
            }
            '[' => {
                // The first character after `[` or `[^` is a member even
                // when it is `]`.
                i += 1;
                if chars.get(i).is_some_and(|c| c.1 == '^') {
                    i += 1;
                }
                i += 1;
                while i < chars.len() && chars[i].1 != ']' {
                    if chars[i].1 == '\\' {
                        i += 1;
                    } else if chars[i].1.is_uppercase() {
                        upper = upper.or(Some(chars[i].0));
                    }
                    i += 1;
                }
            }
            '(' if chars.get(i + 1).is_some_and(|c| c.1 == '?') => group = group.or(Some(b)),
            '^' | '$' => anchor = anchor.or(Some((b, c))),
            c if c.is_uppercase() => upper = upper.or(Some(b)),
            _ => {}
        }
        i += 1;
    }
    let span = |b: usize, len: usize| range(source, ByteSpan::new(start + b, start + b + len));
    if let Some(b) = group {
        out.push(Diagnostic::warning(
            codes::LUCENE_REGEXP,
            "Lucene regular expressions have no `(?…)` groups or flags: `(?:` matches the text `?:` and `(?i)` the text `?i`; drop the `?…` part",
            span(b, 2),
        ));
    }
    if let Some((b, c)) = anchor {
        out.push(Diagnostic::warning(
            codes::LUCENE_REGEXP,
            format!(
                "Lucene regular expressions always match the whole term, so `{c}` is a literal character, not an anchor; drop it (or escape it as `\\{c}` to match the character)"
            ),
            span(b, 1),
        ));
    }
    if dialect == Dialect::CarbonBlack
        && let Some(b) = upper
    {
        let mut d = Diagnostic::warning(
            codes::LUCENE_REGEXP,
            "Carbon Black matches regular expressions against lower-cased tokens on tokenized fields, so an upper-case letter never matches there",
            span(b, 1),
        );
        d.severity = Severity::Hint;
        out.push(d);
    }
}

/// Lucene text that reads like Kibana KQL. One sign can be a coincidence; two
/// different kinds of KQL syntax are a rule written for `language: kuery`.
fn looks_like_kuery(root: Node, source: &str, found: &[Diagnostic]) -> Option<Diagnostic> {
    let mut signals: Vec<&str> = Vec::new();
    let has = |code: &str| found.iter().any(|d| d.code == code);
    if has(codes::LUCENE_LOWERCASE_OPERATOR) {
        signals.push("lower-case `and`/`or`/`not` operators");
    }
    if has(codes::LUCENE_KUERY_SYNTAX) {
        signals.push("`field >= value` ranges");
    }
    // A leading lower-case `not` is a term to Lucene, an operator to KQL.
    let first = root.named_child(0).map(|n| {
        if n.kind() == "boolean_query" {
            n.named_child(0).unwrap_or(n)
        } else {
            n
        }
    });
    if first
        .is_some_and(|n| n.kind() == "term_query" && text(n, source).eq_ignore_ascii_case("not"))
        && root
            .named_child(0)
            .is_some_and(|n| n.kind() == "boolean_query")
    {
        signals.push("a leading `not`");
    }
    // Lucene rejects the text, and Kibana's KQL grammar accepts it.
    if root.has_error()
        && ts_parse(LanguageId::Kuery, source).is_some_and(|t| !t.root_node().has_error())
    {
        signals.push("text only KQL parses");
    }
    signals.dedup();
    (signals.len() >= 2).then(|| {
        Diagnostic::warning(
            codes::LUCENE_LOOKS_LIKE_KUERY,
            format!(
                "this query reads like Kibana KQL ({}); if it is an Elastic rule, set `language: kuery`",
                signals.join(", ")
            ),
            range(source, ByteSpan::new(0, source.len())),
        )
    })
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

fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    let Ok(spans) = opentide_syntax::query_captures(
        LanguageId::Lucene,
        source,
        opentide_highlight::LUCENE_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

/// Field names a query mentions, for completion.
pub fn fields(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Lucene, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field_name" && !node.has_error() {
            names.insert(text(node, source).to_string());
        }
    });
    names.into_iter().collect()
}

const OPERATORS: &[(&str, &str)] = &[
    (
        "AND",
        "Both clauses must match. Also `&&`. Upper case only.",
    ),
    ("&&", "Same as `AND`."),
    ("OR", "Either clause matches. Also `||`. Upper case only."),
    ("||", "Same as `OR`."),
    (
        "NOT",
        "Excludes the clause that follows. Also `!`. Upper case only.",
    ),
    ("!", "Same as `NOT`."),
    ("+", "The clause must match."),
    ("-", "The clause must not match."),
    (
        "TO",
        "Range bounds: `[a TO b]` inclusive, `{a TO b}` exclusive, `*` for an open end.",
    ),
    (
        ":",
        "`field:value`. `_exists_:field` matches documents that have the field.",
    ),
];

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Lucene, source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let word = text(node, source);
    if node.kind() == "boost" {
        return Some(format!(
            "**`^`** boost\n\nRaises the clause's relevance weight.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    if node.kind() == "fuzzy" {
        return Some(format!(
            "**`~`** fuzzy or proximity\n\nAfter a term, edit distance; after a phrase, word slop.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (Lucene)\n\n{d}\n\n[Elastic docs]({SYNTAX_DOCS})"))
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let before = &source[..offset.min(source.len())];
    let mut items = Vec::new();
    if before.ends_with(char::is_whitespace) && !before.trim().is_empty() {
        for kw in ["AND", "OR", "NOT"] {
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

    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn classic_syntax_is_clean() {
        let src = "event.category:process AND process.name:(cmd.exe OR \"power shell.exe\"^2) -user.name:SYSTEM AND bytes:[100 TO *} AND name:jo?n*";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
    }

    #[test]
    fn lowercase_operators_are_terms() {
        let r = analyze("process.name:cmd.exe and user.name:root");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::LUCENE_LOWERCASE_OPERATOR)
            .expect("lowercase and");
        assert_eq!(d.suggestion.as_deref(), Some("AND"));
        assert!(
            codes_of("title:and").is_empty(),
            "a value is not an operator"
        );
    }

    #[test]
    fn parse_errors_are_reported() {
        assert!(codes_of("name:(a OR b").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("bytes:[1 TO]").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
    }

    #[test]
    fn behaviour_checks_from_the_lucene_parser() {
        assert!(codes_of("a OR b AND c").contains(&codes::LUCENE_MIXED_OPERATORS.to_string()));
        assert!(codes_of("(a OR b) AND c").is_empty());
        assert!(codes_of("book.*:x").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("book.\\*:x").is_empty());
        assert!(codes_of("x:[1 TO\n5]").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("path:\"c:\\users\\bob\"").contains(&codes::LUCENE_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\Windows\"").contains(&codes::LUCENE_ESCAPE.to_string()));
        assert!(codes_of("path:\"C:\\\\Windows\"").is_empty());
        assert!(codes_of("bytes >= 10").contains(&codes::LUCENE_KUERY_SYNTAX.to_string()));
        assert!(codes_of("foo:AND").contains(&codes::LUCENE_PARSE_ERROR.to_string()));
        assert!(codes_of("*").is_empty());
        assert!(codes_of("-foo*").is_empty());
    }

    fn find(src: &str, code: &str) -> Option<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .find(|d| d.code == code)
    }

    #[test]
    fn regexp_bodies_follow_lucene() {
        // Rejected by RegExp: PCRE escapes, an unclosed quote, `<` intervals.
        for src in [
            r"CommandLine:/\bnet\b/",
            r#"x:/set.*"/"#,
            r"x:/\s-\s*</",
            r"x:/(a|)/",
        ] {
            let d = find(src, codes::LUCENE_REGEXP).expect(src);
            assert_eq!(d.severity, Severity::Error, "{src}");
        }
        let d = find(
            r"x:/(Copy-Item|cpi) .{2,128} -Destination .{1,32}\\Windows\\(System32|SysWOW64)/",
            codes::LUCENE_REGEXP,
        )
        .expect("too complex");
        assert_eq!(d.severity, Severity::Error);
        // Valid, but PCRE habits that change the meaning.
        for src in ["x:/(?i)cmd.*/", "x:/^cmd.*/", "x:/cmd.*$/"] {
            let d = find(src, codes::LUCENE_REGEXP).expect(src);
            assert_eq!(d.severity, Severity::Warning, "{src}");
        }
        // Lucene 9 and 10 disagree on `[\x-y]`: a warning naming the stack.
        for src in [r"x:/[\.-z-]x/", r"x:/[\~-!]x/"] {
            let d = find(src, codes::LUCENE_REGEXP).expect(src);
            assert_eq!(d.severity, Severity::Warning, "{src}");
        }
        for src in [
            r"x:/cmd\.exe/",
            r"x:/[^a-z]+\d{2,4}/",
            r"x:/a\$b/",
            "x:/[$^]/",
        ] {
            assert!(codes_of(src).is_empty(), "{src}");
        }
    }

    #[test]
    fn fuzziness_follows_elasticsearch() {
        // Elasticsearch 9.5.5 rejects every NaN and Infinity spelling.
        for q in ["a:b~nan", "a:b~NaN", "a:b~Infinity", "a:b~-INFINITY"] {
            assert!(
                codes_of(q).contains(&codes::LUCENE_FUZZY.to_string()),
                "{q}"
            );
        }
        for ok in [
            "f:foo~",
            "f:foo~0",
            "f:foo~2",
            "f:foo~AUTO",
            "f:foo~2.0",
            "\"a b\"~5",
            "\"a b\"~abc",
        ] {
            assert!(codes_of(ok).is_empty(), "{ok}");
        }
        for bad in ["f:foo~3", "f:foo~0.5", "f:foo~1.5", "f:foo~abc", "f:foo~-1"] {
            let d = find(bad, codes::LUCENE_FUZZY).expect(bad);
            assert_eq!(d.severity, Severity::Error, "{bad}");
        }
        // Lucene itself clamps `~3`; Carbon Black gets a warning.
        let r = analyze_dialect("f:foo~3", Dialect::CarbonBlack);
        assert!(
            r.diagnostics
                .iter()
                .all(|d| d.severity == Severity::Warning)
        );
        assert!(r.diagnostics.iter().any(|d| d.code == codes::LUCENE_FUZZY));
    }

    #[test]
    fn range_operator_needs_its_value() {
        let d = find("bytes:> 10", codes::LUCENE_RANGE_OPERATOR).expect("space");
        assert_eq!(d.suggestion.as_deref(), Some(">10"));
        assert!(codes_of("bytes:>10 AND bytes:<=20").is_empty());
    }

    #[test]
    fn unescaped_slashes() {
        let r = analyze("ip:10.0.0.0/8 AND x:1");
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::LUCENE_PARSE_ERROR)
            .expect("lexical error");
        assert!(d.message.contains("regular expression"), "{}", d.message);
        assert!(find("path:/var/log AND x:1", codes::LUCENE_UNESCAPED_SLASH).is_some());
        assert!(find("a/b/c", codes::LUCENE_UNESCAPED_SLASH).is_some());
        assert!(find("path:\\/var\\/log", codes::LUCENE_UNESCAPED_SLASH).is_none());
        assert!(find("path:/var/ AND x:1", codes::LUCENE_UNESCAPED_SLASH).is_none());
    }

    #[test]
    fn bare_term_after_a_field() {
        let d = find("user.name:alice bob", codes::LUCENE_BARE_TERM).expect("bare");
        assert_eq!(d.severity, Severity::Hint);
        assert!(find("user.name:alice AND bob", codes::LUCENE_BARE_TERM).is_none());
        assert!(find("user.name:alice host.name:x", codes::LUCENE_BARE_TERM).is_none());
        let r = analyze_dialect("process_name:cmd.exe powershell", Dialect::CarbonBlack);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::LUCENE_BARE_TERM)
            .expect("cb bare");
        assert_eq!(d.severity, Severity::Warning);
    }

    #[test]
    fn kql_text_in_a_lucene_rule() {
        let d = find(
            "process.name:cmd.exe and event.code >= 4624",
            codes::LUCENE_LOOKS_LIKE_KUERY,
        )
        .expect("two signals");
        assert_eq!(d.severity, Severity::Warning);
        // One signal alone is not enough.
        assert!(
            find(
                "process.name:cmd.exe and user.name:x",
                codes::LUCENE_LOOKS_LIKE_KUERY
            )
            .is_none()
        );
        assert!(
            find(
                "not user.name:x and host.name:y",
                codes::LUCENE_LOOKS_LIKE_KUERY
            )
            .is_some()
        );
    }

    #[test]
    fn carbon_black_dialect() {
        let cb = |src: &str| -> Vec<(String, Severity)> {
            analyze_dialect(src, Dialect::CarbonBlack)
                .diagnostics
                .into_iter()
                .map(|d| (d.code, d.severity))
                .collect()
        };
        // Deploy joins lines with spaces, so a newline in a range is fine.
        assert!(cb("x:[1 TO\n5]").is_empty());
        assert!(!codes_of("x:[1 TO\n5]").is_empty());
        for src in ["_exists_:process_name", "netconn_count:>5", "proc\\*:x"] {
            assert!(
                cb(src)
                    .iter()
                    .any(|(c, s)| c == codes::LUCENE_ELASTICSEARCH_ONLY && *s == Severity::Warning),
                "{src}"
            );
        }
        assert!(
            cb("process_name:/CMD.*/")
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Hint)
        );
        // Diagnostics stay on the source line they belong to.
        let found = analyze_dialect(
            "process_name:cmd.exe\n  AND\n  _exists_:x",
            Dialect::CarbonBlack,
        )
        .diagnostics;
        let d = found
            .iter()
            .find(|d| d.code == codes::LUCENE_ELASTICSEARCH_ONLY)
            .expect("_exists_ warning");
        assert_eq!((d.range.start.line, d.range.start.character), (2, 2));
        // No Elastic language advice for Carbon Black.
        assert!(
            cb("a:1 and b >= 2")
                .iter()
                .all(|(c, _)| c != codes::LUCENE_LOOKS_LIKE_KUERY)
        );
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 AND b:2", Position::new(0, 5)).expect("hover");
        assert!(h.contains("AND"));
        assert!(completions("a:1 ", 4).iter().any(|i| i.label == "AND"));
    }
}
