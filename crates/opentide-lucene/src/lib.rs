//! I/O-free engine for the Lucene classic query syntax, as Elasticsearch's
//! `query_string` reads it (Elastic Security rules with `language: lucene`),
//! as Carbon Black Cloud watchlist queries use it, and as Graylog event
//! definitions and searches use it ([`graylog`]).
//!
//! Boolean operators are upper case only: a lower-case `and` between two
//! clauses is a search term, so the clause list silently widens. Clauses have
//! no precedence (`a OR b AND c` is `a +b +c`), escapes are dropped one
//! backslash at a time, and a tab or newline inside a range glues tokens.
//! `/regexp/` bodies are Lucene's own regular-expression grammar
//! ([`regexp`]). Those are the checks this engine adds after the grammar.
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
pub mod carbon_black;
mod ecs;
pub mod graylog;
mod parser;
pub mod regexp;
mod syntax;
mod tree;

pub use ecs::ecs_diagnostics;

/// The tree of `source` and its errors as indented text, for the snapshot
/// tests of the parser (`tests/trees.rs`). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_parse(source: &str) -> String {
    parser::debug(source)
}

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LineIndex, Range, Severity, codes, position_to_offset,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans, tokens_in};
use syntax::SyntaxKind as K;
use tree::{Node, Tree, walk_once};

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
    /// Graylog searches and event definitions (graylog-1.0): OpenSearch or
    /// Elasticsearch `query_string`, unchanged, with leading wildcards off.
    /// Elastic's checks, without the ECS and Kibana KQL advice, plus
    /// Graylog's own ([`graylog`]).
    Graylog,
}

impl Dialect {
    /// The dialect of a detection platform, as a `configurations` key:
    /// `carbon_black_cloud` and `graylog` have their own, every other
    /// platform (and none) is Elastic's.
    pub fn for_platform(platform: &str) -> Self {
        match platform {
            "carbon_black_cloud" => Dialect::CarbonBlack,
            "graylog" => Dialect::Graylog,
            _ => Dialect::Elastic,
        }
    }
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Whether the Lucene query string grammar accepts `source`: no syntax error.
/// The Kibana KQL engine asks it of a query Kibana rejects (a sign the query
/// was written for `language: lucene`); pass it to `opentide_kuery::analyze`.
#[must_use]
pub fn parses(source: &str) -> bool {
    parser::accepts(source)
}

/// The parse [`analyze`] runs, tree included, and its error count: the
/// throughput benchmark's parse (`cargo bench --bench throughput`, ADR 0014).
/// Not API.
#[doc(hidden)]
#[must_use]
pub fn parse_tree(source: &str) -> usize {
    Tree::parse(source).errors.len()
}

pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_dialect(source, Dialect::Elastic)
}

/// The Lucene query string [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
///
/// The dialect is the platform's ([`Dialect::for_platform`]): Elastic's, the
/// default, unless it names Carbon Black Cloud or Graylog.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Lucene
    }

    fn analyze_for(
        &self,
        source: &str,
        setting: &opentide_highlight::Setting<'_>,
    ) -> opentide_highlight::AnalyzeResult {
        let r = analyze_dialect(source, Dialect::for_platform(setting.platform));
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }

    fn hover(
        &self,
        source: &str,
        offset: usize,
        setting: &opentide_highlight::Setting<'_>,
    ) -> Option<String> {
        hover_dialect(source, offset, Dialect::for_platform(setting.platform))
    }

    fn completions(
        &self,
        source: &str,
        offset: usize,
        setting: &opentide_highlight::Setting<'_>,
    ) -> Vec<opentide_core::CompletionItem> {
        completions_dialect(source, offset, Dialect::for_platform(setting.platform))
    }
}

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_dialect(source: &str, dialect: Dialect) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    // Carbon Black deploy collapses newlines to spaces; same byte offsets.
    let joined;
    let text = if dialect == Dialect::CarbonBlack && source.contains(['\n', '\r']) {
        joined = source.replace(['\n', '\r'], " ");
        joined.as_str()
    } else {
        source
    };
    let tree = Tree::parse(text);
    let root = tree.root();
    let lines = LineIndex::new(text);
    let range = |span: ByteSpan| lines.range(span);
    let mut diagnostics = Vec::new();
    if let Some(err) = tree.errors.first() {
        let (message, mut span) = parse_error(&tree, err, text);
        // At the end of the query: an empty span after its last token, not
        // one over the blanks that follow it.
        if span.start >= text.trim_end().len() {
            span.end = span.start;
        }
        diagnostics.push(Diagnostic::error(
            codes::LUCENE_PARSE_ERROR,
            message,
            range(span),
        ));
    }
    let elastic = dialect == Dialect::Elastic;
    let graylog = dialect == Dialect::Graylog;
    let cx = Cx {
        source: text,
        lines: &lines,
    };
    // One walk runs the checks and gathers the highlight's tokens, when the
    // highlight reads this text (ADR 0014 §5a).
    let same_text = std::ptr::eq(text, source);
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    let mut highlight_token = |t: &rowan::SyntaxToken<syntax::Lucene>| {
        if same_text && let Some(capture) = capture(t) {
            let r = t.text_range();
            spans.push((
                ByteSpan::new(usize::from(r.start()), usize::from(r.end())),
                capture,
            ));
        }
    };
    let checks = |node: &Node, ancestors: &[Node]| match node.kind() {
        K::BooleanQuery => {
            lowercase_operators(node, cx, &mut diagnostics);
            mixed_operators(node, cx, &mut diagnostics);
            kuery_ranges(node, cx, &mut diagnostics);
            bare_terms(node, cx, dialect, &mut diagnostics);
            glued_regexps(node, cx, &mut diagnostics);
        }
        K::FieldName => {
            field_wildcard(node, cx, &mut diagnostics);
            if dialect == Dialect::CarbonBlack {
                elasticsearch_field_syntax(node, cx, &mut diagnostics);
                carbon_black::check_field(node, cx, &mut diagnostics);
            }
        }
        K::FieldQuery => range_operator(node, cx, dialect, &mut diagnostics),
        K::RangeQuery => {
            range_whitespace(node, cx, &mut diagnostics);
            if graylog {
                graylog::open_range(node, cx, &mut diagnostics);
                graylog::analyzed_field(node, ancestors, cx, &mut diagnostics);
            }
        }
        K::TermQuery if graylog => {
            graylog::leading_wildcard(node, cx, &mut diagnostics);
            graylog::analyzed_field(node, ancestors, cx, &mut diagnostics);
        }
        K::RegexpQuery if graylog => {
            graylog::analyzed_field(node, ancestors, cx, &mut diagnostics);
        }
        K::Term | K::WildcardTerm | K::Phrase | K::RangeTerm => escapes(node, cx, &mut diagnostics),
        K::Fuzzy => fuzziness(node, ancestors, cx, dialect, &mut diagnostics),
        K::Regexp => regexp_body(node, ancestors, cx, dialect, &mut diagnostics),
        _ => {}
    };
    walk_once(&root, checks, &mut highlight_token);
    if graylog {
        graylog::double_backslash(cx, &mut diagnostics);
    }
    if elastic && let Some(d) = looks_like_kuery(&tree, cx, &diagnostics) {
        diagnostics.push(d);
    }
    // The checks ran on the joined text, where every newline is a space:
    // move their ranges back onto the source's lines (same byte offsets).
    if !std::ptr::eq(text, source) {
        let source_lines = LineIndex::new(source);
        for d in &mut diagnostics {
            let start = position_to_offset(text, d.range.start);
            let end = position_to_offset(text, d.range.end);
            d.range = source_lines.range(ByteSpan::new(start, end));
        }
    }
    let tokens = if same_text {
        // `text` is `source`: its line table is `lines`.
        tokens_in(spec, &lines, &spans).unwrap_or_default()
    } else {
        highlight(spec, &Tree::parse(source).root, source)
    };
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// The first syntax error, in words, and its span.
fn parse_error(tree: &Tree, err: &opentide_parse::SyntaxError, source: &str) -> (String, ByteSpan) {
    let at = usize::from(err.gap.start());
    let point = |at: usize| ByteSpan::new(at, at + 1);
    // An unclosed `"` or `/` where the error stands is what to fix, whatever
    // the parser missed because of it (`message:"failed login`).
    let next = source[at..]
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .map(|(i, _)| at + i);
    if let Some(unclosed) = next.and_then(|next| unclosed_at(tree, source, next)) {
        return unclosed;
    }
    let missing = |what: &str| (format!("Lucene syntax error: missing `{what}`"), point(at));
    match err.message.as_str() {
        parser::MISSING_PAREN => return missing(")"),
        parser::MISSING_TO => return missing("TO"),
        parser::MISSING_CLOSE => {
            // The bracket that would close the range: `]` for `[`, else `}`.
            let open = source[..at].rfind(['[', '{']).map(|i| &source[i..=i]);
            return missing(if open == Some("[") { "]" } else { "}" });
        }
        parser::MISSING_BOUND => {
            return (
                "Lucene syntax error: a range bound is missing (`[a TO b]`; `*` for an open end)"
                    .into(),
                point(at),
            );
        }
        parser::MISSING_CLAUSE => {
            let before = source[..at].trim_end();
            let last = before.rsplit(char::is_whitespace).next().unwrap_or("");
            // `foo:AND`: an operator where a value belongs.
            let word = source[at..].split_whitespace().next().unwrap_or("");
            if let Some(op) = ["AND", "OR", "NOT"]
                .into_iter()
                .find(|op| word.trim_end_matches(')') == *op)
            {
                let start = at + source[at..].find(op).unwrap_or(0);
                return (
                    format!(
                        "Lucene syntax error: `{op}` is an operator, so a clause is missing after `{last}`; quote it (`\"{op}\"`) to search the word"
                    ),
                    ByteSpan::new(start, start + op.len()),
                );
            }
            let message = if last.is_empty() {
                "Lucene syntax error: a clause is missing".to_string()
            } else {
                format!("Lucene syntax error: a clause is missing after `{last}`")
            };
            return (message, point(at));
        }
        _ => {}
    }
    // An unexpected token: the error node that starts where the gap ends.
    let end = usize::from(err.gap.end());
    let node = tree
        .root
        .descendants()
        .find(|n| n.kind() == K::Error && usize::from(n.text_range().start()) >= end);
    let span = node.map_or(point(end), |n| {
        let r = n.text_range();
        ByteSpan::new(
            usize::from(r.start()),
            usize::from(r.end()).max(usize::from(r.start()) + 1),
        )
    });
    // The nesting limit: the parser's own words, never the query it stopped on
    // (the error node holds the rest of it).
    if let opentide_parse::ErrorKind::TooDeep { .. } = err.kind {
        return (format!("Lucene syntax error: {}", err.message), span);
    }
    if let Some(unclosed) = unclosed_at(tree, source, span.start) {
        return unclosed;
    }
    let t = source.get(span.start..span.end).unwrap_or("");
    let message = match t.split_whitespace().next() {
        Some(first) => format!("Lucene syntax error near `{first}`"),
        None => "Lucene syntax error".into(),
    };
    (message, span)
}

/// The message for a `"` or `/` at byte `at` that the lexer could not close
/// (an error token there), and its span: from it to the end of the query.
fn unclosed_at(tree: &Tree, source: &str, at: usize) -> Option<(String, ByteSpan)> {
    let offset = rowan::TextSize::from(u32::try_from(at).ok()?);
    let token = tree.root.token_at_offset(offset).right_biased()?;
    if token.kind() != K::ErrorToken || token.text_range().start() != offset {
        return None;
    }
    let span = ByteSpan::new(at, source.len().max(at + 1));
    if token.text() == "\"" {
        return Some((
            "Lucene syntax error: a quoted phrase is never closed".into(),
            span,
        ));
    }
    // An unescaped `/` opens a regexp; without a closing `/` the lexer fails.
    if token.text() != "/" {
        return None;
    }
    let word = source[at + 1..].split_whitespace().next().unwrap_or("");
    let glued = source[..at]
        .chars()
        .next_back()
        .is_some_and(|c| !c.is_whitespace() && !matches!(c, '(' | ':'));
    let message = if glued {
        format!(
            "`/` inside a value starts a Lucene regular expression that is never closed (`/{word}`); escape it as `\\/` or quote the value"
        )
    } else {
        format!(
            "`/` starts a Lucene regular expression that is never closed (`/{word}`); escape it as `\\/` or quote the value"
        )
    };
    Some((message, span))
}

/// A bare `and`, `or`, or `not` term between two clauses.
fn lowercase_operators(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let items = node.children();
    for (i, item) in items.iter().enumerate() {
        if i == 0 || i + 1 == items.len() || item.kind() != K::TermQuery {
            continue;
        }
        let word = item.text(source);
        let upper = word.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT") && word != upper {
            out.push(
                Diagnostic::warning(
                    codes::LUCENE_LOWERCASE_OPERATOR,
                    format!(
                        "`{word}` is a search term in Lucene, not an operator; operators are upper case (`{upper}`)"
                    ),
                    cx.range(item.span()),
                )
                .with_suggestion(upper),
            );
        }
    }
}

/// `a OR b AND c` is `a +b +c`: Lucene marks clauses pairwise and has no
/// precedence, so mixing the two at one level is never what it looks like.
fn mixed_operators(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let ops = node.operators();
    let has_and = ops.iter().any(|o| o.kind() == K::And);
    let has_or = ops.iter().any(|o| o.kind() == K::Or);
    if has_and && has_or {
        let first_or = ops.iter().find(|o| o.kind() == K::Or).unwrap_or(node);
        out.push(Diagnostic::warning(
            codes::LUCENE_MIXED_OPERATORS,
            "Lucene has no AND/OR precedence (`a OR b AND c` means `a +b +c`); add parentheses",
            cx.range(first_or.span()),
        ));
    }
}

/// `field >= 10` is KQL. In Lucene it is three terms; write `field:>=10`.
fn kuery_ranges(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let items = node.children();
    for pair in items.windows(2) {
        // The kinds first: the text trims the node's range (ADR 0014 §4).
        if pair[0].kind() != K::TermQuery || pair[1].kind() != K::TermQuery {
            continue;
        }
        let op = pair[1].text(source);
        if matches!(op, "<" | "<=" | ">" | ">=") {
            out.push(Diagnostic::warning(
                codes::LUCENE_KUERY_SYNTAX,
                format!(
                    "`{} {op}` is KQL; Lucene searches `{op}` as a term. Write `{}:{op}value`",
                    pair[0].text(source),
                    pair[0].text(source)
                ),
                cx.range(pair[1].span()),
            ));
        }
    }
}

fn field_wildcard(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    if node
        .first_child()
        .is_some_and(|c| c.kind() == K::WildcardTerm)
    {
        let name = node.text(source);
        out.push(
            Diagnostic::error(
                codes::LUCENE_PARSE_ERROR,
                "Lucene rejects `*` or `?` in a field name; escape it (`book.\\*:`)",
                cx.range(node.span()),
            )
            .with_suggestion(name.replace('*', "\\*").replace('?', "\\?")),
        );
    }
}

/// Lucene's range lexer splits bounds on a space only: `[1 TO<newline>5]`
/// reads `TO<newline>5` as one bound and fails.
fn range_whitespace(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let mut in_phrase = false;
    for (i, c) in node.text(source).char_indices() {
        match c {
            '"' => in_phrase = !in_phrase,
            '\t' | '\n' | '\r' if !in_phrase => {
                let at = node.start() + i;
                out.push(Diagnostic::error(
                    codes::LUCENE_PARSE_ERROR,
                    "Lucene allows only spaces inside a range; a tab or newline joins `TO` to a bound",
                    cx.range(ByteSpan::new(at, at + 1)),
                ));
                return;
            }
            _ => {}
        }
    }
}

/// `\uXXXX` needs four hex digits; any other single backslash is dropped, so
/// `"C:\Windows"` searches `C:Windows`.
fn escapes(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let t = node.text(source);
    let bytes = t.as_bytes();
    let phrase = node.kind() == K::Phrase;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let at = node.start() + i;
        if next == b'u' {
            let hex = t.get(i + 2..i + 6).unwrap_or("");
            if hex.len() < 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                out.push(Diagnostic::error(
                    codes::LUCENE_ESCAPE,
                    "`\\u` must be followed by four hex digits; Lucene rejects the query. Write `\\\\u` for a literal backslash",
                    cx.range(ByteSpan::new(at, at + 2)),
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
                    cx.range(ByteSpan::new(at, at + 2)),
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
        let at = node.start() + i;
        out.push(Diagnostic::error(
            codes::LUCENE_ESCAPE,
            "a value cannot end with a lone backslash; Lucene rejects the query. Write `\\\\` for a literal backslash",
            cx.range(ByteSpan::new(at, at + 1)),
        ));
    }
}

/// `f:v w`: `w` has no field. Elasticsearch searches it in every field
/// (`index.query.default_field`); Carbon Black searches its default fields
/// and, with its default operator, requires it.
fn bare_terms(node: &Node, cx: Cx<'_>, dialect: Dialect, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let children = node.children();
    for pair in children.windows(2) {
        let (prev, item) = (&pair[0], &pair[1]);
        if prev.kind() != K::FieldQuery || !matches!(item.kind(), K::TermQuery | K::PhraseQuery) {
            continue;
        }
        let word = item.text(source);
        let upper = word.to_ascii_uppercase();
        if matches!(upper.as_str(), "AND" | "OR" | "NOT")
            || matches!(word, "<" | "<=" | ">" | ">=")
            || source[prev.end()..item.start()].is_empty()
        {
            continue;
        }
        let field = prev.field().map_or("", |f| f.text(source));
        let value = prev.query().map_or("", |q| q.text(source));
        let (severity, place) = match dialect {
            Dialect::Elastic => (Severity::Hint, "Elasticsearch searches it in every field"),
            Dialect::Graylog => (Severity::Hint, "Graylog searches it in every field"),
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
            cx.range(item.span()),
        );
        d.severity = severity;
        out.push(d);
    }
}

/// `/x/` glued to a term (`a/b/c`, `path:/var/log`): an unescaped `/`
/// starts a regexp, so the value splits into clauses.
fn glued_regexps(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let children = node.children();
    for (i, item) in children.iter().enumerate() {
        let regexp = match item.kind() {
            K::RegexpQuery => item.clone(),
            K::FieldQuery => match item.query() {
                Some(q) if q.kind() == K::RegexpQuery => q,
                _ => continue,
            },
            _ => continue,
        };
        let before = i > 0 && children[i - 1].end() == item.start();
        let after = children
            .get(i + 1)
            .is_some_and(|n| n.start() == regexp.end());
        if before || after {
            out.push(Diagnostic::warning(
                codes::LUCENE_UNESCAPED_SLASH,
                format!(
                    "`{}` is read as a regular expression because `/` is unescaped, so the value splits into separate clauses; escape the slashes (`\\/`) or quote the value",
                    regexp.text(source)
                ),
                cx.range(regexp.span()),
            ));
        }
    }
}

/// `f:> 10`: Elasticsearch's one-sided range needs the value right after
/// the operator. With a space, `f` is searched for the text `>` (and `>=`
/// becomes a range from `=`), and `10` is searched in every field.
fn range_operator(node: &Node, cx: Cx<'_>, dialect: Dialect, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let Some(query) = node.query() else {
        return;
    };
    let op = query.text(source);
    if query.kind() != K::TermQuery {
        return;
    }
    if dialect == Dialect::CarbonBlack {
        if op.len() > 1 && op.starts_with(['<', '>']) {
            out.push(Diagnostic::warning(
                codes::LUCENE_ELASTICSEARCH_ONLY,
                format!(
                    "`{}` is Elasticsearch's one-sided range; Carbon Black searches `{op}` as text. Use `[a TO *]`",
                    node.text(source)
                ),
                cx.range(query.span()),
            ));
        }
        return;
    }
    if !matches!(op, "<" | "<=" | ">" | ">=") {
        return;
    }
    let field = node.field().map_or("", |f| f.text(source));
    let next = node
        .next_sibling()
        .filter(|n| n.kind() == K::TermQuery && source[node.end()..n.start()] == *" ");
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
        cx.range(query.span()),
    );
    if let Some(next) = next {
        d.range = cx.range(ByteSpan::new(query.start(), next.end()));
        d = d.with_suggestion(format!("{op}{}", next.text(source)));
    }
    out.push(d);
}

/// `_exists_` and escaped wildcards in field names are Elasticsearch
/// extensions; Carbon Black reads them literally.
fn elasticsearch_field_syntax(node: &Node, cx: Cx<'_>, out: &mut Vec<Diagnostic>) {
    let source = cx.source;
    let name = node.text(source);
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
        cx.range(node.span()),
    ));
}

/// `term~N`. Elasticsearch reads `N` as a fuzziness: `0`, `1`, `2`, or
/// `AUTO`; anything else fails the query. Lucene itself clamps `~3` to 2
/// and reads `~0.5` as a similarity, which is what Carbon Black's Solr does.
fn fuzziness(
    node: &Node,
    ancestors: &[Node],
    cx: Cx<'_>,
    dialect: Dialect,
    out: &mut Vec<Diagnostic>,
) {
    let source = cx.source;
    // Phrase slop (`"a b"~3`) is a proximity, not an edit distance.
    if ancestors.last().is_none_or(|p| p.kind() != K::TermQuery) {
        return;
    }
    let slop = &node.text(source)[1..];
    if slop.is_empty() {
        return;
    }
    let span = node.span();
    match dialect {
        Dialect::Elastic | Dialect::Graylog => {
            if let Some(message) = elastic_fuzziness_error(slop) {
                out.push(Diagnostic::error(
                    codes::LUCENE_FUZZY,
                    message,
                    cx.range(span),
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
                cx.range(span),
            ));
        }
    }
}

/// Elasticsearch's `Fuzziness.fromString`, as `query_string` applies it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the value is integral, and `as` saturates (NaN to 0) as Java's (int) does; outside 0..=2 is rejected"
)]
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
    ancestors.iter().any(|n| n.kind() == K::FieldQuery)
}

/// The body of `/.../`, checked as Lucene's `RegExp` the way Elasticsearch
/// compiles it.
fn regexp_body(
    node: &Node,
    ancestors: &[Node],
    cx: Cx<'_>,
    dialect: Dialect,
    out: &mut Vec<Diagnostic>,
) {
    let source = cx.source;
    let t = node.text(source);
    if t.len() < 2 {
        return;
    }
    let body = &t[1..t.len() - 1];
    let start = node.start() + 1;
    let at_char = |at: usize| {
        let b = body.char_indices().nth(at).map_or(body.len(), |(b, _)| b);
        let width = body[b..].chars().next().map_or(1, char::len_utf8);
        if b >= body.len() {
            node.span()
        } else {
            ByteSpan::new(start + b, start + b + width)
        }
    };
    // Graylog: its PCRE-only syntax is `graylog_regex_unsupported`, and
    // Lucene checks the rest with that syntax masked, so one construct is
    // reported once.
    let graylog_scan = (dialect == Dialect::Graylog).then(|| graylog::scan_regex(body));
    let push_body = |finding: &graylog::BodyFinding,
                     code: &str,
                     severity: Severity,
                     out: &mut Vec<Diagnostic>| {
        let at = start + finding.at;
        let mut d = Diagnostic::error(
            code,
            finding.message.clone(),
            cx.range(ByteSpan::new(at, at + finding.len)),
        );
        d.severity = severity;
        out.push(d);
    };
    if let Some(graylog_scan) = &graylog_scan {
        for f in &graylog_scan.unsupported {
            push_body(f, codes::GRAYLOG_REGEX_UNSUPPORTED, Severity::Error, out);
        }
    }
    let checked = graylog_scan.as_ref().map_or(body, |s| s.masked.as_str());
    for problem in regexp::elasticsearch_problems(checked) {
        // Carbon Black's Solr version is not known: syntax advice only.
        if dialect == Dialect::CarbonBlack && !problem.syntax {
            continue;
        }
        let span = problem.at.map_or_else(|| node.span(), at_char);
        // Without a field, `query_string` searches every field (`*`), which
        // Elasticsearch runs leniently: the term matches nothing instead of
        // failing the query. Graylog's validator compiles every regex, so
        // there it fails either way.
        let fielded = has_field(ancestors) || dialect == Dialect::Graylog;
        let message = if fielded {
            problem.message
        } else {
            format!(
                "{}; with no field, Elasticsearch searches every field leniently, so this term silently matches nothing",
                problem.message
            )
        };
        let mut d = Diagnostic::error(codes::LUCENE_REGEXP, message, cx.range(span));
        d.severity = match dialect {
            Dialect::Elastic | Dialect::Graylog if fielded => problem.severity,
            Dialect::Elastic | Dialect::Graylog | Dialect::CarbonBlack => Severity::Warning,
        };
        out.push(d);
        if problem.syntax {
            return;
        }
    }
    if let Some(scan) = &graylog_scan {
        for f in &scan.operators {
            push_body(f, codes::GRAYLOG_REGEX_OPERATOR, Severity::Warning, out);
        }
        for f in &scan.quotes {
            push_body(f, codes::GRAYLOG_REGEX_QUOTE, Severity::Warning, out);
        }
    }
    // Carbon Black lower-cases only the tokens of tokenized fields: the upper-case hint is
    // for a regexp under one of those, never for another field or for no field.
    let tokenized = dialect == Dialect::CarbonBlack
        && ancestors
            .iter()
            .rev()
            .find(|n| n.kind() == K::FieldQuery)
            .and_then(Node::field)
            .and_then(|f| carbon_black::field(f.text(source)))
            .is_some_and(|f| f.tokenized);
    regexp_pcre_habits(body, start, cx, dialect, tokenized, out);
}

/// Valid Lucene, but not what a PCRE author meant: `(?:`, `(?i)`, and the
/// anchors `^` and `$` are literal text, because Lucene regexps always match
/// the whole term. Carbon Black matches lower-cased tokens, so upper-case
/// letters cannot match on tokenized fields (`tokenized`: the regexp's field
/// is one).
fn regexp_pcre_habits(
    body: &str,
    start: usize,
    cx: Cx<'_>,
    dialect: Dialect,
    tokenized: bool,
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
    let span = |b: usize, len: usize| cx.range(ByteSpan::new(start + b, start + b + len));
    // Graylog reports `(?…)` as `graylog_regex_unsupported`.
    if let Some(b) = group.filter(|_| dialect != Dialect::Graylog) {
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
        && tokenized
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
fn looks_like_kuery(tree: &Tree, cx: Cx<'_>, found: &[Diagnostic]) -> Option<Diagnostic> {
    let source = cx.source;
    let root = tree.root();
    let mut signals: Vec<&str> = Vec::new();
    let has = |code: &str| found.iter().any(|d| d.code == code);
    if has(codes::LUCENE_LOWERCASE_OPERATOR) {
        signals.push("lower-case `and`/`or`/`not` operators");
    }
    if has(codes::LUCENE_KUERY_SYNTAX) {
        signals.push("`field >= value` ranges");
    }
    // A leading lower-case `not` is a term to Lucene, an operator to KQL.
    let top = root.first_child();
    let first = top.clone().map(|n| {
        if n.kind() == K::BooleanQuery {
            n.first_child().unwrap_or(n)
        } else {
            n
        }
    });
    if first.is_some_and(|n| n.kind() == K::TermQuery && n.text(source).eq_ignore_ascii_case("not"))
        && top.is_some_and(|n| n.kind() == K::BooleanQuery)
    {
        signals.push("a leading `not`");
    }
    // Lucene rejects the text, and Kibana's KQL grammar accepts it.
    if tree.has_error() && opentide_kuery::parses(source) {
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
            cx.range(ByteSpan::new(0, source.len())),
        )
    })
}

/// What every check reads: the text and its line index (one per analysis,
/// so converting a span is a binary search, not a scan from the start).
#[derive(Clone, Copy)]
pub(crate) struct Cx<'a> {
    pub(crate) source: &'a str,
    pub(crate) lines: &'a LineIndex<'a>,
}

impl Cx<'_> {
    pub(crate) fn range(self, span: ByteSpan) -> Range {
        self.lines.range(span)
    }
}

/// The HighlightSpec capture of a token: `highlights/queries/lucene/
/// highlights.scm` as a match on kinds (a field name's token first, then
/// what a token is, then what its node is).
fn capture(token: &rowan::SyntaxToken<syntax::Lucene>) -> Option<&'static str> {
    let parent = token.parent().map(|p| p.kind());
    if parent == Some(K::FieldName) {
        return Some("property");
    }
    Some(match (token.kind(), parent) {
        (K::Star | K::Colon, _)
        | (K::Plus, Some(K::Required))
        | (K::Minus, Some(K::Prohibited)) => "operator",
        (K::RangeTerm | K::Boost | K::Fuzzy, _) => "number",
        (K::Regexp | K::Phrase | K::WildcardTerm | K::BareOperator | K::Term, _) => "string",
        (K::AndKw | K::AmpAmp, Some(K::And))
        | (K::OrKw | K::PipePipe, Some(K::Or))
        | (K::NotKw | K::Bang, Some(K::Not))
        | (K::ToKw, _) => "keyword",
        (K::LParen | K::RParen | K::LBracket | K::RBracket | K::LBrace | K::RBrace, _) => {
            "punctuation.bracket"
        }
        _ => return None,
    })
}

fn highlight(spec: &HighlightSpec, root: &syntax::SyntaxNode, source: &str) -> Vec<HighlightToken> {
    let spans: Vec<(ByteSpan, &str)> = root
        .descendants_with_tokens()
        .inspect(|_| tree::count_visit())
        .filter_map(rowan::NodeOrToken::into_token)
        .filter_map(|t| {
            let r = t.text_range();
            Some((
                ByteSpan::new(usize::from(r.start()), usize::from(r.end())),
                capture(&t)?,
            ))
        })
        .collect();
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
}

/// Field names a query mentions, for completion.
pub fn fields(source: &str) -> Vec<String> {
    let tree = Tree::parse(source);
    let names: std::collections::BTreeSet<String> = tree
        .root
        .descendants()
        .filter(|n| n.kind() == K::FieldName)
        .map(|n| n.text().to_string())
        .collect();
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

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset) {
        return None;
    }
    let tree = Tree::parse(source);
    let node = tree.root().at_offset(offset)?;
    let word = node.text(source);
    if node.kind() == K::Boost {
        return Some(format!(
            "**`^`** boost\n\nRaises the clause's relevance weight.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    if node.kind() == K::Fuzzy {
        return Some(format!(
            "**`~`** fuzzy or proximity\n\nAfter a term, edit distance; after a phrase, word slop.\n\n[Elastic docs]({SYNTAX_DOCS})"
        ));
    }
    OPERATORS
        .iter()
        .find(|(k, _)| *k == word)
        .map(|(k, d)| format!("**`{k}`** (Lucene)\n\n{d}\n\n[Elastic docs]({SYNTAX_DOCS})"))
}

/// Hover in a dialect: Carbon Black fields from its process search catalog,
/// Graylog's built-in message fields, then the operators every dialect
/// shares.
pub fn hover_dialect(source: &str, offset: usize, dialect: Dialect) -> Option<String> {
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset.min(source.len())) {
        return None;
    }
    if dialect == Dialect::Graylog {
        let offset = offset.min(source.len());
        let tree = Tree::parse(source);
        let mut node = tree.root().at_offset(offset);
        while let Some(n) = node {
            if n.kind() == K::FieldName {
                if let Some(docs) = graylog::field_docs(n.text(source)) {
                    return Some(docs);
                }
                break;
            }
            node = n.parent();
        }
    }
    if dialect == Dialect::CarbonBlack {
        let offset = offset.min(source.len());
        let tree = Tree::parse(source);
        // A field name is a `term` (or a wildcard) under `field_name`.
        let mut node = tree.root().at_offset(offset);
        while let Some(n) = node {
            if n.kind() == K::FieldName {
                if let Some(f) = carbon_black::field(n.text(source)) {
                    return Some(carbon_black::markdown(f));
                }
                break;
            }
            node = n.parent();
        }
    }
    hover(source, offset)
}

/// Completion in a dialect: a Carbon Black query is offered its process
/// search fields (or a field's values), never ECS fields; a Graylog query
/// the fields it names and Graylog's built-in message fields.
pub fn completions_dialect(source: &str, offset: usize, dialect: Dialect) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    match dialect {
        Dialect::Elastic => completions(source, offset),
        Dialect::Graylog => {
            let mut items = completions(source, offset);
            for item in graylog::completions() {
                if !items.iter().any(|i| i.label == item.label) {
                    items.push(item);
                }
            }
            items
        }
        Dialect::CarbonBlack => {
            let mut items = Vec::new();
            if before.ends_with(char::is_whitespace) && !before.trim().is_empty() {
                for kw in ["AND", "OR", "NOT"] {
                    items.push(CompletionItem::new(kw, "keyword"));
                }
            }
            items.extend(carbon_black::completions(before));
            items
        }
    }
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
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

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<syntax::Lucene>(&parser::parse(source).1)
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<syntax::Lucene>(&parser::parse(source).1)
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
        // The upper-case hint is for a tokenized field (`process_cmdline`) only.
        let hinted = |src: &str| {
            cb(src)
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Hint)
        };
        assert!(hinted("process_cmdline:/.*CMD.*/"));
        assert!(!hinted("process_name:/CMD.*/"), "an untokenized field");
        assert!(!hinted("not_a_catalog_field:/CMD.*/"), "an unknown field");
        assert!(!hinted("/CMD.*/"), "no field");
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

    fn gl(src: &str) -> Vec<Diagnostic> {
        analyze_dialect(src, Dialect::Graylog).diagnostics
    }

    fn gl_codes(src: &str) -> Vec<(String, Severity)> {
        gl(src).into_iter().map(|d| (d.code, d.severity)).collect()
    }

    fn only(src: &str, code: &str) -> Vec<Diagnostic> {
        gl(src).into_iter().filter(|d| d.code == code).collect()
    }

    #[test]
    fn dialect_for_platform() {
        assert_eq!(Dialect::for_platform("graylog"), Dialect::Graylog);
        assert_eq!(
            Dialect::for_platform("carbon_black_cloud"),
            Dialect::CarbonBlack
        );
        assert_eq!(Dialect::for_platform("elastic"), Dialect::Elastic);
        assert_eq!(Dialect::for_platform(""), Dialect::Elastic);
    }

    #[test]
    fn graylog_spec_queries_are_clean() {
        for src in [
            r"EventID:1 AND image_lc:/.*\\mshta\.exe/",
            r"EventID:1 AND image_lc:/.*\\mshta\.exe/ AND command_line_lc:/.*https?:\/\/.*/",
            "EventID:1\nAND parent_image_lc:/.*\\\\(winword|excel|powerpnt|outlook)\\.exe/\nAND image_lc:/.*\\\\(powershell|pwsh)\\.exe/\nAND command_line_lc:/.*( -enc | -encodedcommand |frombase64string|iex\\().*/\nAND NOT command_line_lc:/.*\\\\program files\\\\contoso\\\\admintools\\\\.*/",
            r"x:/\d{2,4}\s\w+/ AND y:/<16-31>/ AND z:/(a|b)c/",
            "_exists_:CommandLine AND source:dc01 AND x:abc* AND x:a?c",
        ] {
            assert!(gl(src).is_empty(), "{src}: {:?}", gl(src));
        }
    }

    #[test]
    fn graylog_leading_wildcard() {
        for src in [
            "Image:*cmd.exe",
            "x:?abc",
            "*",
            "x:*",
            "x:(a OR *b)",
            "-*",
            "x:*~",
        ] {
            let found = only(src, codes::GRAYLOG_LEADING_WILDCARD);
            assert_eq!(found.len(), 1, "{src}");
            assert_eq!(found[0].severity, Severity::Error, "{src}");
        }
        let d = &only("Image:*cmd.exe", codes::GRAYLOG_LEADING_WILDCARD)[0];
        assert!(d.message.contains(r"Image:/.*cmd\.exe/"), "{}", d.message);
        assert_eq!((d.range.start.character, d.range.end.character), (6, 14));
        assert!(
            only("x:*", codes::GRAYLOG_LEADING_WILDCARD)[0]
                .message
                .contains("_exists_:x")
        );
        for src in ["*", "*:*"] {
            assert!(
                only(src, codes::GRAYLOG_LEADING_WILDCARD)[0]
                    .message
                    .contains("_exists_:<field>"),
                "{src}"
            );
        }
        for src in [
            "x:abc*",
            "x:a*b",
            "x:\\*abc",
            "x:\"*abc\"",
            "x:[*a TO b]",
            "x:\\\\*",
        ] {
            assert!(
                only(src, codes::GRAYLOG_LEADING_WILDCARD).is_empty(),
                "{src}"
            );
        }
        // Not a Graylog code elsewhere.
        assert!(codes_of("Image:*cmd.exe").is_empty());
    }

    #[test]
    fn graylog_regex_unsupported_replaces_the_pcre_habit_warning() {
        for src in [
            "x:/(?i)cmd.*/",
            "x:/(?:a|b)/",
            "x:/(?=a)b/",
            "x:/(?<!a)b/",
            r"x:/(a)\1/",
            r"x:/\bnet\b/",
            r"x:/a\B/",
        ] {
            let found = gl_codes(src);
            assert!(
                found
                    .iter()
                    .any(|(c, s)| c == codes::GRAYLOG_REGEX_UNSUPPORTED && *s == Severity::Error),
                "{src}: {found:?}"
            );
            assert!(
                found.iter().all(|(c, _)| c != codes::LUCENE_REGEXP),
                "{src}: reported twice {found:?}"
            );
        }
        // Elastic keeps its own advice.
        assert!(codes_of("x:/(?i)cmd.*/").contains(&codes::LUCENE_REGEXP.to_string()));
        // An anchor is still Lucene advice; another Lucene error still counts.
        assert!(
            gl_codes("x:/^cmd/")
                .iter()
                .any(|(c, _)| c == codes::LUCENE_REGEXP)
        );
        let found = gl_codes("x:/(?i)[a/");
        assert!(
            found
                .iter()
                .any(|(c, _)| c == codes::GRAYLOG_REGEX_UNSUPPORTED)
        );
        assert!(
            found
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Error)
        );
        // UTF-8: the range is the `\b`, after a two-byte character.
        let d = &only(r"x:/é\b/", codes::GRAYLOG_REGEX_UNSUPPORTED)[0];
        assert_eq!((d.range.start.character, d.range.end.character), (4, 6));
    }

    /// The nesting limit is worded like the other languages' (the parser's
    /// message, one diagnostic) and never dumps the query it stopped on (#1706).
    #[test]
    fn nesting_past_the_limit_names_the_limit_not_the_query() {
        let source = "(".repeat(6_000);
        let found = analyze(&source).diagnostics;
        let errors: Vec<_> = found
            .iter()
            .filter(|d| d.code == codes::LUCENE_PARSE_ERROR && d.severity == Severity::Error)
            .filter(|d| d.message.contains("nesting"))
            .collect();
        assert_eq!(errors.len(), 1, "{found:?}");
        let message = &errors[0].message;
        assert!(
            message.starts_with("Lucene syntax error: nesting deeper than ")
                && message.ends_with(" levels"),
            "{message}"
        );
        assert!(message.len() < 80, "{} chars", message.len());
    }

    #[test]
    fn graylog_regex_operators_and_quotes() {
        let d = only("x:/.*f~g.*/", codes::GRAYLOG_REGEX_OPERATOR);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::Warning);
        assert_eq!(
            (d[0].range.start.character, d[0].range.end.character),
            (6, 7)
        );
        for src in ["x:/a#b/", "x:/a&b/", "x:/a>b/"] {
            assert_eq!(only(src, codes::GRAYLOG_REGEX_OPERATOR).len(), 1, "{src}");
        }
        for src in [r"x:/a\~b/", "x:/[~#&<>]/", "x:/<1-5>/"] {
            assert!(only(src, codes::GRAYLOG_REGEX_OPERATOR).is_empty(), "{src}");
        }
        // `<` alone is a Lucene syntax error: an error, not also a warning.
        let found = gl_codes("x:/a<b/");
        assert!(
            found
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Error)
        );
        assert!(
            found
                .iter()
                .all(|(c, _)| c != codes::GRAYLOG_REGEX_OPERATOR)
        );
        let q = only("x:/a\"b\"c/", codes::GRAYLOG_REGEX_QUOTE);
        assert_eq!(q.len(), 1);
        assert_eq!(
            (q[0].range.start.character, q[0].range.end.character),
            (4, 7)
        );
        assert!(only(r#"x:/a\"b/"#, codes::GRAYLOG_REGEX_QUOTE).is_empty());
        // Unpaired: Lucene refuses it, which is the error.
        let found = gl_codes("x:/a\"b/");
        assert!(
            found
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Error)
        );
        assert!(found.iter().all(|(c, _)| c != codes::GRAYLOG_REGEX_QUOTE));
        // Unfielded regex errors are errors on Graylog (its validator
        // compiles every regex).
        assert!(
            gl_codes("/[a/")
                .iter()
                .any(|(c, s)| c == codes::LUCENE_REGEXP && *s == Severity::Error)
        );
    }

    #[test]
    fn graylog_double_backslash() {
        let d = only(
            r"x:a\\\\b AND y:/c\\\\\\d/",
            codes::GRAYLOG_DOUBLE_BACKSLASH,
        );
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[0].range.start.character, d[0].range.end.character),
            (3, 7)
        );
        assert_eq!(
            (d[1].range.start.character, d[1].range.end.character),
            (17, 23)
        );
        assert!(only(r"x:a\\b", codes::GRAYLOG_DOUBLE_BACKSLASH).is_empty());
        // Multibyte text before the run.
        let d = only(r"x:ü\\\\", codes::GRAYLOG_DOUBLE_BACKSLASH);
        assert_eq!(
            (d[0].range.start.character, d[0].range.end.character),
            (3, 7)
        );
    }

    #[test]
    fn graylog_analyzed_field() {
        for src in [
            "message:/foo.*/",
            "full_message:foo*",
            "message:[a TO b]",
            "message:>5",
            "message:(foo* OR bar)",
        ] {
            let d = only(src, codes::GRAYLOG_ANALYZED_FIELD);
            assert_eq!(d.len(), 1, "{src}");
            assert_eq!(d[0].severity, Severity::Warning);
        }
        for src in ["message:foo", "message_lc:/foo.*/", "source:dc*", "/foo.*/"] {
            assert!(only(src, codes::GRAYLOG_ANALYZED_FIELD).is_empty(), "{src}");
        }
    }

    #[test]
    fn graylog_follows_elastic_elsewhere() {
        let found = gl_codes("x:a and y:b");
        assert!(
            found
                .iter()
                .any(|(c, _)| c == codes::LUCENE_LOWERCASE_OPERATOR)
        );
        assert!(
            gl_codes("x:(a")
                .iter()
                .any(|(c, _)| c == codes::LUCENE_PARSE_ERROR)
        );
        assert!(
            gl_codes("x:b~1.5")
                .iter()
                .any(|(c, s)| c == codes::LUCENE_FUZZY && *s == Severity::Error)
        );
        assert!(
            gl_codes("x:\\u12")
                .iter()
                .any(|(c, _)| c == codes::LUCENE_ESCAPE)
        );
        // No Kibana KQL or Carbon Black advice.
        assert!(
            gl_codes("a:1 and b >= 2")
                .iter()
                .all(|(c, _)| c != codes::LUCENE_LOOKS_LIKE_KUERY)
        );
        assert!(gl_codes("_exists_:x").is_empty());
        let d = only("user:alice bob", codes::LUCENE_BARE_TERM);
        assert!(d[0].message.contains("Graylog"), "{}", d[0].message);
    }

    #[test]
    fn graylog_hover_and_completion() {
        let h = hover_dialect("message:x", 2, Dialect::Graylog).expect("hover");
        assert!(h.contains("Analysed"), "{h}");
        assert!(hover_dialect("a:1 AND b:2", 5, Dialect::Graylog).is_some());
        let items = completions_dialect("EventID:1 AND ", 14, Dialect::Graylog);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        for want in ["AND", "EventID", "source", "full_message", "_exists_"] {
            assert!(labels.contains(&want), "{want}: {labels:?}");
        }
    }

    #[test]
    fn hover_and_completion() {
        let h = hover("a:1 AND b:2", 5).expect("hover");
        assert!(h.contains("AND"));
        assert!(completions("a:1 ", 4).iter().any(|i| i.label == "AND"));
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "user.name:\u{e9} AND host.name:x";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside).is_empty());
        assert_eq!(hover(src, inside), None);
        for dialect in [Dialect::Elastic, Dialect::Graylog, Dialect::CarbonBlack] {
            assert!(completions_dialect(src, inside, dialect).is_empty());
            assert_eq!(hover_dialect(src, inside, dialect), None);
        }
    }
}
