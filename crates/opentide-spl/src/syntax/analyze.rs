//! The analysis on the pure-Rust tree: syntax errors, unknown commands, the
//! stage checks of `stages.rs` and `rejects.rs`, and highlighting. The text
//! checks (`perf`, `search_operators`, `parens`, `cim`, `declared`) read the
//! source and are shared with the tree-sitter path.
//!
//! On broken input it is never noisier than before: one diagnostic per error
//! region, at most [`MAX_PARSE_ERRORS`], and no hint after the first syntax
//! error (recovery leaves fragments a hint would misread).

use super::kind::SyntaxKind as K;
use super::{SyntaxNode, SyntaxToken, parse};
use crate::{AnalyzeResult, Catalog};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, codes};
use opentide_highlight::{HighlightSpec, tokens_in};
use opentide_parse::SyntaxError;
use rowan::{NodeOrToken, TextRange};

/// A badly broken query reports this many error regions, not one per token.
const MAX_PARSE_ERRORS: usize = 5;

/// Longest token text quoted in a message.
const MAX_QUOTED: usize = 32;

/// A command word followed by at most this many search terms is not
/// reported: a short search may really look for the word (`delete user`).
const MAX_TERMS_AFTER_A_WORD: usize = 1;

const LOOSE_OPERATORS: [K; 5] = [K::EQ2, K::LT_GT, K::EQ_GT, K::EQ_LT, K::BANG_TILDE];

fn span(range: TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// A node's span, never empty so editors can show it.
fn shown(range: TextRange) -> ByteSpan {
    let start = usize::from(range.start());
    ByteSpan::new(start, usize::from(range.end()).max(start + 1))
}

/// Analyzes `source` on the pure-Rust tree.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze(source: &str) -> AnalyzeResult {
    let catalog = Catalog::cached();
    let spec = HighlightSpec::shared().expect("spec");
    let lines = LineIndex::new(source);
    // The pipelines, scanned once for the walks of the checks below.
    let _plan = crate::scan::plan_scope(source);
    let (root, parsed) = parse(source);
    let mut diagnostics = Vec::new();
    let index = TreeIndex::new(&root);
    parse_errors(&root, &index, &parsed.errors, &lines, &mut diagnostics);
    let broken = broken_regions(&root, &index, &parsed.errors);
    unknown_commands(&index, catalog, &lines, &mut diagnostics);
    crate::perf::collect(source, catalog, &lines, &mut diagnostics);
    crate::search_operators::collect(source, catalog, &lines, &mut diagnostics);
    crate::parens::refine(source, &lines, &mut diagnostics);
    stages(
        &root,
        &index,
        source,
        &parsed.errors,
        catalog,
        &lines,
        &mut diagnostics,
    );
    rejects(&index, &lines, &mut diagnostics);
    crate::cim::collect(source, &lines, &mut diagnostics);
    crate::declared::collect(source, catalog, &lines, &mut diagnostics);
    // No hint in a broken stage at or after its syntax error, nor over it:
    // recovery leaves fragments there. Splunk splits stages at `|` whatever
    // the parentheses, so the stages after a broken one are read as written.
    let key = |p: opentide_core::Position| (p.line, p.character);
    // The regions, sorted and merged where they overlap, so that each
    // diagnostic is checked against one of them, not all.
    let mut regions: Vec<_> = broken
        .into_iter()
        .map(|(from, to)| (key(lines.position(from)), key(lines.position(to))))
        .collect();
    regions.sort_unstable();
    let mut merged: Vec<(_, _)> = Vec::with_capacity(regions.len());
    for (from, to) in regions {
        match merged.last_mut() {
            Some((_, last_to)) if from <= *last_to => *last_to = (*last_to).max(to),
            _ => merged.push((from, to)),
        }
    }
    diagnostics.retain(|d| {
        let (start, end) = (key(d.range.start), key(d.range.end));
        // The last region that starts before the diagnostic ends.
        let before = merged.partition_point(|&(from, _)| from < end);
        d.code == codes::SPL_PARSE_ERROR
            || before
                .checked_sub(1)
                .and_then(|i| merged.get(i))
                .is_none_or(|&(_, to)| start > to)
    });
    let tokens = highlight(&index, source, &lines, spec, catalog).unwrap_or_default();
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

// ---------------------------------------------------------------- errors

/// The significant tokens and the error nodes of a tree, in source order,
/// read once: each syntax error looks them up by offset, and a broken query
/// can have one error per stage, so a walk of the tree per error is
/// quadratic.
struct TreeIndex {
    tokens: Vec<SyntaxToken>,
    errors: Vec<SyntaxNode>,
    /// Every node, in preorder (the root first).
    nodes: Vec<SyntaxNode>,
    /// Every token, trivia included, in order.
    all_tokens: Vec<SyntaxToken>,
}

#[cfg(test)]
thread_local! {
    /// The elements the analysis's walks visited on this thread: [`visits`].
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one element a walk over the tree visited, in tests (ADR 0014 §7).
#[inline]
fn count_visit() {
    #[cfg(test)]
    VISITS.set(VISITS.get() + 1);
}

/// How many elements the analysis's walks over the tree visited on this thread.
#[cfg(test)]
pub(crate) fn visits() -> usize {
    VISITS.get()
}

impl TreeIndex {
    /// One walk over every element of the tree (ADR 0014 §5a): the checks
    /// and the highlight below read its lists, in preorder, and walk no more.
    fn new(root: &SyntaxNode) -> Self {
        let mut index = Self {
            tokens: Vec::new(),
            errors: Vec::new(),
            nodes: Vec::new(),
            all_tokens: Vec::new(),
        };
        for element in root.descendants_with_tokens() {
            count_visit();
            match element {
                NodeOrToken::Node(node) => {
                    if node.kind() == K::ERROR {
                        index.errors.push(node.clone());
                    }
                    index.nodes.push(node);
                }
                NodeOrToken::Token(token) => {
                    if !trivia(token.kind()) {
                        index.tokens.push(token.clone());
                    }
                    index.all_tokens.push(token);
                }
            }
        }
        index
    }

    /// The first significant token at or after `offset`.
    fn token_at_or_after(&self, offset: usize) -> Option<SyntaxToken> {
        let at = self
            .tokens
            .partition_point(|t| usize::from(t.text_range().start()) < offset);
        self.tokens.get(at).cloned()
    }

    /// The last significant token that ends at or before `offset`.
    fn token_before(&self, offset: usize) -> Option<SyntaxToken> {
        let at = self
            .tokens
            .partition_point(|t| usize::from(t.text_range().end()) <= offset);
        at.checked_sub(1).and_then(|i| self.tokens.get(i)).cloned()
    }

    /// The outermost error node that starts at `offset`, if any (nodes come
    /// in preorder, so the first of those starting there).
    fn error_node_at(&self, offset: usize) -> Option<SyntaxNode> {
        let at = self
            .errors
            .partition_point(|n| usize::from(n.text_range().start()) < offset);
        self.errors
            .get(at)
            .filter(|n| usize::from(n.text_range().start()) == offset)
            .cloned()
    }
}

fn trivia(kind: K) -> bool {
    matches!(kind, K::WHITESPACE | K::COMMENT)
}

/// Where hints are not run: from each syntax error to the end of the stage
/// it is in (the end of the input when it is in none), and every error node.
fn broken_regions(
    root: &SyntaxNode,
    index: &TreeIndex,
    errors: &[SyntaxError],
) -> Vec<(usize, usize)> {
    let end = usize::from(root.text_range().end());
    errors
        .iter()
        .map(|error| {
            let from = usize::from(error.gap.start());
            // The stage of the last token before the error, else of the next.
            let stage = index
                .token_before(from)
                .or_else(|| index.token_at_or_after(from))
                .and_then(|t| t.parent())
                .and_then(|n| {
                    n.ancestors()
                        .find(|a| a.parent().is_some_and(|p| p.kind() == K::PIPELINE))
                });
            let to = stage
                .filter(|s| s.kind() != K::ERROR)
                .map_or(end, |s| usize::from(s.text_range().end()));
            (from, to.max(from))
        })
        // And every error node: the tokens recovery skipped.
        .chain(index.errors.iter().map(|n| {
            (
                usize::from(n.text_range().start()),
                usize::from(n.text_range().end()),
            )
        }))
        .collect()
}

/// `spl_parse_error`s: one per error region (the errors of one place and of
/// the error node recovery made there), at most [`MAX_PARSE_ERRORS`].
fn parse_errors(
    root: &SyntaxNode,
    index: &TreeIndex,
    errors: &[SyntaxError],
    lines: &LineIndex<'_>,
    out: &mut Vec<Diagnostic>,
) {
    let mut regions: Vec<(&SyntaxError, usize)> = Vec::new();
    for error in errors {
        let at = usize::from(error.gap.end());
        let end = index
            .error_node_at(at)
            .map_or(at, |n| usize::from(n.text_range().end()));
        if let Some((kept, last_end)) = regions.last_mut()
            && usize::from(error.gap.start()) <= *last_end
        {
            *last_end = (*last_end).max(end);
            // An unclosed bracket names the cause: it wins over what follows it.
            if error.message.starts_with("missing `") && !kept.message.starts_with("missing `") {
                *kept = error;
            }
            continue;
        }
        regions.push((error, end));
    }
    for (error, _) in regions.into_iter().take(MAX_PARSE_ERRORS) {
        let (where_, message) = describe(root, index, error);
        out.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            message,
            lines.range(where_),
        ));
    }
}

/// Where and what to report for one error region.
fn describe(root: &SyntaxNode, index: &TreeIndex, error: &SyntaxError) -> (ByteSpan, String) {
    let gap_start = usize::from(error.gap.start());
    for (closer, opener, open) in [("`)`", "(", K::L_PAREN), ("`]`", "[", K::L_BRACKET)] {
        if error.message == format!("missing {closer}")
            && let Some(at) = unclosed(root, gap_start, open)
        {
            return (
                shown(at),
                format!("SPL syntax error: '{opener}' is never closed"),
            );
        }
    }
    let skipped = error.message == "unexpected token"
        || index.error_node_at(usize::from(error.gap.end())).is_some();
    match index.token_at_or_after(usize::from(error.gap.end())) {
        // A token recovery had to skip: name it, as before.
        Some(token) if skipped => (
            shown(token.text_range()),
            format!("SPL syntax error: unexpected '{}'", quoted(token.text())),
        ),
        // Something is missing before the token: say what, and where.
        Some(token) => (
            shown(token.text_range()),
            format!(
                "SPL syntax error: {} before '{}'",
                error.message,
                quoted(token.text())
            ),
        ),
        None => (
            ByteSpan::new(gap_start, gap_start + 1),
            format!("SPL syntax error: {}", error.message),
        ),
    }
}

/// The `(` or `[` that the token ending at `offset` is inside of and that
/// no closer follows: the innermost node holding it.
fn unclosed(root: &SyntaxNode, offset: usize, open: K) -> Option<TextRange> {
    let close = if open == K::L_PAREN {
        K::R_PAREN
    } else {
        K::R_BRACKET
    };
    let token = root
        .descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| usize::from(t.text_range().end()) <= offset && !trivia(t.kind()))
        .last()?;
    let mut node = token.parent();
    while let Some(n) = node {
        let opener = n
            .children_with_tokens()
            .filter_map(NodeOrToken::into_token)
            .find(|t| t.kind() == open);
        let closed = n
            .children_with_tokens()
            .filter_map(NodeOrToken::into_token)
            .any(|t| t.kind() == close);
        if let Some(opener) = opener
            && !closed
        {
            return Some(opener.text_range());
        }
        node = n.parent();
    }
    None
}

fn quoted(text: &str) -> String {
    let line = text.trim().lines().next().unwrap_or("");
    if line.chars().count() <= MAX_QUOTED {
        return line.to_string();
    }
    let cut: String = line.chars().take(MAX_QUOTED).collect();
    format!("{cut}…")
}

/// Whether a syntax error or an error node lies inside `range`.
fn has_error(node: &SyntaxNode, errors: &[SyntaxError]) -> bool {
    let range = node.text_range();
    node.descendants().any(|n| n.kind() == K::ERROR)
        || errors.iter().any(|e| {
            range.contains_inclusive(e.gap.start()) && range.contains_inclusive(e.gap.end())
        })
}

// ---------------------------------------------------------------- commands

fn first_token_text(node: &SyntaxNode) -> String {
    node.children_with_tokens()
        .find_map(|e| match e {
            NodeOrToken::Token(t) if !trivia(t.kind()) => Some(t.text().to_owned()),
            NodeOrToken::Node(n) => n.first_token().map(|t| t.text().to_owned()),
            NodeOrToken::Token(_) => None,
        })
        .unwrap_or_default()
}

/// `spl_unknown_command`: a name in command position the catalog does not
/// know. An app on the search head can add commands, so it is a warning; one
/// edit from a known command it is almost certainly a typo, an error.
fn unknown_commands(
    index: &TreeIndex,
    catalog: &Catalog,
    lines: &LineIndex<'_>,
    out: &mut Vec<Diagnostic>,
) {
    // The finding of each name, made once: its typo check and "did you mean"
    // scan the whole catalog, and a query can repeat one unknown command.
    let mut made: std::collections::HashMap<String, Diagnostic> = std::collections::HashMap::new();
    for node in index
        .nodes
        .iter()
        .filter(|n| n.kind() == K::UNKNOWN_COMMAND)
    {
        let name = first_token_text(node);
        if catalog.command(&name).is_none() {
            let range = lines.range(shown(node.text_range()));
            let mut finding = made
                .entry(name)
                .or_insert_with_key(|name| crate::unknown_command(name, range, catalog))
                .clone();
            finding.range = range;
            out.push(finding);
        }
    }
}

// ---------------------------------------------------------------- stages

fn child_nodes(node: &SyntaxNode) -> impl Iterator<Item = SyntaxNode> {
    node.children()
}

fn has_child(node: &SyntaxNode, kinds: &[K]) -> bool {
    child_nodes(node).any(|c| kinds.contains(&c.kind()))
}

/// What an argumentless command does, or `None` when it has arguments or
/// none are needed.
fn empty_command(node: &SyntaxNode) -> Option<(String, &'static str, bool)> {
    let name = first_token_text(node);
    let empty = match node.kind() {
        K::WHERE_COMMAND => child_nodes(node).next().is_none(),
        K::SEARCH_COMMAND => !has_child(node, &[K::SEARCH_EXPRESSION]),
        K::FIELDS_COMMAND => !has_child(node, &[K::IDENTIFIER, K::GLOB, K::STR, K::MACRO_CALL]),
        K::LOOKUP_COMMAND | K::INPUTLOOKUP_COMMAND => {
            !has_child(node, &[K::IDENTIFIER, K::STR, K::MACRO_CALL])
        }
        K::STATS_COMMAND => {
            !has_child(node, &[K::AGGREGATE_ITEM, K::MACRO_CALL])
                && matches!(
                    name.as_str(),
                    "stats" | "eventstats" | "streamstats" | "sistats"
                )
        }
        _ => false,
    };
    if !empty {
        return None;
    }
    let (what, error) = match name.as_str() {
        "stats" => ("returns no results", true),
        "inputlookup" => ("fails at run time: Splunk needs a lookup table", true),
        "sistats" => ("computes nothing to summarize", false),
        _ => ("does nothing", false),
    };
    Some((name, what, error))
}

/// In a pipeline whose query or subsearch has a syntax error.
fn in_broken_pipeline(node: &SyntaxNode, errors: &[SyntaxError]) -> bool {
    let mut at = node.parent();
    while let Some(parent) = at {
        if parent.kind() == K::ERROR {
            return true;
        }
        if parent.kind() == K::PIPELINE {
            let owner = parent.parent().unwrap_or(parent);
            return has_error(&owner, errors);
        }
        at = parent.parent();
    }
    false
}

fn stages(
    root: &SyntaxNode,
    index: &TreeIndex,
    source: &str,
    errors: &[SyntaxError],
    catalog: &Catalog,
    lines: &LineIndex<'_>,
    out: &mut Vec<Diagnostic>,
) {
    let Some(pipeline) = root.children().find(|n| n.kind() == K::PIPELINE) else {
        return;
    };
    command_without_pipe(&pipeline, source, errors, catalog, lines, out);
    // `has_error` of the root, from the index: its error nodes are all of the
    // tree's, and a walk of every node found none in a query without one.
    let root_range = root.text_range();
    let root_error = !index.errors.is_empty()
        || errors.iter().any(|e| {
            root_range.contains_inclusive(e.gap.start())
                && root_range.contains_inclusive(e.gap.end())
        });
    if !root_error {
        empty_stage(&pipeline, lines, out);
    }
    for node in &index.nodes {
        if let Some((name, what, error)) = empty_command(node)
            && !in_broken_pipeline(node, errors)
        {
            let range = lines.range(shown(node.text_range()));
            let message = format!("`{name}` with no arguments {what}");
            out.push(if error {
                Diagnostic::error(codes::SPL_EMPTY_COMMAND, message, range)
            } else {
                Diagnostic::warning(codes::SPL_EMPTY_COMMAND, message, range)
            });
        }
    }
}

/// `... | stats count |`: the query's last token is a `|`.
fn empty_stage(pipeline: &SyntaxNode, lines: &LineIndex<'_>, out: &mut Vec<Diagnostic>) {
    let elements: Vec<_> = pipeline
        .children_with_tokens()
        .filter(|e| !trivia(e.kind()))
        .collect();
    let Some(NodeOrToken::Token(last)) = elements.last() else {
        return;
    };
    if last.kind() != K::PIPE || elements.len() < 2 {
        return;
    }
    out.push(Diagnostic::warning(
        codes::SPL_EMPTY_STAGE,
        "empty pipeline stage: Splunk ignores a trailing `|`; remove it or add the command",
        lines.range(shown(last.text_range())),
    ));
}

/// `tstats count where index=a by sourcetype`: with no `|`, Splunk runs
/// `search tstats count ...` and returns nothing.
fn command_without_pipe(
    pipeline: &SyntaxNode,
    source: &str,
    errors: &[SyntaxError],
    catalog: &Catalog,
    lines: &LineIndex<'_>,
    out: &mut Vec<Diagnostic>,
) {
    let Some(NodeOrToken::Node(search)) =
        pipeline.children_with_tokens().find(|e| !trivia(e.kind()))
    else {
        return;
    };
    if search.kind() != K::BARE_SEARCH || has_error(&search, errors) {
        return;
    }
    // The first term must be a word: a leading `NOT` is no command.
    let Some(first) = search.children().next() else {
        return;
    };
    let terms = search
        .children()
        .filter(|n| n.kind() != K::SEARCH_BOOLEAN)
        .skip(1);
    let word = first.first_token();
    if first.kind() != K::IDENTIFIER || word.as_ref().map(SyntaxToken::kind) != Some(K::IDENT) {
        return;
    }
    let name = &source[span(first.text_range()).start..span(first.text_range()).end];
    if name.eq_ignore_ascii_case("search") || catalog.command(name).is_none() {
        return;
    }
    if terms.count() <= MAX_TERMS_AFTER_A_WORD {
        return;
    }
    out.push(
        Diagnostic::error(
            codes::SPL_COMMAND_WITHOUT_PIPE,
            format!(
                "the search starts with the command name `{name}` but no `|`; Splunk searches for the word `{name}` instead of running the command"
            ),
            lines.range(shown(first.text_range())),
        )
        .with_suggestion(format!("| {name}")),
    );
}

// ---------------------------------------------------------------- rejects

/// Forms the grammar shares with valid ones that Splunk's parser rejects:
/// a loose comparison in `tstats ... where`, and `geostats by` with no
/// aggregate.
fn rejects(index: &TreeIndex, lines: &LineIndex<'_>, out: &mut Vec<Diagnostic>) {
    for node in &index.nodes {
        if node.kind() == K::TSTATS_COMMAND
            && let Some(clause) = node.children().find(|n| n.kind() == K::SEARCH_EXPRESSION)
        {
            loose_operators(&clause, lines, out);
        }
        if node.kind() == K::STATS_COMMAND && first_token_text(node) == "geostats" {
            let first = node.children().find(|n| {
                matches!(
                    n.kind(),
                    K::AGGREGATE_ITEM | K::MACRO_CALL | K::COMMAND_OPTION
                ) && n.kind() != K::COMMAND_OPTION
            });
            if let Some(first) = first
                && first.text().to_string().eq_ignore_ascii_case("by")
            {
                out.push(Diagnostic::error(
                    codes::SPL_PARSE_ERROR,
                    "SPL syntax error: `geostats ... by` needs an aggregate before `by` (`geostats count by x`)",
                    lines.range(shown(first.text_range())),
                ));
            }
        }
    }
}

fn loose_operators(node: &SyntaxNode, lines: &LineIndex<'_>, out: &mut Vec<Diagnostic>) {
    for element in node.children_with_tokens() {
        match element {
            NodeOrToken::Node(n) if n.kind() == K::SUBSEARCH => {}
            NodeOrToken::Node(n) => {
                if n.kind() == K::FIELD_VALUE
                    && let Some(op) = n
                        .children_with_tokens()
                        .filter_map(NodeOrToken::into_token)
                        .find(|t| LOOSE_OPERATORS.contains(&t.kind()))
                {
                    out.push(Diagnostic::error(
                        codes::SPL_PARSE_ERROR,
                        format!(
                            "SPL syntax error: `tstats ... where` does not take '{}'; Splunk rejects it (WHERE clause is not an exact query)",
                            op.text()
                        ),
                        lines.range(shown(op.text_range())),
                    ));
                }
                loose_operators(&n, lines, out);
            }
            NodeOrToken::Token(_) => {}
        }
    }
}

// ---------------------------------------------------------------- highlighting

/// The capture of `token` as `highlights.scm` gives it: the first pattern
/// that matches the tree-sitter node of the token, read here from the
/// token's kind and the node around it. `None`: no pattern matches.
fn capture(token: &SyntaxToken) -> Option<&'static str> {
    let kind = token.kind();
    let parent = token.parent()?;
    // Recovery's tokens: what tree-sitter's `(identifier)`, `(number)`, ... say.
    if parent.kind() == K::ERROR {
        match kind {
            K::IDENT if matches!(token.text(), "AND" | "OR" | "NOT") => return Some("operator"),
            K::IDENT | K::FIELD_WORD | K::GLOB_TOKEN | K::SEARCH_WORD_TOKEN | K::CALL_WORD => {
                return Some("variable");
            }
            K::NUMBER_TOKEN => return Some("number"),
            _ => {}
        }
    }
    let grand = parent.parent();
    let parent_kind = parent.kind();
    let grand_kind = grand.as_ref().map(SyntaxNode::kind);
    let first_child = |of: &SyntaxNode| of.children().next().as_ref() == Some(&parent);
    match parent_kind {
        K::IDENTIFIER => {
            let role = grand
                .as_ref()
                .filter(|g| first_child(g))
                .map(SyntaxNode::kind);
            return Some(match role {
                Some(K::FUNCTION_CALL) => "function",
                Some(K::UNKNOWN_COMMAND) => "error",
                // rex's `field=` is a keyword of its own rule, which no pattern names.
                Some(K::COMMAND_OPTION)
                    if grand
                        .as_ref()
                        .and_then(SyntaxNode::parent)
                        .map(|n| n.kind())
                        == Some(K::REX_COMMAND)
                        && token.text() == "field" =>
                {
                    return None;
                }
                Some(K::COMMAND_OPTION | K::COMPARISON) => "property",
                _ if grand_kind == Some(K::FIELD_REF) && in_field_value(grand.as_ref()) => {
                    "property"
                }
                _ => "variable",
            });
        }
        K::SEARCH_WORD => {
            return Some(
                if grand_kind == Some(K::FIELD_REF) && in_field_value(grand.as_ref()) {
                    "property"
                } else {
                    "variable"
                },
            );
        }
        K::GLOB => return Some("variable"),
        K::STR => return Some("string"),
        K::NUMBER => return Some("number"),
        K::BOOLEAN => return Some("boolean"),
        K::MACRO_CALL => return Some("macro"),
        K::TERM_TEXT => return Some("string"),
        K::SEARCH_BOOLEAN => return Some("operator"),
        K::CATALOG_COMMAND_NAME => return Some("keyword"),
        _ => {}
    }
    Some(match kind {
        K::COMMENT => "comment",
        K::MACRO_TOKEN => "macro",
        K::STRING_TOKEN => "string",
        K::PIPE => "operator.pipe",
        K::TERM_KW | K::CASE_KW | K::PREFIX_KW => "function.builtin",
        K::AND_KW
        | K::OR_KW
        | K::NOT_KW
        | K::AND_LOWER_KW
        | K::OR_LOWER_KW
        | K::NOT_LOWER_KW
        | K::IN_KW
        | K::LIKE_KW
        | K::LIKE_LOWER_KW
        | K::LT
        | K::GT
        | K::LE
        | K::GE
        | K::EQ
        | K::EQ2
        | K::NE => "operator",
        K::L_PAREN | K::R_PAREN | K::L_BRACKET | K::R_BRACKET => "punctuation.bracket",
        K::COMMA => "punctuation.delimiter",
        K::DELIM_KW | K::FIELD_KW => return None,
        k if k.is_keyword() => "keyword",
        _ => return None,
    })
}

fn in_field_value(field_ref: Option<&SyntaxNode>) -> bool {
    field_ref
        .and_then(SyntaxNode::parent)
        .is_some_and(|n| n.kind() == K::FIELD_VALUE)
}

fn looks_like_macro(text: &str) -> bool {
    let t = text.trim();
    t.starts_with('`') && t.ends_with('`') && !t.starts_with("```") && t.len() >= 3
}

/// The highlight tokens: each token's capture, then the catalog's
/// refinements, as the tree-sitter path does them.
fn highlight(
    index: &TreeIndex,
    source: &str,
    lines: &LineIndex<'_>,
    spec: &HighlightSpec,
    catalog: &Catalog,
) -> Result<Vec<opentide_highlight::HighlightToken>, opentide_highlight::HighlightError> {
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    for token in &index.all_tokens {
        if token.kind() == K::WHITESPACE || token.text().is_empty() {
            continue;
        }
        let Some(mut capture) = capture(token) else {
            continue;
        };
        let text = token.text();
        if catalog.function(text).is_some() && matches!(capture, "variable" | "function") {
            capture = "function.builtin";
        } else if (matches!(
            text,
            "by" | "AS"
                | "as"
                | "from"
                | "datamodel"
                | "summariesonly"
                | "where"
                | "prestats"
                | "allow_old_summaries"
                | "fillnull_value"
        ) && capture == "variable")
            || (catalog.command(text).is_some() && matches!(capture, "variable" | "error"))
        {
            capture = "keyword";
        } else if looks_like_macro(text) {
            capture = "macro";
        } else if catalog.datamodel(text).is_some() && capture == "variable" {
            capture = "type";
        } else if catalog.field(text).is_some() && capture == "variable" {
            capture = "property";
        }
        spans.push((span(token.text_range()), capture));
    }
    let _ = source;
    tokens_in(spec, lines, &spans)
}

#[cfg(test)]
mod tests {
    use super::analyze;
    use opentide_core::codes;

    #[test]
    fn long_tokens_are_shortened_in_the_message() {
        assert_eq!(super::quoted("abc"), "abc");
        let long = "x".repeat(super::MAX_QUOTED + 5);
        let q = super::quoted(&long);
        assert!(q.ends_with('…'), "{q}");
        assert_eq!(q.chars().count(), super::MAX_QUOTED + 1);
        assert_eq!(super::quoted("a\nb"), "a");
    }

    #[test]
    fn many_broken_stages_stay_linear() {
        // One syntax error per stage: a walk of the tree per error took
        // 16 s for 5,000 stages in a debug build; the old engine 0.1 s.
        let source = "| ( ".repeat(20_000);
        let started = std::time::Instant::now();
        let result = analyze(&source);
        assert!(!result.diagnostics.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn one_diagnostic_per_error_region() {
        let errors: Vec<_> = analyze("a AND OR b")
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_PARSE_ERROR)
            .collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    #[test]
    fn an_unclosed_paren_is_reported_at_the_paren() {
        let errors: Vec<_> = analyze("index=a | where x=(1 | head 1")
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_PARSE_ERROR)
            .collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("'(' is never closed"),
            "{errors:?}"
        );
        assert_eq!(errors[0].range.start.character, 18, "{errors:?}");
    }

    #[test]
    fn no_hint_in_a_broken_stage_after_its_error() {
        let all = analyze("index=* x ) *foo | notacommand y").diagnostics;
        assert!(
            !all.iter().any(|d| d.code == codes::SPL_WILDCARD),
            "a fragment after the error: {all:?}"
        );
        assert!(
            all.iter().any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
            "the next stage is read as written: {all:?}"
        );
        let clean = analyze("index=* *foo | notacommand y").diagnostics;
        assert!(
            clean.iter().any(|d| d.code == codes::SPL_WILDCARD),
            "{clean:?}"
        );
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    /// Searches like the corpus's, written here: an engine crate reads no file
    /// (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        "index=main sourcetype=access_combined status>=500 | stats count by host | where count > 10 | sort - count",
        "index=web [search index=threat | fields src_ip | rename src_ip as clientip] | table _time clientip uri",
        "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest",
        "index=main | geostats by city | mispsearch field=user | stast count | eval",
        "index=main | eval a=\"unclosed [ | stats count | (",
        "search index=a `macro(arg)` | append [| makeresults | eval y=1] | lookup assets ip as src",
    ];

    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        let cut: Vec<String> = SAMPLES
            .iter()
            .flat_map(|t| t.char_indices().map(|(i, _)| t[..i].to_owned()))
            .collect();
        out.extend(cut);
        out
    }

    /// The index's lists are what the walks they replace read: every node in
    /// preorder, every token in order, the significant tokens and the error
    /// nodes (ADR 0014 §5a).
    #[test]
    fn the_index_holds_what_the_walks_read() {
        for source in texts() {
            let (root, _) = parse(&source);
            let index = TreeIndex::new(&root);
            let nodes: Vec<_> = root.descendants().collect();
            assert_eq!(index.nodes, nodes, "{source:?}");
            let tokens: Vec<_> = root
                .descendants_with_tokens()
                .filter_map(NodeOrToken::into_token)
                .collect();
            assert_eq!(index.all_tokens, tokens, "{source:?}");
            let significant: Vec<_> = tokens.into_iter().filter(|t| !trivia(t.kind())).collect();
            assert_eq!(index.tokens, significant, "{source:?}");
            let errors: Vec<_> = root
                .descendants()
                .filter(|n| n.kind() == K::ERROR)
                .collect();
            assert_eq!(index.errors, errors, "{source:?}");
        }
    }

    /// An analysis walks the tree once (ADR 0014 §7): the index, the unknown
    /// commands, the stages, the rejects and the highlight each walked it.
    /// The count is the index's walk; the checks and the highlight take the
    /// index, not the tree, so no other walk of the whole tree is left to
    /// count (`stages` reads the root's children for its pipeline).
    #[test]
    fn an_analysis_visits_each_element_once() {
        for source in [SAMPLES[1], SAMPLES[3]] {
            let (root, _) = parse(source);
            let elements = root.descendants_with_tokens().count();
            let before = visits();
            analyze(source);
            assert_eq!(visits() - before, elements, "{source:?}");
        }
    }
}
