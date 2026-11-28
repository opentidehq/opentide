//! Highlight tokens from the tree: the HighlightSpec capture of each token, as the
//! tree-sitter query `highlights/queries/cql/highlights.scm` gave them. Every capture of that
//! query was one token wide, so the first pattern that matched a token is a match on the
//! token's kind and on the node that holds it, in the query's order.

use crate::catalog::Catalog;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::ByteSpan;
use opentide_highlight::{Capture, HighlightSpec, HighlightToken, tokens_from_spans};

/// The highlight tokens of a tree. A call to a catalogued function is
/// `function.builtin`; any other call (a newer function) stays `function`.
#[cfg(test)]
pub(crate) fn tokens(spec: &HighlightSpec, root: &SyntaxNode, source: &str) -> Vec<HighlightToken> {
    let spans: Vec<(ByteSpan, &str)> = root
        .descendants_with_tokens()
        .inspect(|_| crate::check::count_visit())
        .filter_map(rowan::NodeOrToken::into_token)
        .filter_map(|t| span(&t, source))
        .collect();
    from_spans(spec, source, &spans)
}

/// The span and capture of one token, if it has one: what `tokens` reads
/// of each, for a walk that meets the tokens itself (ADR 0014 §5a).
pub(crate) fn span(token: &SyntaxToken, source: &str) -> Option<(ByteSpan, &'static str)> {
    let range = token.text_range();
    let span = ByteSpan::new(usize::from(range.start()), usize::from(range.end()));
    let mut c = capture(token, source)?;
    if c == Capture::FUNCTION
        && Catalog::cached()
            .function(source.get(span.start..span.end).unwrap_or(""))
            .is_some_and(|f| !f.removed)
    {
        c = Capture::FUNCTION_BUILTIN;
    }
    (!range.is_empty()).then_some((span, c.name()))
}

/// The highlight tokens of the spans, in document order.
pub(crate) fn from_spans(
    spec: &HighlightSpec,
    source: &str,
    spans: &[(ByteSpan, &str)],
) -> Vec<HighlightToken> {
    tokens_from_spans(spec, source, spans).unwrap_or_default()
}

/// Whether `node` is the `n`th child node of its parent, and the parent is `parent`.
fn is_child(node: &SyntaxNode, parent: K, n: usize) -> bool {
    node.parent()
        .is_some_and(|p| p.kind() == parent && p.children().nth(n).as_ref() == Some(node))
}

/// The field of a filter, an assignment, a shorthand or a `match` (its first child).
fn is_field(node: &SyntaxNode) -> bool {
    [
        K::FIELD_FILTER,
        K::ASSIGNMENT,
        K::FIELD_SHORTHAND,
        K::MATCH_STATEMENT,
    ]
    .into_iter()
    .any(|p| is_child(node, p, 0))
}

/// The name of a named argument or a saved query's argument (its first child).
fn is_argument_name(node: &SyntaxNode) -> bool {
    is_child(node, K::NAMED_ARGUMENT, 0) || is_child(node, K::SAVED_QUERY_ARGUMENT, 0)
}

/// The capture of a token: its own kind for the punctuation, the node that wraps it for
/// a word, a literal or a name.
fn capture(token: &SyntaxToken, source: &str) -> Option<Capture> {
    let parent = token.parent()?;
    let in_node = |k: K| parent.kind() == k;
    Some(match token.kind() {
        K::LINE_COMMENT | K::BLOCK_COMMENT => Capture::COMMENT,
        K::DOLLAR if in_node(K::SAVED_QUERY) => Capture::MACRO,
        K::QUESTION | K::QUESTION_L_BRACE if in_node(K::QUERY_PARAMETER) => Capture::MACRO,
        K::SLASH if in_node(K::REGEX) => Capture::STRING,
        K::AND_KW | K::OR_KW | K::NOT_KW | K::CASE_KW | K::MATCH_KW | K::LIKE_KW => {
            Capture::KEYWORD
        }
        K::PIPE => Capture::PIPE,
        K::EQ
        | K::NOT_EQ
        | K::LT
        | K::LT_EQ
        | K::GT
        | K::GT_EQ
        | K::EQ_EQ
        | K::LT_EQ_GT
        | K::COLON_EQ
        | K::EQ_TILDE
        | K::FAT_ARROW
        | K::BANG
        | K::PLUS
        | K::MINUS
        | K::STAR
        | K::SLASH
        | K::PERCENT => Capture::OPERATOR,
        K::L_PAREN | K::R_PAREN | K::L_BRACK | K::R_BRACK | K::L_BRACE | K::R_BRACE => {
            Capture::BRACKET
        }
        K::COMMA | K::SEMI | K::COLON => Capture::DELIMITER,
        _ => node_capture(&parent, source)?,
    })
}

/// The capture of the one-token node `node` (a name or a literal). Its text is a slice of
/// `source`, read only where the capture depends on it: a token's parent can be a node as
/// large as the query (whitespace in a deep `case`), and copying its text for each token
/// was quadratic in the nesting.
fn node_capture(node: &SyntaxNode, source: &str) -> Option<Capture> {
    let text = || crate::text(node, source);
    Some(match node.kind() {
        K::SAVED_QUERY_NAME => Capture::MACRO,
        K::STRING if is_child(node, K::SAVED_QUERY, 0) => Capture::MACRO,
        K::PARAMETER_NAME => Capture::MACRO,
        K::STRING if is_child(node, K::QUERY_PARAMETER, 0) => Capture::MACRO,
        K::FUNCTION_NAME => Capture::FUNCTION,
        K::TAG => Capture::TYPE,
        K::FIELD_NAME | K::STRING if is_field(node) => Capture::PROPERTY,
        K::FIELD_NAME
            if node
                .parent()
                .is_some_and(|p| p.kind() == K::LINK_CONSTRAINT) =>
        {
            Capture::PROPERTY
        }
        K::ARGUMENT_NAME | K::STRING if is_argument_name(node) => Capture::VARIABLE,
        K::IDENTIFIER => Capture::VARIABLE,
        K::FIELD_NAME if is_duration(text()) => Capture::NUMBER,
        K::FIELD_NAME => Capture::PROPERTY,
        K::REGEX_PATTERN => Capture::STRING,
        K::REGEX_FLAGS => Capture::CONSTANT,
        K::UNQUOTED_PATTERN if is_number(text()) => Capture::NUMBER,
        K::UNQUOTED_PATTERN | K::STRING => Capture::STRING,
        K::NUMBER => Capture::NUMBER,
        K::BOOLEAN => Capture::BOOLEAN,
        K::AND | K::OR | K::NOT => Capture::KEYWORD,
        _ => return None,
    })
}

/// `^-?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$`.
fn is_number(text: &str) -> bool {
    let s = text.strip_prefix('-').unwrap_or(text);
    let Some(mut rest) = after_digits(s) else {
        return false;
    };
    if let Some(r) = rest.strip_prefix('.') {
        let Some(r) = after_digits(r) else {
            return false;
        };
        rest = r;
    }
    if let Some(r) = rest.strip_prefix(['e', 'E']) {
        let r = r.strip_prefix(['+', '-']).unwrap_or(r);
        let Some(r) = after_digits(r) else {
            return false;
        };
        rest = r;
    }
    rest.is_empty()
}

/// What follows the ASCII digits `s` starts with, when it starts with one.
fn after_digits(s: &str) -> Option<&str> {
    let rest = s.trim_start_matches(|c: char| c.is_ascii_digit());
    (rest.len() < s.len()).then_some(rest)
}

/// A bareword duration such as `5min`: digits, then one of LogScale's time units.
fn is_duration(text: &str) -> bool {
    const UNITS: &[&str] = &[
        "ms",
        "millis",
        "millisecond",
        "milliseconds",
        "s",
        "sec",
        "secs",
        "second",
        "seconds",
        "m",
        "min",
        "mins",
        "minute",
        "minutes",
        "h",
        "hr",
        "hrs",
        "hour",
        "hours",
        "d",
        "day",
        "days",
        "w",
        "week",
        "weeks",
        "mon",
        "month",
        "months",
        "q",
        "qtr",
        "qtrs",
        "quarter",
        "quarters",
        "y",
        "yr",
        "yrs",
        "year",
        "years",
    ];
    after_digits(text).is_some_and(|unit| UNITS.contains(&unit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_durations_read_as_the_query_did() {
        for yes in ["1", "-1", "1.5", "1e5", "1.5E-3", "007"] {
            assert!(is_number(yes), "{yes}");
        }
        for no in ["", "-", "1.", ".5", "1e", "1x", "--1", "+1"] {
            assert!(!is_number(no), "{no}");
        }
        for yes in ["5min", "1h", "30s", "2weeks", "1millisecond", "3qtrs"] {
            assert!(is_duration(yes), "{yes}");
        }
        for no in ["min", "5", "5minutesx", "5 min", "5M"] {
            assert!(!is_duration(no), "{no}");
        }
        for no in ["é", "1é", "1.é", "1e😀", "😀1", "5é😀", "é5min"] {
            assert!(!is_number(no) && !is_duration(no), "{no}");
        }
    }
}
