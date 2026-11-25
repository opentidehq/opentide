//! A query as the analysis reads it: the parser's tree, and each problem the parser reported
//! with the token it stopped at.

use crate::parser;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_core::ByteSpan;

/// What the parser reported.
#[derive(Clone, Debug)]
pub(crate) struct Problem {
    /// Where: the gap before the token it sits at.
    pub(crate) span: ByteSpan,
    /// The token it sits at (empty at the end of the source).
    pub(crate) token: ByteSpan,
    /// What the parser said.
    pub(crate) message: String,
    /// What it expected there, as words (`"`where`, or `(`"`).
    pub(crate) expected: Option<String>,
    /// Whether the toolkit's depth guard said it.
    pub(crate) too_deep: bool,
}

/// A parsed query.
pub(crate) struct Parsed {
    pub(crate) syntax: SyntaxNode,
    pub(crate) problems: Vec<Problem>,
    /// Where each problem's token starts, and where its gap starts, each sorted: a span is
    /// asked about in two binary searches, so that a query with thousands of problems is not
    /// scanned once per node.
    token_starts: Vec<usize>,
    gap_starts: Vec<usize>,
}

impl Parsed {
    /// Whether the parser reported any problem.
    pub(crate) fn has_problems(&self) -> bool {
        !self.token_starts.is_empty() || !self.gap_starts.is_empty()
    }

    /// Whether the parser reported a problem in `at`, or right after it.
    pub(crate) fn broken(&self, at: ByteSpan) -> bool {
        // A token starting in `start..end`, or a gap starting in `start + 1..=end`.
        let token = self.token_starts.partition_point(|&s| {
            crate::step();
            s < at.start
        });
        let gap = self.gap_starts.partition_point(|&s| {
            crate::step();
            s <= at.start
        });
        self.token_starts.get(token).is_some_and(|&s| s < at.end)
            || self.gap_starts.get(gap).is_some_and(|&s| s <= at.end)
    }
}

/// Parses `source`.
pub(crate) fn parse(source: &str) -> Parsed {
    let parse = parser::parse(source);
    let syntax = SyntaxNode::new_root(parse.green);
    // Every token's range, in order: each problem's token is found by a binary search, not by
    // rowan's `token_at_offset`, which scans a node's children (a call with 20,000 empty
    // arguments has as many problems).
    let tokens: Vec<(usize, usize)> = if parse.errors.is_empty() {
        Vec::new()
    } else {
        syntax
            .descendants_with_tokens()
            .filter_map(rowan::NodeOrToken::into_token)
            .map(|t| {
                let r = t.text_range();
                (usize::from(r.start()), usize::from(r.end()))
            })
            .collect()
    };
    let problems: Vec<Problem> = parse
        .errors
        .iter()
        .map(|e| {
            let at = usize::from(e.anchor(source.len()));
            // At the end of the input the error is the empty span there.
            let at_end = usize::from(e.gap.end()) >= source.len();
            // The token that starts at the gap's end, the first non-empty one.
            let first = tokens.partition_point(|&(start, _)| {
                crate::step();
                start < at
            });
            let end = tokens[first..]
                .iter()
                .take_while(|&&(start, _)| start == at)
                .map(|&(_, end)| end)
                .find(|&end| end > at && !at_end)
                .unwrap_or(at);
            Problem {
                span: ByteSpan::new(usize::from(e.gap.start()), at),
                token: ByteSpan::new(at, end),
                message: e.message.clone(),
                expected: expected_list(e.expected),
                too_deep: matches!(
                    e.kind,
                    opentide_parse::ErrorKind::TooDeep { .. }
                        | opentide_parse::ErrorKind::TreeTooDeep { .. }
                ),
            }
        })
        .collect();
    let mut token_starts: Vec<usize> = problems.iter().map(|p: &Problem| p.token.start).collect();
    let mut gap_starts: Vec<usize> = problems.iter().map(|p: &Problem| p.span.start).collect();
    token_starts.sort_unstable();
    gap_starts.sort_unstable();
    Parsed {
        syntax,
        problems,
        token_starts,
        gap_starts,
    }
}

/// The kinds that start an expression: where the parser expected all of them, the message says
/// "an expression" once, not each of them (`a name, a function, a number, …, \`(\`, or \`?\``).
const EXPRESSION_START: [K; 12] = [
    K::WORD,
    K::TILDE_WORD,
    K::NUMBER_TOKEN,
    K::STRING_TOKEN,
    K::QUOTED_IDENT_TOKEN,
    K::FALSE_KW,
    K::NULL_KW,
    K::TRUE_KW,
    K::PLUS,
    K::MINUS,
    K::L_PAREN,
    K::QUESTION,
];

/// What a syntax error says the parser expected, as one phrase. Operators are named by their
/// class with an example, as KQL names "a comparison operator" (a list ran to 27 items); where
/// an expression could start, "an expression" stands for its first tokens.
///
/// `+` and `-` are signs where an expression starts, and the grammar records them there only
/// with every other first token (`expr_bp`): so a set holding them without `WORD` is an
/// operator position, and "an arithmetic operator" is right. The tests pin both cases.
pub(crate) fn expected_list(expected: opentide_parse::TokenSet) -> Option<String> {
    let expression = EXPRESSION_START
        .iter()
        .all(|&k| expected.contains(rowan::SyntaxKind(k as u16)));
    opentide_parse::describe_expected(expected, |raw| {
        let kind = K::from_raw(raw);
        if expression && EXPRESSION_START.contains(&kind) {
            // Named once, by the first kind of the set (`WORD` comes first).
            return if kind == K::WORD { "an expression" } else { "" };
        }
        match kind {
            K::EQ_EQ | K::NOT_EQ | K::LT | K::LT_EQ | K::GT | K::GT_EQ => {
                "a comparison operator such as `==`"
            }
            K::PLUS | K::MINUS | K::STAR | K::SLASH | K::PERCENT => {
                "an arithmetic operator such as `+`"
            }
            K::IN_KW
            | K::IN_TILDE
            | K::COLON
            | K::LIKE_KW
            | K::LIKE_TILDE
            | K::REGEX_KW
            | K::REGEX_TILDE => "a match operator such as `in`",
            other => other.describe(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(query: &str) -> String {
        parse(query)
            .problems
            .first()
            .and_then(|p| p.expected.clone())
            .unwrap_or_default()
    }

    #[test]
    fn operators_are_named_by_class() {
        assert_eq!(
            message("process where a b"),
            "an index, `and`, a match operator such as `in`, `not`, `or`, `|`, a comparison \
             operator such as `==`, an arithmetic operator such as `+`, or `.`"
        );
    }

    #[test]
    fn where_an_expression_starts_it_is_one_item() {
        assert_eq!(message("process where a == "), "an expression");
        assert_eq!(message("process where "), "an expression or `not`");
        assert_eq!(message("process where f("), "an expression, `not`, or `)`");
    }

    #[test]
    fn a_partial_set_keeps_its_kinds() {
        // After `:` only constants: no expression, so each is named.
        assert_eq!(
            message("process where a : "),
            "a number, a string, `false`, `null`, `true`, or `(`"
        );
        assert_eq!(message("process where a == 1 | "), "a name");
        assert_eq!(message("any where a.b."), "a name or a quoted name");
    }

    #[test]
    fn a_partial_class_is_named_by_its_class() {
        // After `a + b` the loop records `*`, `/`, `%` (one level up), not `+`, `-`: the
        // class still stands, as `+` is valid there too.
        assert!(
            message("process where a + b c").contains("an arithmetic operator such as `+`"),
            "{}",
            message("process where a + b c")
        );
        // A comparison is not associative: after `1 == 1` the comparison class is gone.
        assert_eq!(
            message("process where 1 == 1 == "),
            "`and`, a match operator such as `in`, `not`, `or`, `|`, or an arithmetic \
             operator such as `+`"
        );
    }
}
