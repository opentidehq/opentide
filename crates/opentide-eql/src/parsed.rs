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
                expected: opentide_parse::describe_expected(e.expected, |k| {
                    K::from_raw(k).describe()
                }),
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
