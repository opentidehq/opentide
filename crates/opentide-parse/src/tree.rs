//! [`build`]: events to a lossless rowan green tree and its errors.

use crate::input::offset;
use crate::{ErrorKind, Event, Input, Lexeme, TokenSet};
use rowan::{GreenNode, GreenNodeBuilder, SyntaxKind, TextRange, TextSize};

/// A syntax error of a parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// Who recorded it.
    pub kind: ErrorKind,
    /// The message.
    pub message: String,
    /// The kinds the parser looked for.
    pub expected: TokenSet,
    /// From the end of the last token before the error to the start of the
    /// token after it: the error sits in this gap (its trivia).
    pub gap: TextRange,
    /// The kinds of the nodes open when the grammar recorded it, root first:
    /// the productions it was in. A range cannot tell them at a node's edge
    /// (a closer missing from a call, or a stray token after a whole one);
    /// the order of the parser's events does.
    pub within: Vec<SyntaxKind>,
}

impl SyntaxError {
    /// Where to report the error in a text of `len` bytes: the start of the
    /// token after the gap, or, when that token is the end of the input, the
    /// end of the last token before it. A query that stops too early is
    /// reported right after its last token, not past the blanks, newlines and
    /// comments that follow it (#1431 follow-up: a standalone file's error
    /// sat on the line after its last, a Tide block's after its comment).
    #[must_use]
    pub fn anchor(&self, len: usize) -> TextSize {
        if usize::from(self.gap.end()) >= len {
            self.gap.start()
        } else {
            self.gap.end()
        }
    }
}

/// A green tree and its syntax errors.
#[derive(Clone, Debug)]
pub struct Parse {
    /// The lossless tree: every byte of the source, trivia included.
    pub green: GreenNode,
    /// The errors, in source order.
    pub errors: Vec<SyntaxError>,
    /// How many nodes deep the tree is (the root is 1).
    pub depth: usize,
}

/// The message of the fallback tree's error.
const UNBALANCED: &str =
    "the parser built an unbalanced tree (an engine bug: please report this query)";

/// The deepest tree [`build`] makes, in nodes (the root is 1).
///
/// rowan drops a green tree recursively, a few stack frames per level: on a
/// 1 MB stack (the browser WASM module's) a debug build holds about 10 000
/// levels (measured on aarch64 macOS). [`Parser::enter`](crate::Parser::enter)
/// bounds a grammar's recursion, but a loop that wraps each node in a new one
/// ([`CompletedMarker::precede`](crate::CompletedMarker::precede): a
/// left-associative `a + b + c`) nests the tree without recursing. Past this
/// depth [`build`] opens no more nodes: their tokens go to the node at the
/// limit, with one [`ErrorKind::TreeTooDeep`] diagnostic, so no input can
/// overflow the stack when the tree is dropped. A language keeps chains flat
/// (`a or b or c` as one n-ary node) to stay far below it.
pub const MAX_TREE_DEPTH: usize = 4_096;

/// Replays `events` over `input` into a green tree, iteratively: no
/// recursion, whatever the nesting.
///
/// Trivia before a node goes to its parent, so a node's range starts and
/// ends at a significant token; trivia between a node's tokens stays inside
/// it. Tokens the grammar left unconsumed go into an error node at the end
/// of the root, so the tree is lossless whatever the grammar did.
///
/// # Panics
///
/// In debug builds, when the events do not form one root node (a grammar
/// bug). Release builds return the source as one error node instead, with
/// one diagnostic.
pub fn build(input: &Input<'_>, events: Vec<Event>) -> Parse {
    build_or_fallback(input, events, cfg!(debug_assertions), MAX_TREE_DEPTH)
}

pub(crate) fn build_or_fallback(
    input: &Input<'_>,
    events: Vec<Event>,
    panic_on_bug: bool,
    max_tree_depth: usize,
) -> Parse {
    let mut errors = Vec::new();
    if let Some((green, depth)) = replay(input, events, &mut errors, max_tree_depth) {
        return Parse {
            green,
            errors,
            depth,
        };
    }
    assert!(
        !panic_on_bug,
        "opentide-parse: the events do not form one root node (a Marker completed twice, a token outside the root, or an unclosed node)"
    );
    let mut builder = GreenNodeBuilder::new();
    builder.start_node(input.grammar.error);
    for l in &input.lexemes {
        builder.token(l.kind, input.text(l));
    }
    builder.finish_node();
    errors.push(SyntaxError {
        kind: ErrorKind::Unbalanced,
        message: UNBALANCED.to_owned(),
        expected: TokenSet::EMPTY,
        gap: TextRange::empty(TextSize::from(0)),
        within: Vec::new(),
    });
    Parse {
        green: builder.finish(),
        errors,
        depth: 1,
    }
}

/// The replay; `None` when the events are not one balanced root. Nodes past
/// `max_tree_depth` are not opened ([`MAX_TREE_DEPTH`]).
#[expect(
    clippy::too_many_lines,
    reason = "one loop over the events: each arm keeps the open nodes, their kinds and the depth in step"
)]
fn replay(
    input: &Input<'_>,
    mut events: Vec<Event>,
    errors: &mut Vec<SyntaxError>,
    max_tree_depth: usize,
) -> Option<(GreenNode, usize)> {
    let mut builder = GreenNodeBuilder::new();
    let lexemes = &input.lexemes;
    let mut next = 0usize; // the next lexeme to emit
    // Each open node, and whether the builder opened it (false past the
    // depth limit); `depth` counts the opened ones.
    let mut open: Vec<bool> = Vec::new();
    let (mut depth, mut deepest, mut roots) = (0usize, 0usize, 0usize);
    let mut flattened = false;
    let mut last_end = TextSize::from(0);
    let mut parents = Vec::new();
    // The kinds of the open nodes, root first: an error's `within`.
    let mut kinds: Vec<SyntaxKind> = Vec::new();
    for i in 0..events.len() {
        match std::mem::replace(&mut events[i], Event::Tombstone) {
            Event::Start {
                kind,
                forward_parent,
            } => {
                parents.clear();
                parents.push(kind);
                let (mut at, mut fp) = (i, forward_parent);
                while let Some(distance) = fp {
                    at += distance as usize;
                    fp = match events
                        .get_mut(at)
                        .map(|e| std::mem::replace(e, Event::Tombstone))
                    {
                        Some(Event::Start {
                            kind,
                            forward_parent,
                        }) => {
                            parents.push(kind);
                            forward_parent
                        }
                        _ => None,
                    };
                }
                for &kind in parents.iter().rev() {
                    if open.is_empty() {
                        roots += 1;
                        if roots > 1 {
                            return None;
                        }
                    } else {
                        flush_trivia(&mut builder, input, &mut next);
                    }
                    let opened = depth < max_tree_depth.max(1);
                    if opened {
                        builder.start_node(kind);
                        depth += 1;
                        deepest = deepest.max(depth);
                    } else if !flattened {
                        flattened = true;
                        errors.push(SyntaxError {
                            kind: ErrorKind::TreeTooDeep {
                                limit: u32::try_from(max_tree_depth).unwrap_or(u32::MAX),
                            },
                            message: format!(
                                "the syntax tree nests deeper than {max_tree_depth} nodes"
                            ),
                            expected: TokenSet::EMPTY,
                            gap: gap(input, next, last_end),
                            within: kinds.clone(),
                        });
                    }
                    open.push(opened);
                    kinds.push(kind);
                }
            }
            Event::Finish => {
                let opened = open.pop()?;
                kinds.pop();
                if open.is_empty() {
                    flush_rest(&mut builder, input, &mut next);
                }
                if opened {
                    builder.finish_node();
                    depth -= 1;
                }
            }
            Event::Token { kind } => {
                if open.is_empty() {
                    return None;
                }
                flush_trivia(&mut builder, input, &mut next);
                if let Some(l) = lexemes.get(next) {
                    builder.token(kind, input.text(l));
                    last_end = l.range.end();
                    next += 1;
                }
            }
            Event::Error {
                kind,
                message,
                expected,
            } => {
                errors.push(SyntaxError {
                    kind,
                    message,
                    expected,
                    gap: gap(input, next, last_end),
                    within: kinds.clone(),
                });
            }
            Event::Tombstone => {}
        }
    }
    (open.is_empty() && roots == 1).then(|| (builder.finish(), deepest))
}

/// From the end of the last significant token emitted (`last_end`) to the
/// start of the next one at or after lexeme `next` (or the end of input).
fn gap(input: &Input<'_>, next: usize, last_end: TextSize) -> TextRange {
    let after = input
        .lexemes
        .get(next..)
        .unwrap_or_default()
        .iter()
        .find(|l| !input.grammar.trivia.contains(l.kind))
        .map_or(offset(input.source.len()), |l| l.range.start());
    TextRange::new(last_end, after.max(last_end))
}

fn flush_trivia(builder: &mut GreenNodeBuilder<'_>, input: &Input<'_>, next: &mut usize) {
    while let Some(l) = input.lexemes.get(*next) {
        if !input.grammar.trivia.contains(l.kind) {
            break;
        }
        builder.token(l.kind, input.text(l));
        *next += 1;
    }
}

/// What is left when the root closes: trivia, and tokens the grammar left
/// unconsumed (in an error node, so the tree stays lossless).
fn flush_rest(builder: &mut GreenNodeBuilder<'_>, input: &Input<'_>, next: &mut usize) {
    flush_trivia(builder, input, next);
    let rest: &[Lexeme] = input.lexemes.get(*next..).unwrap_or_default();
    if !rest.is_empty() {
        builder.start_node(input.grammar.error);
        for l in rest {
            builder.token(l.kind, input.text(l));
        }
        builder.finish_node();
        *next = input.lexemes.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Grammar, input::range};
    use rowan::SyntaxKind;

    const WORD: SyntaxKind = SyntaxKind(1);
    const ERROR: SyntaxKind = SyntaxKind(3);
    const ROOT: SyntaxKind = SyntaxKind(4);

    fn input(source: &str) -> Input<'_> {
        let lexemes = (0..source.len())
            .map(|i| Lexeme {
                kind: WORD,
                range: range(i, i + 1),
            })
            .collect();
        let grammar = Grammar {
            eof: SyntaxKind(2),
            error: ERROR,
            trivia: TokenSet::EMPTY,
            max_depth: 8,
        };
        Input::new(source, lexemes, grammar)
    }

    fn start(kind: SyntaxKind) -> Event {
        Event::Start {
            kind,
            forward_parent: None,
        }
    }

    #[test]
    fn an_error_at_the_end_is_anchored_after_the_last_token() {
        let error = |start: u32, end: u32| SyntaxError {
            kind: ErrorKind::Syntax,
            message: String::new(),
            expected: TokenSet::EMPTY,
            gap: TextRange::new(start.into(), end.into()),
            within: Vec::new(),
        };
        // `a ( // c\n`: the gap after `(` runs to the end, past the comment.
        assert_eq!(error(3, 10).anchor(10), TextSize::from(3));
        // No trivia after the last token: the same place either way.
        assert_eq!(error(3, 3).anchor(3), TextSize::from(3));
        // A token follows: the error is at it.
        assert_eq!(error(3, 5).anchor(10), TextSize::from(5));
    }

    #[test]
    fn unbalanced_events_fall_back_to_one_error_node() {
        let input = input("ab");
        let token = Event::Token { kind: WORD };
        for events in [
            vec![],
            vec![token.clone()],
            vec![start(ROOT), token.clone()],
            vec![start(ROOT), Event::Finish, Event::Finish],
            vec![start(ROOT), Event::Finish, start(ROOT), Event::Finish],
        ] {
            let parse = build_or_fallback(&input, events.clone(), false, MAX_TREE_DEPTH);
            assert_eq!(parse.green.kind(), ERROR, "{events:?}");
            assert_eq!(parse.green.to_string(), "ab");
            assert_eq!(parse.errors.len(), 1);
            assert_eq!(parse.errors[0].message, UNBALANCED);
        }
    }

    #[test]
    fn nodes_past_the_tree_depth_limit_are_flattened_with_one_error() {
        // ROOT[a A[b B[c C[D[d]]]]] on a limit of 3: C and D are flattened
        // into B, which keeps their word.
        let input = input("abcd");
        let (a, b, c, d) = (SyntaxKind(5), SyntaxKind(6), SyntaxKind(7), SyntaxKind(8));
        let token = || Event::Token { kind: WORD };
        let mut events = vec![start(ROOT), token(), start(a), token()];
        events.extend([start(b), token(), start(c), start(d), token()]);
        events.extend([Event::Finish, Event::Finish, Event::Finish, Event::Finish]);
        events.push(Event::Finish);
        let parse = build_or_fallback(&input, events, true, 3);
        let tree = rowan::SyntaxNode::<crate::tests::Raw>::new_root(parse.green);
        let tree = crate::debug_tree(&tree, |k| k.0);
        assert_eq!(
            tree,
            "4@0..4\n  1@0..1 \"a\"\n  5@1..4\n    1@1..2 \"b\"\n    6@2..4\n      1@2..3 \"c\"\n      1@3..4 \"d\"\n"
        );
        assert_eq!(parse.depth, 3);
        assert_eq!(parse.errors.len(), 1, "{:?}", parse.errors);
        assert_eq!(parse.errors[0].kind, ErrorKind::TreeTooDeep { limit: 3 });
        assert_eq!(parse.errors[0].gap, range(3, 3));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "do not form one root node")]
    fn unbalanced_events_panic_in_debug_builds() {
        let _ = build(&input("a"), vec![Event::Token { kind: WORD }]);
    }
}
