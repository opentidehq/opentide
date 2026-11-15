//! [`build`]: events to a lossless rowan green tree and its errors.

use crate::input::offset;
use crate::{ErrorKind, Event, Input, Lexeme, TokenSet};
use rowan::{GreenNode, GreenNodeBuilder, TextRange, TextSize};

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
    build_or_fallback(input, events, cfg!(debug_assertions))
}

pub(crate) fn build_or_fallback(
    input: &Input<'_>,
    events: Vec<Event>,
    panic_on_bug: bool,
) -> Parse {
    let mut errors = Vec::new();
    if let Some((green, depth)) = replay(input, events, &mut errors) {
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
    });
    Parse {
        green: builder.finish(),
        errors,
        depth: 1,
    }
}

/// The replay; `None` when the events are not one balanced root.
fn replay(
    input: &Input<'_>,
    mut events: Vec<Event>,
    errors: &mut Vec<SyntaxError>,
) -> Option<(GreenNode, usize)> {
    let mut builder = GreenNodeBuilder::new();
    let lexemes = &input.lexemes;
    let mut next = 0usize; // the next lexeme to emit
    let (mut depth, mut deepest, mut roots) = (0usize, 0usize, 0usize);
    let mut last_end = TextSize::from(0);
    let mut parents = Vec::new();
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
                    if depth == 0 {
                        roots += 1;
                        if roots > 1 {
                            return None;
                        }
                    } else {
                        flush_trivia(&mut builder, input, &mut next);
                    }
                    builder.start_node(kind);
                    depth += 1;
                    deepest = deepest.max(depth);
                }
            }
            Event::Finish => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    flush_rest(&mut builder, input, &mut next);
                }
                builder.finish_node();
            }
            Event::Token { kind } => {
                if depth == 0 {
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
                let after = lexemes
                    .get(next..)
                    .unwrap_or_default()
                    .iter()
                    .find(|l| !input.grammar.trivia.contains(l.kind))
                    .map_or(offset(input.source.len()), |l| l.range.start());
                errors.push(SyntaxError {
                    kind,
                    message,
                    expected,
                    gap: TextRange::new(last_end, after.max(last_end)),
                });
            }
            Event::Tombstone => {}
        }
    }
    (depth == 0 && roots == 1).then(|| (builder.finish(), deepest))
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
            let parse = build_or_fallback(&input, events.clone(), false);
            assert_eq!(parse.green.kind(), ERROR, "{events:?}");
            assert_eq!(parse.green.to_string(), "ab");
            assert_eq!(parse.errors.len(), 1);
            assert_eq!(parse.errors[0].message, UNBALANCED);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "do not form one root node")]
    fn unbalanced_events_panic_in_debug_builds() {
        let _ = build(&input("a"), vec![Event::Token { kind: WORD }]);
    }
}
