//! Text renderings for snapshot tests and messages.

use crate::{SyntaxError, TokenSet};
use rowan::{NodeOrToken, SyntaxKind, WalkEvent};
use std::fmt::{Display, Write as _};

/// Whether `parse` reported an error, and the `Debug` names of its tree's
/// kinds, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads of every language (`debug_kinds` in each query
/// crate). Iterative, so any depth is read.
#[must_use]
pub fn debug_kinds<L: rowan::Language>(parse: &crate::Parse) -> (bool, Vec<String>)
where
    L::Kind: std::fmt::Debug,
{
    let root = rowan::SyntaxNode::<L>::new_root(parse.green.clone());
    let kinds = root
        .descendants_with_tokens()
        .map(|e| format!("{:?}", e.kind()))
        .collect();
    (!parse.errors.is_empty(), kinds)
}

/// For each syntax error of `parse`, the `Debug` names of the nodes and
/// tokens whose range touches it: every one that holds the gap the error sits
/// in, or ends or starts at it (a closer missing at a node's end, the token after it). What
/// the corpus gate of `opentide-analysis` reads to check that an invalid
/// fixture fails inside the production it names. Iterative.
#[must_use]
pub fn debug_error_kinds<L: rowan::Language>(parse: &crate::Parse) -> Vec<Vec<String>>
where
    L::Kind: std::fmt::Debug,
{
    let root = rowan::SyntaxNode::<L>::new_root(parse.green.clone());
    parse
        .errors
        .iter()
        .map(|e| {
            root.descendants_with_tokens()
                .filter(|n| {
                    let r = n.text_range();
                    r.start() <= e.gap.end() && e.gap.start() <= r.end()
                })
                .map(|n| format!("{:?}", n.kind()))
                .collect()
        })
        .collect()
}

/// A tree as indented text, one element per line (`KIND@start..end`, and a
/// token's text), for insta snapshots. `name` spells a kind. Iterative, so
/// any depth renders.
pub fn debug_tree<L: rowan::Language, D: Display>(
    root: &rowan::SyntaxNode<L>,
    name: impl Fn(L::Kind) -> D,
) -> String {
    let mut out = String::new();
    let mut indent = 0usize;
    for event in root.preorder_with_tokens() {
        match event {
            WalkEvent::Enter(element) => {
                let r = element.text_range();
                let _ = write!(
                    out,
                    "{:indent$}{}@{}..{}",
                    "",
                    name(element.kind()),
                    u32::from(r.start()),
                    u32::from(r.end())
                );
                match &element {
                    NodeOrToken::Token(t) => {
                        let _ = write!(out, " {:?}", t.text());
                    }
                    NodeOrToken::Node(_) => indent += 2,
                }
                out.push('\n');
            }
            WalkEvent::Leave(NodeOrToken::Node(_)) => indent = indent.saturating_sub(2),
            WalkEvent::Leave(NodeOrToken::Token(_)) => {}
        }
    }
    out
}

/// Errors as text, one per line (`start..end: message (expected A, B)`), for
/// insta snapshots beside [`debug_tree`]. `name` spells a kind.
pub fn debug_errors<D: Display>(errors: &[SyntaxError], name: impl Fn(SyntaxKind) -> D) -> String {
    let mut out = String::new();
    for e in errors {
        let _ = write!(
            out,
            "{}..{}: {}",
            u32::from(e.gap.start()),
            u32::from(e.gap.end()),
            e.message
        );
        if !e.expected.is_empty() {
            let names: Vec<String> = e.expected.iter().map(|k| name(k).to_string()).collect();
            let _ = write!(out, " (expected {})", names.join(", "));
        }
        out.push('\n');
    }
    out
}

/// What a message says the parser expected: each kind of `expected`, in
/// kind order, spelled by `describe` (`""` leaves a kind out), each spelling
/// once, joined as "a", "a or b", "a, b, or c". `None` when nothing is left.
///
/// For "near `)`; expected `or`, `and`, or end of input".
pub fn describe_expected<'a>(
    expected: TokenSet,
    describe: impl Fn(SyntaxKind) -> &'a str,
) -> Option<String> {
    let mut names: Vec<&str> = Vec::new();
    for name in expected.iter().map(describe) {
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    let (last, rest) = names.split_last()?;
    Some(match rest {
        [] => (*last).to_owned(),
        [one] => format!("{one} or {last}"),
        _ => format!("{}, or {last}", rest.join(", ")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn describe(k: SyntaxKind) -> &'static str {
        match k.0 {
            1 => "`or`",
            2 => "`and`",
            3 | 4 => "a value",
            5 => "end of input",
            _ => "",
        }
    }

    #[test]
    fn expected_kinds_read_as_one_phrase() {
        let set = |kinds: &[u16]| {
            kinds
                .iter()
                .fold(TokenSet::EMPTY, |s, &k| s.with(SyntaxKind(k)))
        };
        assert_eq!(describe_expected(set(&[]), describe), None);
        assert_eq!(describe_expected(set(&[0, 9]), describe), None);
        assert_eq!(
            describe_expected(set(&[2]), describe).as_deref(),
            Some("`and`")
        );
        assert_eq!(
            describe_expected(set(&[3, 4]), describe).as_deref(),
            Some("a value")
        );
        assert_eq!(
            describe_expected(set(&[5, 1]), describe).as_deref(),
            Some("`or` or end of input"),
            "two items take no comma"
        );
        assert_eq!(
            describe_expected(set(&[1, 2, 5]), describe).as_deref(),
            Some("`or`, `and`, or end of input")
        );
        assert_eq!(
            describe_expected(set(&[1, 2, 3, 4, 5, 0]), describe).as_deref(),
            Some("`or`, `and`, a value, or end of input")
        );
    }
}
