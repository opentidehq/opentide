//! Spans and text of the rowan tree as the analysis reports them: a node spans its first to its
//! last visible token (whitespace and comments around it are not part of it), and a node that
//! stands for one token spans that token. Found by walking the first or the last children down,
//! never by recursion.

use crate::highlight::is_leaf;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_core::ByteSpan;
use rowan::{NodeOrToken, TextRange};

/// A child the analysis sees: a node, or a token that is not trivia.
fn visible(element: &rowan::SyntaxElement<crate::syntax::Lang>) -> bool {
    match element {
        NodeOrToken::Node(_) => true,
        NodeOrToken::Token(t) => !t.kind().is_trivia(),
    }
}

/// The range of a node's own first token that is not trivia, else its whole range.
fn own_token_range(node: &SyntaxNode) -> TextRange {
    node.children_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .find(|t| !t.kind().is_trivia())
        .map_or_else(|| node.text_range(), |t| t.text_range())
}

/// Where the first (`first`) or the last visible child of `node`, and so on down, starts or ends.
fn edge(node: &SyntaxNode, first: bool) -> usize {
    let mut node = node.clone();
    loop {
        if is_leaf(node.kind()) {
            let r = own_token_range(&node);
            return usize::from(if first { r.start() } else { r.end() });
        }
        // The last child is found from the end: a run's node can hold thousands of children.
        let child = if first {
            node.children_with_tokens().find(visible)
        } else {
            std::iter::successors(node.last_child_or_token(), |c| c.prev_sibling_or_token())
                .find(visible)
        };
        match child {
            Some(NodeOrToken::Node(child)) => node = child,
            Some(NodeOrToken::Token(token)) => {
                let r = token.text_range();
                return usize::from(if first { r.start() } else { r.end() });
            }
            None => {
                let r = own_token_range(&node);
                return usize::from(if first { r.start() } else { r.end() });
            }
        }
    }
}

/// The span of `node`.
pub(crate) fn span(node: &SyntaxNode) -> ByteSpan {
    if node.kind() == K::SOURCE_FILE {
        return ByteSpan::new(0, usize::from(node.text_range().end()));
    }
    ByteSpan::new(edge(node, true), edge(node, false))
}

/// The text of `node`'s span.
pub(crate) fn text<'a>(node: &SyntaxNode, source: &'a str) -> &'a str {
    let s = span(node);
    source.get(s.start..s.end).unwrap_or("")
}

/// The span of `node`'s first visible child (a keyword, most often).
pub(crate) fn first_child_span(node: &SyntaxNode) -> ByteSpan {
    match node.children_with_tokens().find(visible) {
        Some(NodeOrToken::Node(child)) => span(&child),
        Some(NodeOrToken::Token(token)) => {
            let r = token.text_range();
            ByteSpan::new(usize::from(r.start()), usize::from(r.end()))
        }
        None => span(node),
    }
}

/// What stands at byte `offset`, for hover: the text of the deepest node or token whose span
/// holds it (a node standing for one token as a whole), and the kind of the node it stands in.
/// Each level takes the first visible child that starts at or before `offset` and ends after
/// it; between children, the node itself.
pub(crate) fn element_at<'a>(
    root: &SyntaxNode,
    offset: usize,
    source: &'a str,
) -> (&'a str, Option<K>) {
    let mut node = root.clone();
    loop {
        if node != *root && is_leaf(node.kind()) {
            return (text(&node, source), node.parent().map(|p| p.kind()));
        }
        let mut next = None;
        for child in node.children_with_tokens() {
            // A span lies in its element's range: only an element whose range holds `offset`
            // needs its span, a walk down its edges.
            let whole = child.text_range();
            if usize::from(whole.end()) <= offset {
                continue;
            }
            if offset < usize::from(whole.start()) {
                break;
            }
            let range = match &child {
                NodeOrToken::Node(n) => span(n),
                NodeOrToken::Token(t) if t.kind() != K::WHITESPACE => {
                    let r = t.text_range();
                    ByteSpan::new(usize::from(r.start()), usize::from(r.end()))
                }
                NodeOrToken::Token(_) => continue,
            };
            if range.end <= offset {
                continue;
            }
            if offset < range.start {
                break;
            }
            next = Some((child, range));
            break;
        }
        match next {
            Some((NodeOrToken::Node(child), _)) => node = child,
            Some((NodeOrToken::Token(_), range)) => {
                return (
                    source.get(range.start..range.end).unwrap_or(""),
                    Some(node.kind()),
                );
            }
            None => return (text(&node, source), node.parent().map(|p| p.kind())),
        }
    }
}
