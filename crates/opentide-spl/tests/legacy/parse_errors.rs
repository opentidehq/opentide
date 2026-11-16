//! `spl_parse_error` at the token tree-sitter could not place.
//!
//! Only the generic error API is used (`ERROR` and `MISSING` nodes and the
//! anonymous `(`, `)`, `[`, `]` tokens), never a grammar rule name, so the
//! positions survive grammar rewrites.

use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use opentide_syntax::{node_span, prev_sibling};
use tree_sitter::Node;

/// A badly broken query reports this many error regions, not one per token.
pub(crate) const MAX_PARSE_ERRORS: usize = 5;

/// Longest token text quoted in a message.
const MAX_QUOTED: usize = 32;

pub(crate) fn collect(root: Node, source: &str, out: &mut Vec<Diagnostic>) {
    for region in error_regions(root, MAX_PARSE_ERRORS) {
        let (span, message) = describe(region, source);
        out.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            message,
            span_to_range(source, span),
        ));
    }
}

/// Outermost `ERROR` and `MISSING` nodes in document order, at most `cap`.
/// A region's own nested errors belong to it and are not listed again.
fn error_regions(root: Node, cap: usize) -> Vec<Node> {
    let mut regions = Vec::new();
    if !erroneous(root) {
        return regions;
    }
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        let region = node.is_error() || node.is_missing();
        if region {
            regions.push(node);
            if regions.len() == cap {
                return regions;
            }
        }
        if !region && erroneous(node) && cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return regions;
            }
        }
    }
}

/// Where and what to report for one error region.
fn describe(region: Node, source: &str) -> (ByteSpan, String) {
    let node = innermost(region);
    if node.is_missing() {
        return missing(node);
    }
    let token = first_leaf(node);
    let text = source
        .get(token.start_byte()..token.end_byte())
        .unwrap_or("")
        .trim();
    let message = if text.is_empty() {
        "SPL syntax error".to_string()
    } else {
        format!("SPL syntax error: unexpected '{}'", quoted(text))
    };
    (node_span(token), message)
}

/// The first error inside `region`: a nested `ERROR` or `MISSING` node wins
/// over the region itself, since recovery often wraps valid text around it.
fn innermost(region: Node) -> Node {
    let mut found = region;
    let mut node = region;
    loop {
        if node.is_missing() {
            return node;
        }
        let mut cursor = node.walk();
        let next = node.children(&mut cursor).find(|child| erroneous(*child));
        match next {
            Some(child) => {
                if child.is_error() || child.is_missing() {
                    found = child;
                }
                node = child;
            }
            None => return found,
        }
    }
}

/// A single-token `ERROR` leaf does not report `has_error`, so ask all three.
fn erroneous(node: Node) -> bool {
    node.is_error() || node.is_missing() || node.has_error()
}

fn first_leaf(node: Node) -> Node {
    let mut leaf = node;
    while let Some(child) = leaf.child(0) {
        leaf = child;
    }
    leaf
}

/// A missing closer points at the opener it would close: that is the token to
/// fix, and the place where the closer is missing is often the end of the query.
fn missing(node: Node) -> (ByteSpan, String) {
    let kind = node.kind();
    let opener = match kind {
        ")" => Some("("),
        "]" => Some("["),
        _ => None,
    };
    if let Some(opener) = opener {
        let mut sibling = prev_sibling(node);
        while let Some(s) = sibling {
            if s.kind() == opener && !s.is_missing() {
                return (
                    node_span(s),
                    format!("SPL syntax error: '{opener}' is never closed"),
                );
            }
            sibling = prev_sibling(s);
        }
    }
    (
        node_span(node),
        format!("SPL syntax error: missing '{kind}'"),
    )
}

fn quoted(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    if line.chars().count() <= MAX_QUOTED {
        return line.to_string();
    }
    let cut: String = line.chars().take(MAX_QUOTED).collect();
    format!("{cut}…")
}
