//! Reading the tree: spans, parentheses, literals and field paths, the few
//! questions the checks ask of a node that the typed AST does not answer.

use crate::ast::{BareField, UdmField};
use crate::catalog::Segment;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_parse::ast::AstNode;

/// A byte range of the source.
pub(crate) type At = (usize, usize);

/// The range of a node, at least one byte long (a finding is never empty).
pub(crate) fn at(node: &SyntaxNode) -> At {
    let r = node.text_range();
    let start = usize::from(r.start());
    (start, usize::from(r.end()).max(start + 1))
}

/// The range of a token, at least one byte long.
pub(crate) fn at_token(token: &SyntaxToken) -> At {
    let r = token.text_range();
    let start = usize::from(r.start());
    (start, usize::from(r.end()).max(start + 1))
}

/// The exact range of a token.
pub(crate) fn exact(token: &SyntaxToken) -> At {
    let r = token.text_range();
    (usize::from(r.start()), usize::from(r.end()))
}

/// `node` without the parentheses around it.
pub(crate) fn unparen(mut node: SyntaxNode) -> SyntaxNode {
    while node.kind() == K::PAREN_EXPR {
        match node.children().next() {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

/// The kind of the one token of a literal node (`STRING`, `INTEGER`, ...).
pub(crate) fn literal_kind(node: &SyntaxNode) -> Option<K> {
    if node.kind() != K::LITERAL {
        return None;
    }
    node.first_token().map(|t| t.kind())
}

/// Whether `node` is a literal of kind `kind`.
pub(crate) fn is_literal(node: &SyntaxNode, kind: K) -> bool {
    literal_kind(node) == Some(kind)
}

/// Whether `node` is a string or a back-quoted string.
pub(crate) fn is_string(node: &SyntaxNode) -> bool {
    matches!(literal_kind(node), Some(K::STRING | K::RAW_STRING))
}

/// The text of a string or raw string literal, decoded.
pub(crate) fn literal_text(node: &SyntaxNode) -> Option<String> {
    let token = node.first_token()?;
    decode(token.kind(), token.text())
}

/// The text of a string (`STRING`) or back-quoted string (`RAW_STRING`) token.
pub(crate) fn decode(kind: K, raw: &str) -> Option<String> {
    let inner = raw.get(1..raw.len().saturating_sub(1))?;
    match kind {
        K::RAW_STRING => Some(inner.to_string()),
        K::STRING => {
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c != '\\' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => out.push('\\'),
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// The segments of the accessors after a variable, or after a bare path's
/// root (which is not included).
pub(crate) fn accessor_segments(field: &SyntaxNode) -> Vec<Segment> {
    let mut out = Vec::new();
    for child in field.children() {
        match child.kind() {
            K::MEMBER => {
                if let Some(name) = child
                    .children_with_tokens()
                    .find_map(|e| e.into_token().filter(|t| t.kind() == K::FIELD_NAME))
                {
                    out.push(Segment::Name(name.text().to_owned(), exact(&name)));
                }
            }
            K::INDEX => {
                let integer = child
                    .children_with_tokens()
                    .filter_map(|e| e.into_token())
                    .any(|t| t.kind() == K::INTEGER);
                if integer {
                    out.push(Segment::Position(at(&child)));
                } else {
                    out.push(Segment::Key(at(&child)));
                }
            }
            _ => {}
        }
    }
    out
}

/// The segments of a field path as the UDM catalogue resolves it: a bare
/// path's root is its first segment.
pub(crate) fn field_segments(field: &SyntaxNode) -> Vec<Segment> {
    let mut segs = Vec::new();
    if let Some(bare) = BareField::cast(field.clone())
        && let Some(root) = bare.root()
    {
        segs.push(Segment::Name(root.text().to_owned(), exact(&root)));
    }
    segs.extend(accessor_segments(field));
    segs
}

/// The variable at the root of a `UdmField`.
pub(crate) fn root_variable(field: &SyntaxNode) -> Option<SyntaxNode> {
    UdmField::cast(field.clone())
        .and_then(|f| f.variable())
        .map(|v| v.syntax().clone())
}

/// The name a variable or count reference stands for: `$e` for `$e` and `#e`.
pub(crate) fn dollar_name(text: &str) -> String {
    format!("${}", text.get(1..).unwrap_or(""))
}
