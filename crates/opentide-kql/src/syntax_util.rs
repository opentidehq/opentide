//! Reading the new tree: spans without trivia, names, the plain forms of
//! expressions, and the node names the tree-sitter grammar gave each kind
//! (messages and the HIR name operators by them).

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::ByteSpan;
use rowan::{NodeOrToken, TextRange};

/// Whether a token is whitespace or a comment.
pub(crate) fn is_trivia(token: &SyntaxToken) -> bool {
    matches!(token.kind(), K::WHITESPACE | K::COMMENT)
}

/// A node's range without the trivia at its ends (what tree-sitter spanned):
/// from its first significant token to its last; empty at its start when it
/// has none.
pub(crate) fn range(node: &SyntaxNode) -> TextRange {
    // From each end inward past the trivia only: walking every token of the
    // node to find its last was most of the column pass on a long query,
    // and `range` is asked of most nodes. rowan's token steps stop at an
    // empty node (as broken input leaves), so a walk that runs out without
    // a significant token, or a node of trivia only, takes the long way.
    let inside = |t: &SyntaxToken| t.parent_ancestors().any(|a| a == *node);
    let significant = |mut at: Option<SyntaxToken>, forward: bool| {
        while let Some(t) = at {
            if !inside(&t) {
                return None;
            }
            if !is_trivia(&t) {
                return Some(t);
            }
            at = if forward {
                t.next_token()
            } else {
                t.prev_token()
            };
        }
        None
    };
    match (
        significant(node.first_token(), true),
        significant(node.last_token(), false),
    ) {
        (Some(first), Some(last)) => {
            TextRange::new(first.text_range().start(), last.text_range().end())
        }
        _ => range_by_walking(node),
    }
}

/// [`range`] by walking every token of the node, in order: what [`range`]
/// falls back to, and what the tests hold it to.
pub(crate) fn range_by_walking(node: &SyntaxNode) -> TextRange {
    let mut tokens = node
        .descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| !is_trivia(t));
    let Some(first) = tokens.next() else {
        return TextRange::empty(node.text_range().start());
    };
    let last = tokens.last().unwrap_or_else(|| first.clone());
    TextRange::new(first.text_range().start(), last.text_range().end())
}

/// [`range`] as a [`ByteSpan`].
pub(crate) fn span(node: &SyntaxNode) -> ByteSpan {
    to_span(range(node))
}

/// A token's span.
pub(crate) fn token_span(token: &SyntaxToken) -> ByteSpan {
    to_span(token.text_range())
}

fn to_span(range: TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// A node's text without the trivia at its ends.
pub(crate) fn text<'s>(source: &'s str, node: &SyntaxNode) -> &'s str {
    let r = range(node);
    &source[usize::from(r.start())..usize::from(r.end())]
}

/// The significant tokens directly under `node`.
pub(crate) fn tokens(node: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> {
    node.children_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| !is_trivia(t))
}

/// The first identifier directly under `node`: the name of a call, a `let`, a
/// parameter, a table reference.
pub(crate) fn ident(node: &SyntaxNode) -> Option<SyntaxToken> {
    tokens(node).find(|t| t.kind() == K::IDENT)
}

/// The first child node of `kind`.
pub(crate) fn child(node: &SyntaxNode, kind: K) -> Option<SyntaxNode> {
    node.children().find(|c| c.kind() == kind)
}

/// The name a `NAME_REF` stands for: `['a b']` is `a b`.
pub(crate) fn name<'s>(source: &'s str, name_ref: &SyntaxNode) -> &'s str {
    let text = text(source, name_ref);
    if tokens(name_ref).any(|t| t.kind() == K::QUOTED_IDENT) {
        crate::schema::unquote_name(text)
    } else {
        text
    }
}

/// The expression under a node that only wraps it, or the node itself; `None`
/// when it has an operator (`a + 1`, `-a`, `(a)`): what tree-sitter's
/// one-child wrappers reduced to.
pub(crate) fn simple_primary(node: &SyntaxNode) -> Option<SyntaxNode> {
    match node.kind() {
        K::OR_EXPR
        | K::AND_EXPR
        | K::NOT_EXPR
        | K::COMPARISON_EXPR
        | K::IN_EXPR
        | K::BETWEEN_EXPR
        | K::ADDITIVE_EXPR
        | K::MULTIPLICATIVE_EXPR
        | K::UNARY_EXPR
        | K::PAREN_EXPR => None,
        K::SORT_ITEM => {
            let only = tokens(node).next().is_none() && node.children().count() == 1;
            only.then(|| node.first_child())
                .flatten()
                .and_then(|n| simple_primary(&n))
        }
        _ => Some(node.clone()),
    }
}

/// The name an expression is, if it is a bare one (plain or quoted).
pub(crate) fn simple_ident(node: &SyntaxNode) -> Option<SyntaxNode> {
    simple_primary(node).filter(|n| n.kind() == K::NAME_REF)
}

/// The call an expression is, if it is a bare one.
pub(crate) fn simple_call(node: &SyntaxNode) -> Option<SyntaxNode> {
    simple_primary(node).filter(|n| n.kind() == K::FUNCTION_CALL)
}

/// The kind of the literal a `LITERAL` node holds.
pub(crate) fn literal_kind(node: &SyntaxNode) -> Option<K> {
    (node.kind() == K::LITERAL)
        .then(|| tokens(node).next().map(|t| t.kind()))
        .flatten()
}

/// The node name tree-sitter gave an operator kind (`where_operator`): the
/// HIR and the column pass's messages name operators by it.
pub(crate) fn legacy_kind(kind: K) -> &'static str {
    match kind {
        K::WHERE_OPERATOR => "where_operator",
        K::FILTER_OPERATOR => "filter_operator",
        K::PROJECT_OPERATOR => "project_operator",
        K::PROJECT_AWAY_OPERATOR => "project_away_operator",
        K::PROJECT_RENAME_OPERATOR => "project_rename_operator",
        K::PROJECT_KEEP_OPERATOR => "project_keep_operator",
        K::PROJECT_REORDER_OPERATOR => "project_reorder_operator",
        K::EXTEND_OPERATOR => "extend_operator",
        K::SUMMARIZE_OPERATOR => "summarize_operator",
        K::JOIN_OPERATOR => "join_operator",
        K::UNION_OPERATOR => "union_operator",
        K::PARSE_OPERATOR => "parse_operator",
        K::PARSE_WHERE_OPERATOR => "parse_where_operator",
        K::PARSE_KV_OPERATOR => "parse_kv_operator",
        K::LOOKUP_OPERATOR => "lookup_operator",
        K::TAKE_OPERATOR => "take_operator",
        K::LIMIT_OPERATOR => "limit_operator",
        K::TOP_OPERATOR => "top_operator",
        K::COUNT_OPERATOR => "count_operator",
        K::MV_EXPAND_OPERATOR => "mv_expand_operator",
        K::MV_APPLY_OPERATOR => "mv_apply_operator",
        K::MAKE_SERIES_OPERATOR => "make_series_operator",
        K::EVALUATE_OPERATOR => "evaluate_operator",
        K::SORT_OPERATOR => "sort_operator",
        K::DISTINCT_OPERATOR => "distinct_operator",
        K::RENDER_OPERATOR => "render_operator",
        K::RANGE_OPERATOR => "range_operator",
        K::TOP_NESTED_OPERATOR => "top_nested_operator",
        K::SAMPLE_DISTINCT_OPERATOR => "sample_distinct_operator",
        K::FORK_OPERATOR => "fork_operator",
        K::FACET_OPERATOR => "facet_operator",
        K::PARTITION_OPERATOR => "partition_operator",
        K::SCAN_OPERATOR => "scan_operator",
        K::KEYWORD_OPERATOR => "keyword_operator",
        K::PRINT_OPERATOR => "print_operator",
        K::UNKNOWN_OPERATOR => "unknown_operator",
        _ => "operator",
    }
}

/// Whether a kind is a tabular operator (`legacy_kind` names it).
pub(crate) fn is_operator(kind: K) -> bool {
    legacy_kind(kind) != "operator"
}

/// The token at `offset`, as rowan's `token_at_offset` gives it: with `left`,
/// the one that ends there or holds it (the first token at offset 0); else
/// the one that starts there or holds it (the last token at the end of the
/// text). A scan of the tokens in order, on rowan's iterative preorder:
/// `token_at_offset` recurses once per tree level, and a 20,000-term chain
/// is a tree that deep (it overflowed a 1 MB stack).
pub(crate) fn token_at(
    root: &SyntaxNode,
    offset: rowan::TextSize,
    left: bool,
) -> Option<SyntaxToken> {
    let mut last = None;
    for token in root
        .descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
    {
        let range = token.text_range();
        let here = if left {
            range.start() < offset && offset <= range.end()
                || (offset == range.start() && last.is_none())
        } else {
            range.start() <= offset && offset < range.end()
        };
        if here {
            return Some(token);
        }
        if range.start() > offset {
            break;
        }
        last = Some(token);
    }
    // Past the last token: the last one (right) or none found (left).
    if left {
        None
    } else {
        last.filter(|t| t.text_range().end() == offset)
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;

    fn sources() -> Vec<String> {
        let mut out = vec![
            String::new(),
            "   ".into(),
            "// only a comment".into(),
            "T | where a == 1 // trailing comment\n".into(),
            "  T\n| where (  a == 1 /* c */ )  \n| project b , c ".into(),
            "let x = (\n  // c\n);\nT".into(),
            "T | where".into(),
            "T | join ( U | where x == 1 ) on a".into(),
            "T | summarize count() by bin(TimeGenerated, 1h) // x".into(),
        ];
        let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata")];
        while let Some(dir) = dirs.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "kql") {
                    out.extend(std::fs::read_to_string(&path).ok());
                }
            }
        }
        out
    }

    /// From each end inward gives the range that walking every token gave,
    /// for every node of every KQL file under `crates/testdata`, broken ones
    /// and ones with trivia at either end among them.
    #[test]
    fn range_from_the_ends_is_range_by_walking() {
        let mut nodes = 0;
        for source in sources() {
            let root = SyntaxNode::new_root(crate::parser::parse(&source).green);
            for node in root.descendants() {
                assert_eq!(
                    range(&node),
                    range_by_walking(&node),
                    "{node:?} in {source:?}"
                );
                nodes += 1;
            }
        }
        assert!(nodes > 5_000, "{nodes} nodes");
    }
}
