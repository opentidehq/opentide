//! The parsed tree as the analysis reads it: a [`Node`] is a node of the
//! rowan tree or one of its leaf tokens that the grammar names (a term, a
//! phrase, a boost, ...), with its range trimmed to its first and last
//! token that is not whitespace, and accessors for the grammar's fields
//! (`field:query`, a term query's term, a range's bounds).

use crate::parser;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_core::ByteSpan;
use opentide_parse::SyntaxError;
use rowan::{NodeOrToken, TextRange, TextSize};

type Element = rowan::SyntaxElement<crate::syntax::Lucene>;

/// A named node or token of the tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Node(Element);

/// Leaf tokens the grammar names; the rest (`:`, brackets, whitespace,
/// keyword tokens inside their `And`/`Or`/`Not` nodes) are anonymous.
const NAMED_TOKENS: [K; 9] = [
    K::Term,
    K::WildcardTerm,
    K::Star,
    K::Phrase,
    K::Regexp,
    K::RangeTerm,
    K::Boost,
    K::Fuzzy,
    K::BareOperator,
];

fn is_named(e: &Element) -> bool {
    match e {
        NodeOrToken::Node(_) => true,
        NodeOrToken::Token(t) => NAMED_TOKENS.contains(&t.kind()),
    }
}

/// The range of `e` without the whitespace at its ends.
fn trimmed(e: &Element) -> TextRange {
    let NodeOrToken::Node(n) = e else {
        return e.text_range();
    };
    let tokens = || {
        n.descendants_with_tokens()
            .filter_map(NodeOrToken::into_token)
            .filter(|t| t.kind() != K::Whitespace)
    };
    let start = tokens().next().map(|t| t.text_range().start());
    // The last token: walk back from the node's last token.
    let mut last = n.last_token();
    while let Some(t) = &last {
        if t.kind() != K::Whitespace || !n.text_range().contains_range(t.text_range()) {
            break;
        }
        last = t.prev_token();
    }
    let end = last
        .filter(|t| n.text_range().contains_range(t.text_range()))
        .map(|t| t.text_range().end());
    // tree-sitter's root runs from its first token to the end of the text.
    let end = if n.kind() == K::SourceFile {
        Some(n.text_range().end())
    } else {
        end
    };
    match (start, end) {
        (Some(s), Some(e)) if s <= e => TextRange::new(s, e),
        _ => TextRange::empty(n.text_range().start()),
    }
}

impl Node {
    /// The tree's root.
    pub(crate) fn root(root: &SyntaxNode) -> Self {
        Self(NodeOrToken::Node(root.clone()))
    }

    pub(crate) fn kind(&self) -> K {
        self.0.kind()
    }

    pub(crate) fn range(&self) -> TextRange {
        trimmed(&self.0)
    }

    pub(crate) fn start(&self) -> usize {
        usize::from(self.range().start())
    }

    pub(crate) fn end(&self) -> usize {
        usize::from(self.range().end())
    }

    /// The span a diagnostic on the node covers: at least one byte.
    pub(crate) fn span(&self) -> ByteSpan {
        ByteSpan::new(self.start(), self.end().max(self.start() + 1))
    }

    pub(crate) fn text<'s>(&self, source: &'s str) -> &'s str {
        source.get(self.start()..self.end()).unwrap_or("")
    }

    /// The named children, in order.
    pub(crate) fn children(&self) -> Vec<Node> {
        match &self.0 {
            NodeOrToken::Node(n) => n
                .children_with_tokens()
                .filter(is_named)
                .map(Node)
                .collect(),
            NodeOrToken::Token(_) => Vec::new(),
        }
    }

    /// The first named child of kind `kind`.
    fn child(&self, kinds: &[K]) -> Option<Node> {
        self.children()
            .into_iter()
            .find(|c| kinds.contains(&c.kind()))
    }

    pub(crate) fn first_child(&self) -> Option<Node> {
        self.children().into_iter().next()
    }

    pub(crate) fn parent(&self) -> Option<Node> {
        self.0.parent().map(|p| Node(NodeOrToken::Node(p)))
    }

    /// The next named sibling.
    pub(crate) fn next_sibling(&self) -> Option<Node> {
        let mut next = self.0.next_sibling_or_token();
        while let Some(e) = next {
            if is_named(&e) {
                return Some(Node(e));
            }
            next = e.next_sibling_or_token();
        }
        None
    }

    /// A field query's field name (`field_name`).
    pub(crate) fn field(&self) -> Option<Node> {
        (self.kind() == K::FieldQuery)
            .then(|| self.child(&[K::FieldName]))
            .flatten()
    }

    /// A field query's body (`query`): the node after the field name.
    pub(crate) fn query(&self) -> Option<Node> {
        if self.kind() != K::FieldQuery {
            return None;
        }
        self.children()
            .into_iter()
            .find(|c| c.kind() != K::FieldName && c.kind() != K::Error)
    }

    /// A term query's term.
    pub(crate) fn term(&self) -> Option<Node> {
        (self.kind() == K::TermQuery)
            .then(|| self.child(&[K::Term, K::WildcardTerm, K::Star, K::BareOperator]))
            .flatten()
    }

    /// A phrase query's phrase.
    pub(crate) fn phrase(&self) -> Option<Node> {
        (self.kind() == K::PhraseQuery)
            .then(|| self.child(&[K::Phrase]))
            .flatten()
    }

    /// A range's lower (`upper == false`) or upper bound.
    pub(crate) fn bound(&self, upper: bool) -> Option<Node> {
        if self.kind() != K::RangeQuery {
            return None;
        }
        let NodeOrToken::Node(n) = &self.0 else {
            return None;
        };
        // The bounds sit either side of `TO`.
        let mut seen_to = false;
        for e in n.children_with_tokens() {
            match e.kind() {
                K::ToKw => seen_to = true,
                K::RangeTerm | K::Phrase if seen_to == upper => return Some(Node(e)),
                _ => {}
            }
        }
        None
    }

    /// The first token child, named or not, of one of `kinds` (a range's
    /// brackets).
    pub(crate) fn token(&self, kinds: &[K]) -> Option<Node> {
        match &self.0 {
            NodeOrToken::Node(n) => n
                .children_with_tokens()
                .find(|e| kinds.contains(&e.kind()))
                .map(Node),
            NodeOrToken::Token(_) => None,
        }
    }

    /// A boolean query's operators (`And` and `Or` nodes).
    pub(crate) fn operators(&self) -> Vec<Node> {
        self.children()
            .into_iter()
            .filter(|c| matches!(c.kind(), K::And | K::Or))
            .collect()
    }

    /// The deepest named node or token whose range holds `offset`: the
    /// token starting there at a boundary between two, else the smallest
    /// node around it (tree-sitter's `descendant_for_byte_range`).
    pub(crate) fn at_offset(&self, offset: usize) -> Option<Node> {
        let at = TextSize::from(u32::try_from(offset).ok()?);
        let mut node = self.clone();
        loop {
            let NodeOrToken::Node(n) = &node.0 else {
                return Some(node);
            };
            // Children are in order: the first that ends past `at` is the
            // only one that can hold it.
            let inner = n
                .children_with_tokens()
                .filter(|e| e.kind() != K::Whitespace)
                .find(|e| at < e.text_range().end())
                .filter(|e| {
                    let r = trimmed(e);
                    r.start() <= at && at < r.end()
                });
            match inner {
                Some(e) => node = Node(e),
                None => return Some(node),
            }
        }
    }
}

/// A parse of a Lucene query, for the analysis.
pub(crate) struct Tree {
    pub(crate) root: SyntaxNode,
    pub(crate) errors: Vec<SyntaxError>,
}

impl Tree {
    pub(crate) fn parse(source: &str) -> Self {
        let (root, parse) = parser::parse(source);
        Self {
            root,
            errors: parse.errors,
        }
    }

    pub(crate) fn root(&self) -> Node {
        Node::root(&self.root)
    }

    pub(crate) fn has_error(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Pre-order walk of the named nodes and tokens under `root` (`root`
/// included), each with its ancestors, root first. Iterative, so a deeply
/// nested query cannot exhaust the stack.
pub(crate) fn walk_with_ancestors(root: &Node, mut f: impl FnMut(&Node, &[Node])) {
    let mut stack: Vec<(Node, usize)> = vec![(root.clone(), 0)];
    let mut ancestors: Vec<Node> = Vec::new();
    while let Some((node, depth)) = stack.pop() {
        ancestors.truncate(depth);
        f(&node, &ancestors);
        let children = node.children();
        if !children.is_empty() {
            ancestors.push(node);
            for child in children.into_iter().rev() {
                stack.push((child, depth + 1));
            }
        }
    }
}
